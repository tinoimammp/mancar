// Package usage counts HTTP traffic per hostname and hour for the dashboard
// (requests, server errors, bytes in and out).
//
// Counting is in memory and costs one map update per request; totals are
// added to the database every FlushInterval, so the hot path never touches
// the database. The store keeps hourly rows for Retention (90 days) and daily
// and lifetime totals forever.
package usage

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"time"
)

// Retention is how long hourly rows are kept (daily and lifetime totals are
// kept forever).
const Retention = 90 * 24 * time.Hour

// FlushInterval is how often counts are written to the database.
const FlushInterval = 30 * time.Second

// Row is the traffic of one hostname in one hour.
type Row struct {
	UserID   string
	Hostname string
	Hour     time.Time
	Requests int64
	Errors   int64 // responses with status 5xx, or none at all
	BytesIn  int64
	BytesOut int64
}

// Totals summarises a period.
type Totals struct {
	Requests int64 `json:"requests"`
	Errors   int64 `json:"errors"`
	BytesIn  int64 `json:"bytes_in"`
	BytesOut int64 `json:"bytes_out"`
}

// Store persists counts (implemented by *postgres.Store).
type Store interface {
	AddUsage(ctx context.Context, rows []Row) error
	PurgeUsage(ctx context.Context, before time.Time) (int64, error)
}

type key struct {
	user string
	host string
	hour time.Time
}

// Counter aggregates traffic in memory.
type Counter struct {
	store Store
	log   *slog.Logger
	now   func() time.Time

	mu sync.Mutex
	m  map[key]*Row
}

// NewCounter builds a Counter; call Run to start flushing.
func NewCounter(store Store, log *slog.Logger) *Counter {
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Counter{store: store, log: log, now: time.Now, m: map[key]*Row{}}
}

// Add records one finished request.
func (c *Counter) Add(userID, hostname string, status int, bytesIn, bytesOut int64) {
	k := key{userID, hostname, c.now().UTC().Truncate(time.Hour)}
	c.mu.Lock()
	defer c.mu.Unlock()
	r := c.m[k]
	if r == nil {
		r = &Row{UserID: userID, Hostname: hostname, Hour: k.hour}
		c.m[k] = r
	}
	r.Requests++
	if status == 0 || status >= 500 {
		r.Errors++
	}
	r.BytesIn += bytesIn
	r.BytesOut += bytesOut
}

// Run flushes counts until ctx is cancelled, then flushes once more.
func (c *Counter) Run(ctx context.Context) {
	flush := time.NewTicker(FlushInterval)
	defer flush.Stop()
	purge := time.NewTicker(6 * time.Hour)
	defer purge.Stop()
	c.purge(ctx)
	for {
		select {
		case <-flush.C:
			c.Flush(ctx)
		case <-purge.C:
			c.purge(ctx)
		case <-ctx.Done():
			c.Flush(context.WithoutCancel(ctx))
			return
		}
	}
}

// Flush writes the pending counts. On failure they are kept and retried on
// the next flush.
func (c *Counter) Flush(ctx context.Context) {
	c.mu.Lock()
	if len(c.m) == 0 {
		c.mu.Unlock()
		return
	}
	pending := c.m
	c.m = map[key]*Row{}
	c.mu.Unlock()

	rows := make([]Row, 0, len(pending))
	for _, r := range pending {
		rows = append(rows, *r)
	}
	wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := c.store.AddUsage(wctx, rows); err != nil {
		c.log.Warn("usage: storing traffic counts failed; will retry", "err", err)
		c.mu.Lock()
		for k, r := range pending {
			if cur := c.m[k]; cur != nil {
				cur.Requests += r.Requests
				cur.Errors += r.Errors
				cur.BytesIn += r.BytesIn
				cur.BytesOut += r.BytesOut
			} else {
				c.m[k] = r
			}
		}
		c.mu.Unlock()
	}
}

func (c *Counter) purge(ctx context.Context) {
	pctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	if _, err := c.store.PurgeUsage(pctx, c.now().Add(-Retention)); err != nil && ctx.Err() == nil {
		c.log.Warn("usage: purging old counts failed", "err", err)
	}
}
