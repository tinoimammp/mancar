// Package inspect records HTTP traffic through tunnels for the dashboard's
// request inspector and replay.
//
// Captures are encrypted before they reach the database: method, URL,
// headers, bodies and the client address are sealed with AES-256-GCM under
// ENCRYPTION_KEY, bound to the row ID. Only what listing and retention need is
// stored in the clear (owner, hostname, status, duration, sizes, time).
//
// Recording never slows traffic down: captures go through a bounded queue to
// a background writer and are dropped, not waited for, when it is full.
// Old captures are deleted automatically (age and row-count limits).
package inspect

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Record is one captured request/response exchange.
type Record struct {
	ID         string    `json:"id"`
	UserID     string    `json:"-"`
	Hostname   string    `json:"hostname"`
	TunnelID   string    `json:"tunnel_id"`
	Time       time.Time `json:"time"`
	DurationMs int64     `json:"duration_ms"`
	Status     int       `json:"status"`

	Method     string      `json:"method"`
	URI        string      `json:"uri"` // path and query
	Proto      string      `json:"proto"`
	Client     string      `json:"client"`
	ReqHeader  http.Header `json:"request_headers"`
	ReqBody    []byte      `json:"request_body"`
	ReqSize    int64       `json:"request_size"` // full size; ReqBody may be a prefix
	RespHeader http.Header `json:"response_headers"`
	RespBody   []byte      `json:"response_body"`
	RespSize   int64       `json:"response_size"`
	Replay     bool        `json:"replay"`
}

// ReqTruncated reports whether only part of the request body was kept.
func (r *Record) ReqTruncated() bool { return int64(len(r.ReqBody)) < r.ReqSize }

// RespTruncated reports whether only part of the response body was kept.
func (r *Record) RespTruncated() bool { return int64(len(r.RespBody)) < r.RespSize }

// Row is a capture as stored: clear metadata plus the sealed record.
type Row struct {
	ID         string
	UserID     string
	Hostname   string
	Status     int
	DurationMs int64
	ReqSize    int64
	RespSize   int64
	CreatedAt  time.Time
	Nonce      []byte
	Ciphertext []byte
}

// Filter selects captures for listing.
type Filter struct {
	Hostname string    // "" = all
	Before   time.Time // zero = newest
	Limit    int
}

// Store persists captures (implemented by *postgres.Store).
type Store interface {
	InsertCaptures(ctx context.Context, rows []Row) error
	ListCaptures(ctx context.Context, f Filter) ([]Row, error)
	GetCapture(ctx context.Context, id string) (Row, error)
	DeleteCaptures(ctx context.Context, hostname string) (int64, error)
	PurgeCaptures(ctx context.Context, olderThan time.Time, keep int) (int64, error)
}

// ---- encryption ------------------------------------------------------------

// Sealer encrypts and decrypts records.
type Sealer struct{ aead cipher.AEAD }

// NewSealer builds a Sealer from a 32-byte key.
func NewSealer(key []byte) (*Sealer, error) {
	if len(key) != 32 {
		return nil, errors.New("inspect: encryption key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Sealer{aead: aead}, nil
}

// Seal encrypts rec into a storable Row. The row ID is the additional
// authenticated data, so a ciphertext cannot be moved to another row.
func (s *Sealer) Seal(rec *Record) (Row, error) {
	plain, err := json.Marshal(rec)
	if err != nil {
		return Row{}, err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Row{}, err
	}
	return Row{
		ID: rec.ID, UserID: rec.UserID, Hostname: rec.Hostname, Status: rec.Status,
		DurationMs: rec.DurationMs, ReqSize: rec.ReqSize, RespSize: rec.RespSize, CreatedAt: rec.Time,
		Nonce: nonce, Ciphertext: s.aead.Seal(nil, nonce, plain, []byte(rec.ID)),
	}, nil
}

// Open decrypts a Row.
func (s *Sealer) Open(row Row) (*Record, error) {
	plain, err := s.aead.Open(nil, row.Nonce, row.Ciphertext, []byte(row.ID))
	if err != nil {
		return nil, errors.New("inspect: capture cannot be decrypted (was ENCRYPTION_KEY changed?)")
	}
	var rec Record
	if err := json.Unmarshal(plain, &rec); err != nil {
		return nil, fmt.Errorf("inspect: corrupt capture: %w", err)
	}
	rec.ID, rec.UserID = row.ID, row.UserID
	return &rec, nil
}

// NewID returns a random UUID (v4) string.
func NewID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("inspect: crypto/rand failed: " + err.Error())
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// ---- recorder --------------------------------------------------------------

// Options configures a Recorder.
type Options struct {
	Store     Store
	Sealer    *Sealer
	MaxBody   int           // bytes of each body kept (default 64 KiB)
	Retention time.Duration // captures older than this are deleted (default 24h)
	MaxRows   int           // at most this many captures are kept (default 50,000)
	Logger    *slog.Logger
}

// Recorder queues captures and writes them in the background.
type Recorder struct {
	opts    Options
	log     *slog.Logger
	queue   chan *Record
	dropped atomic.Int64
	done    chan struct{}
	once    sync.Once
}

// NewRecorder builds a Recorder; call Run to start writing.
func NewRecorder(opts Options) *Recorder {
	if opts.MaxBody <= 0 {
		opts.MaxBody = 64 << 10
	}
	if opts.Retention <= 0 {
		opts.Retention = 24 * time.Hour
	}
	if opts.MaxRows <= 0 {
		opts.MaxRows = 50_000
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Recorder{opts: opts, log: opts.Logger, queue: make(chan *Record, 1024), done: make(chan struct{})}
}

// MaxBody is how many bytes of each body to keep.
func (r *Recorder) MaxBody() int { return r.opts.MaxBody }

// Retention is how long captures are kept.
func (r *Recorder) Retention() time.Duration { return r.opts.Retention }

// Sealer returns the sealer used to decrypt stored captures.
func (r *Recorder) Sealer() *Sealer { return r.opts.Sealer }

// Store returns the capture store.
func (r *Recorder) Store() Store { return r.opts.Store }

// Submit queues rec without blocking; it is dropped if the queue is full.
func (r *Recorder) Submit(rec *Record) {
	select {
	case r.queue <- rec:
	default:
		r.dropped.Add(1)
	}
}

// Run writes queued captures and enforces retention until ctx is cancelled,
// then flushes what is left.
func (r *Recorder) Run(ctx context.Context) {
	defer r.once.Do(func() { close(r.done) })
	flush := time.NewTicker(time.Second)
	defer flush.Stop()
	purge := time.NewTicker(5 * time.Minute)
	defer purge.Stop()
	r.purge(ctx)

	var batch []Row
	write := func(c context.Context) {
		if len(batch) == 0 {
			return
		}
		wctx, cancel := context.WithTimeout(c, 10*time.Second)
		defer cancel()
		if err := r.opts.Store.InsertCaptures(wctx, batch); err != nil {
			r.log.Warn("inspector: storing captures failed", "count", len(batch), "err", err)
		}
		batch = batch[:0]
	}
	add := func(rec *Record) {
		row, err := r.opts.Sealer.Seal(rec)
		if err != nil {
			r.log.Warn("inspector: sealing a capture failed", "err", err)
			return
		}
		batch = append(batch, row)
	}
	for {
		select {
		case rec := <-r.queue:
			add(rec)
			if len(batch) >= 100 {
				write(ctx)
			}
		case <-flush.C:
			write(ctx)
			if n := r.dropped.Swap(0); n > 0 {
				r.log.Warn("inspector: captures dropped because the write queue was full", "count", n)
			}
		case <-purge.C:
			r.purge(ctx)
		case <-ctx.Done():
		drain:
			for {
				select {
				case rec := <-r.queue:
					add(rec)
				default:
					break drain
				}
			}
			write(context.WithoutCancel(ctx))
			return
		}
	}
}

// Done is closed when Run has returned.
func (r *Recorder) Done() <-chan struct{} { return r.done }

func (r *Recorder) purge(ctx context.Context) {
	pctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	n, err := r.opts.Store.PurgeCaptures(pctx, time.Now().Add(-r.opts.Retention), r.opts.MaxRows)
	if err != nil && ctx.Err() == nil {
		r.log.Warn("inspector: retention purge failed", "err", err)
		return
	}
	if n > 0 {
		r.log.Info("inspector: old captures deleted", "count", n)
	}
}

// ---- capture helpers -------------------------------------------------------

// Buffer keeps the first max bytes written to it and counts the rest. It is
// safe for concurrent use (the proxy may still be reading a request body when
// the response has been written).
type Buffer struct {
	mu    sync.Mutex
	max   int
	buf   []byte
	total int64
}

// NewBuffer returns a Buffer that keeps up to max bytes.
func NewBuffer(max int) *Buffer { return &Buffer{max: max} }

func (b *Buffer) Write(p []byte) (int, error) {
	n := len(p) // always report a full write: a short one would break io.TeeReader
	b.mu.Lock()
	defer b.mu.Unlock()
	b.total += int64(n)
	if room := b.max - len(b.buf); room > 0 {
		if len(p) > room {
			p = p[:room]
		}
		b.buf = append(b.buf, p...)
	}
	return n, nil
}

// Snapshot returns a copy of the kept bytes and the total size seen.
func (b *Buffer) Snapshot() ([]byte, int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.buf...), b.total
}

// TeeBody wraps a request body so what is read from it is also written to b.
func TeeBody(body io.ReadCloser, b *Buffer) io.ReadCloser {
	if body == nil || body == http.NoBody {
		return body
	}
	return teeReadCloser{Reader: io.TeeReader(body, b), Closer: body}
}

type teeReadCloser struct {
	io.Reader
	io.Closer
}
