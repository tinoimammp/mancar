package usage

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type store struct {
	mu   sync.Mutex
	rows []Row
	fail bool
}

func (s *store) AddUsage(_ context.Context, rows []Row) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return errors.New("database down")
	}
	s.rows = append(s.rows, rows...)
	return nil
}

func (s *store) PurgeUsage(context.Context, time.Time) (int64, error) { return 0, nil }

func TestCounterAggregatesPerHostAndHour(t *testing.T) {
	st := &store{}
	c := NewCounter(st, nil)
	now := time.Date(2026, 3, 1, 10, 15, 0, 0, time.UTC)
	c.now = func() time.Time { return now }
	c.Add("u1", "a.example.com", 200, 10, 100)
	c.Add("u1", "a.example.com", 502, 5, 50)
	c.Add("u1", "a.example.com", 0, 1, 0) // no response at all counts as an error
	c.Add("u2", "b.example.com", 404, 0, 9)
	now = now.Add(time.Hour)
	c.Add("u1", "a.example.com", 200, 1, 1)
	c.Flush(context.Background())

	got := map[string]Row{}
	for _, r := range st.rows {
		got[r.Hostname+"@"+r.Hour.Format("15")] = r
	}
	a10 := got["a.example.com@10"]
	if a10.Requests != 3 || a10.Errors != 2 || a10.BytesIn != 16 || a10.BytesOut != 150 || a10.UserID != "u1" {
		t.Errorf("a.example.com 10h: %+v", a10)
	}
	if b := got["b.example.com@10"]; b.Requests != 1 || b.Errors != 0 {
		t.Errorf("4xx is not a server error: %+v", b)
	}
	if got["a.example.com@11"].Requests != 1 || len(st.rows) != 3 {
		t.Errorf("hours not separated: %+v", st.rows)
	}
}

func TestFailedFlushIsRetried(t *testing.T) {
	st := &store{fail: true}
	c := NewCounter(st, nil)
	c.Add("u1", "a.example.com", 200, 1, 1)
	c.Flush(context.Background())
	c.Add("u1", "a.example.com", 200, 1, 1)
	st.fail = false
	c.Flush(context.Background())
	if len(st.rows) != 1 || st.rows[0].Requests != 2 {
		t.Errorf("counts lost after a failed flush: %+v", st.rows)
	}
}

func TestRunFlushesOnShutdown(t *testing.T) {
	st := &store{}
	c := NewCounter(st, nil)
	c.Add("u1", "a.example.com", 200, 1, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()
	cancel()
	<-done
	if len(st.rows) != 1 {
		t.Errorf("pending counts not flushed on shutdown: %+v", st.rows)
	}
}
