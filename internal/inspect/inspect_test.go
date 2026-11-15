package inspect_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tinoimammp/mancar/internal/inspect"
)

var key = bytes.Repeat([]byte{7}, 32)

func TestSealOpenRoundTripHidesContent(t *testing.T) {
	s, err := inspect.NewSealer(key)
	if err != nil {
		t.Fatal(err)
	}
	rec := &inspect.Record{
		ID: inspect.NewID(), Hostname: "api.example.com", Status: 201, Method: "POST", URI: "/login?token=s3cret-query",
		ReqHeader: http.Header{"Authorization": {"Bearer s3cret-header"}}, ReqBody: []byte(`{"password":"s3cret-body"}`), ReqSize: 26,
	}
	row, err := s.Seal(rec)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"s3cret-query", "s3cret-header", "s3cret-body", "/login", "POST"} {
		if bytes.Contains(row.Ciphertext, []byte(secret)) {
			t.Errorf("ciphertext contains %q", secret)
		}
	}
	if row.Hostname != "api.example.com" || row.Status != 201 {
		t.Errorf("clear metadata wrong: %+v", row)
	}
	got, err := s.Open(row)
	if err != nil {
		t.Fatal(err)
	}
	if got.URI != rec.URI || string(got.ReqBody) != string(rec.ReqBody) || got.ReqHeader.Get("Authorization") != "Bearer s3cret-header" {
		t.Errorf("round trip mismatch: %+v", got)
	}
}

func TestOpenRejectsTamperingAndWrongKey(t *testing.T) {
	s, _ := inspect.NewSealer(key)
	row, _ := s.Seal(&inspect.Record{ID: inspect.NewID(), Method: "GET"})

	moved := row
	moved.ID = inspect.NewID() // ciphertext copied onto another row
	if _, err := s.Open(moved); err == nil {
		t.Error("ciphertext accepted under another row ID")
	}
	flipped := row
	flipped.Ciphertext = append([]byte(nil), row.Ciphertext...)
	flipped.Ciphertext[0] ^= 1
	if _, err := s.Open(flipped); err == nil {
		t.Error("modified ciphertext accepted")
	}
	other, _ := inspect.NewSealer(bytes.Repeat([]byte{8}, 32))
	if _, err := other.Open(row); err == nil {
		t.Error("opened with the wrong key")
	}
	if _, err := inspect.NewSealer([]byte("short")); err == nil {
		t.Error("short key accepted")
	}
}

func TestBufferKeepsPrefixAndCountsAll(t *testing.T) {
	b := inspect.NewBuffer(5)
	// io.TeeReader fails on a short write, so Write must always report len(p).
	r := io.TeeReader(strings.NewReader("hello world"), b)
	if out, err := io.ReadAll(r); err != nil || string(out) != "hello world" {
		t.Fatalf("tee read: %q %v", out, err)
	}
	kept, total := b.Snapshot()
	if string(kept) != "hello" || total != 11 {
		t.Errorf("kept=%q total=%d", kept, total)
	}
}

type memStore struct {
	mu     sync.Mutex
	rows   []inspect.Row
	purged int
}

func (m *memStore) InsertCaptures(_ context.Context, rows []inspect.Row) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rows = append(m.rows, rows...)
	return nil
}
func (m *memStore) ListCaptures(context.Context, inspect.Filter) ([]inspect.Row, error) {
	return nil, nil
}
func (m *memStore) GetCapture(context.Context, string) (inspect.Row, error) {
	return inspect.Row{}, nil
}
func (m *memStore) DeleteCaptures(context.Context, string) (int64, error) { return 0, nil }
func (m *memStore) PurgeCaptures(context.Context, time.Time, int) (int64, error) {
	m.mu.Lock()
	m.purged++
	m.mu.Unlock()
	return 0, nil
}

func TestRecorderFlushesOnShutdownAndPurges(t *testing.T) {
	st := &memStore{}
	s, _ := inspect.NewSealer(key)
	r := inspect.NewRecorder(inspect.Options{Store: st, Sealer: s})
	ctx, cancel := context.WithCancel(context.Background())
	go r.Run(ctx)
	for i := 0; i < 3; i++ {
		r.Submit(&inspect.Record{ID: inspect.NewID(), Method: "GET"})
	}
	cancel()
	select {
	case <-r.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("recorder did not stop")
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.rows) != 3 {
		t.Errorf("stored %d captures, want 3 (queued captures must be flushed on shutdown)", len(st.rows))
	}
	if st.purged == 0 {
		t.Error("retention purge never ran")
	}
}

func TestSubmitNeverBlocks(t *testing.T) {
	s, _ := inspect.NewSealer(key)
	r := inspect.NewRecorder(inspect.Options{Store: &memStore{}, Sealer: s}) // not running: queue fills up
	done := make(chan struct{})
	go func() {
		for i := 0; i < 5000; i++ {
			r.Submit(&inspect.Record{})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Submit blocked on a full queue")
	}
}
