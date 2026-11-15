package integration_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tinoimammp/mancar/internal/inspect"
	"github.com/tinoimammp/mancar/internal/router"
	"github.com/tinoimammp/mancar/internal/server"
)

type captureStore struct {
	mu   sync.Mutex
	rows []inspect.Row
}

func (c *captureStore) InsertCaptures(_ context.Context, rows []inspect.Row) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rows = append(c.rows, rows...)
	return nil
}
func (c *captureStore) ListCaptures(context.Context, inspect.Filter) ([]inspect.Row, error) {
	return nil, nil
}
func (c *captureStore) GetCapture(context.Context, string) (inspect.Row, error) {
	return inspect.Row{}, nil
}
func (c *captureStore) DeleteCaptures(context.Context, string) (int64, error) { return 0, nil }
func (c *captureStore) PurgeCaptures(context.Context, time.Time, int) (int64, error) {
	return 0, nil
}

func (c *captureStore) snapshot() []inspect.Row {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]inspect.Row(nil), c.rows...)
}

func TestInspectorCapturesEncryptedExchanges(t *testing.T) {
	keyBytes := bytes.Repeat([]byte{9}, 32)
	store := &captureStore{}
	e := newEnvWith(t, map[string]string{"ENCRYPTION_KEY": hex.EncodeToString(keyBytes), "INSPECT_MAX_BODY_BYTES": "16"},
		func(d *server.Deps) { d.Captures = store })
	backend := echoServer(t, "one")
	tun := e.startAgent(e.token("alice"), "", httpSpec(backend.URL, "")).waitOnline(t)[0].Registered

	body := `{"password":"hunter2-and-more-text"}`
	resp, _ := e.do("POST", tun.Hostname, "/login?otp=424242", strings.NewReader(body), map[string]string{"Authorization": "Bearer tok-xyz"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("request: %d", resp.StatusCode)
	}
	eventually(t, "capture stored", func() bool { return len(store.snapshot()) == 1 })

	row := store.snapshot()[0]
	for _, secret := range []string{"hunter2", "424242", "tok-xyz", "/login"} {
		if bytes.Contains(row.Ciphertext, []byte(secret)) {
			t.Errorf("stored ciphertext contains %q", secret)
		}
	}
	if row.Hostname != tun.Hostname || row.Status != http.StatusCreated || row.ReqSize != int64(len(body)) {
		t.Errorf("metadata: %+v", row)
	}
	sealer, _ := inspect.NewSealer(keyBytes)
	rec, err := sealer.Open(row)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Method != "POST" || rec.URI != "/login?otp=424242" || rec.ReqHeader.Get("Authorization") != "Bearer tok-xyz" {
		t.Errorf("record: %+v", rec)
	}
	if string(rec.ReqBody) != body[:16] || !rec.ReqTruncated() {
		t.Errorf("request body should keep the first 16 bytes: %q", rec.ReqBody)
	}
	if rec.RespHeader.Get("X-Backend") != "one" || rec.RespSize == 0 || len(rec.RespBody) != 16 {
		t.Errorf("response: header=%v size=%d kept=%d", rec.RespHeader, rec.RespSize, len(rec.RespBody))
	}
	if rec.Replay {
		t.Error("a public request was marked as a replay")
	}

	// A replay goes through the same router and is marked as such; a client
	// cannot fake the mark with a header.
	req := httptest.NewRequest("GET", "http://"+tun.Hostname+"/again", nil).WithContext(router.WithReplay(context.Background()))
	req.RemoteAddr = "127.0.0.1:1"
	e.srv.Handler().ServeHTTP(httptest.NewRecorder(), req)
	e.do("GET", tun.Hostname, "/fake", nil, map[string]string{"X-Mancar-Replay": "1"})
	eventually(t, "replay captured", func() bool { return len(store.snapshot()) == 3 })
	marks := map[string]bool{}
	for _, r := range store.snapshot()[1:] {
		rec, _ := sealer.Open(r)
		marks[rec.URI] = rec.Replay
	}
	if !marks["/again"] || marks["/fake"] {
		t.Errorf("replay marks: %v", marks)
	}
}

func TestInspectorOffWithoutKeyOrWhenDisabled(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"no key":   {},
		"disabled": {"ENCRYPTION_KEY": strings.Repeat("ab", 32), "INSPECT": "off"},
	} {
		t.Run(name, func(t *testing.T) {
			store := &captureStore{}
			e := newEnvWith(t, env, func(d *server.Deps) { d.Captures = store })
			backend := echoServer(t, "one")
			tun := e.startAgent(e.token("alice"), "", httpSpec(backend.URL, "")).waitOnline(t)[0].Registered
			e.do("GET", tun.Hostname, "/", nil, nil)
			time.Sleep(1500 * time.Millisecond) // longer than the recorder's flush interval
			if n := len(store.snapshot()); n != 0 {
				t.Errorf("%d captures stored while the inspector is off", n)
			}
		})
	}
}
