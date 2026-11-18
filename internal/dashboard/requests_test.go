package dashboard_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tinoimammp/mancar/internal/dashboard"
	"github.com/tinoimammp/mancar/internal/inspect"
	"github.com/tinoimammp/mancar/internal/store/postgres"
)

type captures struct{ rows []inspect.Row }

func (c *captures) InsertCaptures(_ context.Context, rows []inspect.Row) error {
	c.rows = append(c.rows, rows...)
	return nil
}
func (c *captures) ListCaptures(_ context.Context, f inspect.Filter) ([]inspect.Row, error) {
	var out []inspect.Row
	for _, r := range c.rows {
		if (f.Hostname == "" || r.Hostname == f.Hostname) && (f.UserID == "" || r.UserID == f.UserID) {
			out = append(out, r)
		}
	}
	return out, nil
}
func (c *captures) GetCapture(_ context.Context, id string) (inspect.Row, error) {
	for _, r := range c.rows {
		if r.ID == id {
			return r, nil
		}
	}
	return inspect.Row{}, postgres.ErrNotFound
}
func (c *captures) DeleteCaptures(context.Context, string) (int64, error) {
	n := int64(len(c.rows))
	c.rows = nil
	return n, nil
}
func (c *captures) PurgeCaptures(context.Context, time.Time, int) (int64, error) { return 0, nil }

// replayTarget stands in for the public router.
type replayTarget struct {
	got  *http.Request
	body string
}

func (r *replayTarget) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	b, _ := io.ReadAll(req.Body)
	r.got, r.body = req, string(b)
	w.WriteHeader(http.StatusAccepted)
	w.Write([]byte("done"))
}

// lastStore is the fake store of the latest setupInspector call.
var lastStore *fakeStore

func setupInspector(t *testing.T) (*dashboard.Dashboard, *captures, *replayTarget, *inspect.Sealer) {
	t.Helper()
	hash, _ := dashboard.HashPassword(password)
	st := newFakeStore()
	st.add(postgres.Account{ID: "a1", Username: "root", Role: postgres.RoleAdmin, PasswordHash: hash, PasswordChangedAt: time.Now().Add(-time.Hour)})
	lastStore = st
	sealer, _ := inspect.NewSealer(bytes.Repeat([]byte{1}, 32))
	cs := &captures{}
	rec := inspect.NewRecorder(inspect.Options{Store: cs, Sealer: sealer})
	target := &replayTarget{}
	d := dashboard.New(dashboard.Options{
		Store: st, Hub: &fakeHub{}, SessionSecret: strings.Repeat("s", 32), Secure: true,
		BaseDomain: "tunnel.example.com", PublicScheme: "https", Inspector: rec, Replay: target,
	})
	return d, cs, target, sealer
}

func addCapture(t *testing.T, cs *captures, s *inspect.Sealer, rec *inspect.Record) string {
	t.Helper()
	rec.ID = inspect.NewID()
	rec.Time = time.Now()
	row, err := s.Seal(rec)
	if err != nil {
		t.Fatal(err)
	}
	cs.rows = append(cs.rows, row)
	return rec.ID
}

func TestRequestsListDetailAndReplay(t *testing.T) {
	d, cs, target, s := setupInspector(t)
	c := login(t, d)
	id := addCapture(t, cs, s, &inspect.Record{
		Hostname: "api.tunnel.example.com", Method: "POST", URI: "/hook?x=1", Status: 200,
		ReqHeader: http.Header{"Content-Type": {"application/json"}, "X-Forwarded-For": {"203.0.113.9"}, "X-Custom": {"keep"}},
		ReqBody:   []byte(`{"a":1}`), ReqSize: 7,
		RespHeader: http.Header{"Content-Type": {"text/plain"}}, RespBody: []byte("ok"), RespSize: 2,
	})

	if rec := do(d, req{method: "GET", path: "/api/v1/admin/requests"}); rec.Code != http.StatusUnauthorized {
		t.Errorf("list without session: %d", rec.Code)
	}
	rec := do(d, req{method: "GET", path: "/api/v1/admin/requests", cookie: c})
	var list struct {
		Requests []struct{ ID, Method, URI string } `json:"requests"`
	}
	json.Unmarshal(rec.Body.Bytes(), &list)
	if rec.Code != 200 || len(list.Requests) != 1 || list.Requests[0].URI != "/hook?x=1" || list.Requests[0].Method != "POST" {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}

	rec = do(d, req{method: "GET", path: "/api/v1/admin/requests/" + id, cookie: c})
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"text":"{\"a\":1}"`) || !strings.Contains(rec.Body.String(), `"replayable":true`) {
		t.Fatalf("detail: %d %s", rec.Code, rec.Body)
	}

	if rec := do(d, req{method: "POST", path: "/api/v1/admin/requests/" + id + "/replay", cookie: c}); rec.Code != http.StatusForbidden {
		t.Errorf("replay without CSRF header: %d", rec.Code)
	}
	rec = do(d, req{method: "POST", path: "/api/v1/admin/requests/" + id + "/replay", cookie: c, csrf: true})
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"status":202`) {
		t.Fatalf("replay: %d %s", rec.Code, rec.Body)
	}
	g := target.got
	if g.Method != "POST" || g.Host != "api.tunnel.example.com" || g.URL.RequestURI() != "/hook?x=1" || target.body != `{"a":1}` {
		t.Errorf("replayed request: %s %s%s body=%q", g.Method, g.Host, g.URL.RequestURI(), target.body)
	}
	if g.Header.Get("X-Forwarded-For") != "" || g.Header.Get("X-Custom") != "keep" {
		t.Errorf("replay headers: %v", g.Header)
	}
}

func TestReplayRefusedForTruncatedBody(t *testing.T) {
	d, cs, target, s := setupInspector(t)
	c := login(t, d)
	id := addCapture(t, cs, s, &inspect.Record{Hostname: "a.tunnel.example.com", Method: "POST", URI: "/", ReqBody: []byte("part"), ReqSize: 1000})
	rec := do(d, req{method: "POST", path: "/api/v1/admin/requests/" + id + "/replay", cookie: c, csrf: true})
	if rec.Code != http.StatusConflict || target.got != nil {
		t.Errorf("truncated replay: %d, sent=%v", rec.Code, target.got != nil)
	}
}

func TestRequestsDisabledWithoutInspector(t *testing.T) {
	d, _, _ := setup(t)
	c := login(t, d)
	rec := do(d, req{method: "GET", path: "/api/v1/admin/requests", cookie: c})
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "inspector_disabled") {
		t.Errorf("disabled inspector: %d %s", rec.Code, rec.Body)
	}
}

func TestUnknownRequestIs404(t *testing.T) {
	d, _, _, _ := setupInspector(t)
	c := login(t, d)
	if rec := do(d, req{method: "GET", path: "/api/v1/admin/requests/" + inspect.NewID(), cookie: c}); rec.Code != http.StatusNotFound {
		t.Errorf("unknown id: %d", rec.Code)
	}
}

func TestUsersSeeOnlyTheirOwnRequests(t *testing.T) {
	d, cs, _, s := setupInspector(t)
	st := lastStore
	hash, _ := dashboard.HashPassword(password)
	st.add(postgres.Account{ID: "u-tino", Username: "tino", PasswordHash: hash, PasswordChangedAt: time.Now().Add(-time.Hour)})
	mine := addCapture(t, cs, s, &inspect.Record{UserID: "u-tino", Hostname: "mine.tunnel.example.com", Method: "GET", URI: "/a", Status: 200})
	theirs := addCapture(t, cs, s, &inspect.Record{UserID: "a1", Hostname: "root.tunnel.example.com", Method: "GET", URI: "/secret", Status: 200})
	c := loginAs(t, d, "tino", password)

	list := do(d, req{method: "GET", path: "/api/v1/me/requests", cookie: c}).Body.String()
	if !strings.Contains(list, mine) || strings.Contains(list, theirs) || strings.Contains(list, "/secret") {
		t.Errorf("list: %s", list)
	}
	if rec := do(d, req{method: "GET", path: "/api/v1/me/requests/" + theirs, cookie: c}); rec.Code != http.StatusNotFound {
		t.Errorf("reading someone else's request: %d", rec.Code)
	}
	if rec := do(d, req{method: "POST", path: "/api/v1/me/requests/" + theirs + "/replay", cookie: c, csrf: true}); rec.Code != http.StatusNotFound {
		t.Errorf("replaying someone else's request: %d", rec.Code)
	}
	if rec := do(d, req{method: "GET", path: "/api/v1/me/requests/" + mine, cookie: c}); rec.Code != http.StatusOK {
		t.Errorf("own request: %d", rec.Code)
	}
}
