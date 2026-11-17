package dashboard_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tinoimammp/mancar/internal/dashboard"
	"github.com/tinoimammp/mancar/internal/gateway"
	"github.com/tinoimammp/mancar/internal/store/postgres"
	"github.com/tinoimammp/mancar/internal/usage"
)

// fakeStore is an in-memory dashboard.Store.
type fakeStore struct {
	admins  map[string]postgres.Admin // by username
	users   []postgres.UserInfo
	tokens  []postgres.TokenInfo
	domains []postgres.DomainInfo
	usage   map[string]postgres.UsageWindows
}

func (f *fakeStore) AdminByUsername(_ context.Context, u string) (postgres.Admin, error) {
	if a, ok := f.admins[u]; ok {
		return a, nil
	}
	return postgres.Admin{}, postgres.ErrNotFound
}

func (f *fakeStore) AdminByID(_ context.Context, id string) (postgres.Admin, error) {
	for _, a := range f.admins {
		if a.ID == id {
			return a, nil
		}
	}
	return postgres.Admin{}, postgres.ErrNotFound
}

func (f *fakeStore) TouchAdminLogin(context.Context, string) error { return nil }

func (f *fakeStore) ListUsers(context.Context) ([]postgres.UserInfo, error) { return f.users, nil }

func (f *fakeStore) EnsureUser(_ context.Context, u string) (string, error) {
	for _, x := range f.users {
		if x.Username == u {
			return x.ID, nil
		}
	}
	f.users = append(f.users, postgres.UserInfo{ID: "u-" + u, Username: u})
	return "u-" + u, nil
}

func (f *fakeStore) DeleteUser(_ context.Context, id string) error { return nil }

func (f *fakeStore) ListAgentTokens(context.Context) ([]postgres.TokenInfo, error) {
	return f.tokens, nil
}

func (f *fakeStore) CreateAgentToken(_ context.Context, uid, name string) (string, string, error) {
	f.tokens = append(f.tokens, postgres.TokenInfo{ID: "t1", Name: name})
	return "mc_secret", "t1", nil
}

func (f *fakeStore) RevokeAgentToken(_ context.Context, id string) error {
	for i := range f.tokens {
		if f.tokens[i].ID == id && f.tokens[i].RevokedAt == nil {
			now := time.Now()
			f.tokens[i].RevokedAt = &now
			return nil
		}
	}
	return postgres.ErrNotFound
}

func (f *fakeStore) ListDomains(context.Context) ([]postgres.DomainInfo, error) {
	return f.domains, nil
}

func (f *fakeStore) ReleaseDomain(context.Context, string) error { return postgres.ErrNotFound }

func (f *fakeStore) UsageByHost(context.Context) (map[string]postgres.UsageWindows, error) {
	return f.usage, nil
}

func (f *fakeStore) UsageByUser(context.Context) (map[string]postgres.UsageWindows, error) {
	return nil, nil
}

type fakeHub struct{ disconnectedTokens []string }

func (h *fakeHub) Stats() gateway.Stats            { return gateway.Stats{} }
func (h *fakeHub) Sessions() []gateway.SessionInfo { return nil }
func (h *fakeHub) Disconnect(string) bool          { return false }
func (h *fakeHub) DisconnectToken(id string) int {
	h.disconnectedTokens = append(h.disconnectedTokens, id)
	return 1
}

const password = "correct horse battery"

func setup(t *testing.T) (*dashboard.Dashboard, *fakeStore, *fakeHub) {
	t.Helper()
	hash, err := dashboard.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	st := &fakeStore{admins: map[string]postgres.Admin{
		"root": {ID: "a1", Username: "root", PasswordHash: hash, PasswordChangedAt: time.Now().Add(-time.Hour)},
	}}
	hub := &fakeHub{}
	d := dashboard.New(dashboard.Options{
		Store: st, Hub: hub, SessionSecret: strings.Repeat("s", 32), Secure: true,
		BaseDomain: "tunnel.example.com", PublicScheme: "https",
	})
	return d, st, hub
}

type req struct {
	method, path, body string
	cookie             *http.Cookie
	csrf               bool
	origin             string
}

func do(d http.Handler, r req) *httptest.ResponseRecorder {
	var body *strings.Reader
	if r.body != "" {
		body = strings.NewReader(r.body)
	} else {
		body = strings.NewReader("")
	}
	q := httptest.NewRequest(r.method, "https://tunnel.example.com"+r.path, body)
	q.RemoteAddr = "198.51.100.7:4000"
	if r.cookie != nil {
		q.AddCookie(r.cookie)
	}
	if r.csrf {
		q.Header.Set(dashboard.HeaderCSRF, "1")
	}
	if r.origin != "" {
		q.Header.Set("Origin", r.origin)
	}
	rec := httptest.NewRecorder()
	d.ServeHTTP(rec, q)
	return rec
}

func login(t *testing.T, d http.Handler) *http.Cookie {
	t.Helper()
	rec := do(d, req{method: "POST", path: "/api/v1/admin/login", body: `{"username":"root","password":"` + password + `"}`, csrf: true})
	if rec.Code != http.StatusOK {
		t.Fatalf("login: %d %s", rec.Code, rec.Body)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "__Host-mancar_session" {
			if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode || c.Path != "/" {
				t.Errorf("session cookie lacks protections: %+v", c)
			}
			return c
		}
	}
	t.Fatal("no session cookie")
	return nil
}

func TestPasswordHashRoundTrip(t *testing.T) {
	h, err := dashboard.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(h, password) {
		t.Fatal("hash contains the password")
	}
	if ok, _ := dashboard.CheckPassword(h, password); !ok {
		t.Error("correct password rejected")
	}
	if ok, _ := dashboard.CheckPassword(h, password+"x"); ok {
		t.Error("wrong password accepted")
	}
	if _, err := dashboard.HashPassword("short"); err == nil {
		t.Error("short password accepted")
	}
}

func TestAPIRequiresSession(t *testing.T) {
	d, _, _ := setup(t)
	for _, p := range []string{"/api/v1/admin/session", "/api/v1/admin/tokens", "/api/v1/admin/agents"} {
		if rec := do(d, req{method: "GET", path: p}); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s without session: %d", p, rec.Code)
		}
	}
	forged := &http.Cookie{Name: "__Host-mancar_session", Value: "eyJhIjoiYTEifQ.AAAA"}
	if rec := do(d, req{method: "GET", path: "/api/v1/admin/session", cookie: forged}); rec.Code != http.StatusUnauthorized {
		t.Errorf("forged session accepted: %d", rec.Code)
	}
}

func TestLoginAndSession(t *testing.T) {
	d, _, _ := setup(t)
	c := login(t, d)
	rec := do(d, req{method: "GET", path: "/api/v1/admin/session", cookie: c})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"root"`) {
		t.Fatalf("session: %d %s", rec.Code, rec.Body)
	}
}

func TestWrongPasswordAndRateLimit(t *testing.T) {
	d, _, _ := setup(t)
	bad := `{"username":"root","password":"nope nope nope"}`
	for i := 0; i < 10; i++ {
		if rec := do(d, req{method: "POST", path: "/api/v1/admin/login", body: bad, csrf: true}); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i, rec.Code)
		}
	}
	rec := do(d, req{method: "POST", path: "/api/v1/admin/login", body: `{"username":"root","password":"` + password + `"}`, csrf: true})
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Errorf("after 10 failures the correct password got %d, want 429", rec.Code)
	}
}

func TestUnknownUserLooksLikeWrongPassword(t *testing.T) {
	d, _, _ := setup(t)
	rec := do(d, req{method: "POST", path: "/api/v1/admin/login", body: `{"username":"ghost","password":"whatever-123456"}`, csrf: true})
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "invalid_credentials") {
		t.Errorf("unknown user: %d %s", rec.Code, rec.Body)
	}
}

func TestCSRFProtection(t *testing.T) {
	d, _, _ := setup(t)
	c := login(t, d)
	body := `{"user":"alice","name":"laptop"}`
	if rec := do(d, req{method: "POST", path: "/api/v1/admin/tokens", body: body, cookie: c}); rec.Code != http.StatusForbidden {
		t.Errorf("no CSRF header: %d", rec.Code)
	}
	if rec := do(d, req{method: "POST", path: "/api/v1/admin/tokens", body: body, cookie: c, csrf: true, origin: "https://evil.tunnel.example.com"}); rec.Code != http.StatusForbidden {
		t.Errorf("foreign origin (a tunnel subdomain): %d", rec.Code)
	}
	if rec := do(d, req{method: "POST", path: "/api/v1/admin/login", body: `{"username":"root","password":"` + password + `"}`}); rec.Code != http.StatusForbidden {
		t.Errorf("login without CSRF header: %d", rec.Code)
	}
	if rec := do(d, req{method: "POST", path: "/api/v1/admin/tokens", body: body, cookie: c, csrf: true, origin: "https://tunnel.example.com"}); rec.Code != http.StatusCreated {
		t.Errorf("same origin: %d %s", rec.Code, rec.Body)
	}
}

func TestTokenCreateAndRevoke(t *testing.T) {
	d, _, hub := setup(t)
	c := login(t, d)
	rec := do(d, req{method: "POST", path: "/api/v1/admin/tokens", body: `{"user":"Alice","name":"laptop"}`, cookie: c, csrf: true})
	var out map[string]string
	json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != http.StatusCreated || out["token"] != "mc_secret" || out["user"] != "alice" {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	if rec := do(d, req{method: "POST", path: "/api/v1/admin/tokens", body: `{"user":"bad user!","name":"x"}`, cookie: c, csrf: true}); rec.Code != http.StatusBadRequest {
		t.Errorf("invalid username: %d", rec.Code)
	}
	list := do(d, req{method: "GET", path: "/api/v1/admin/tokens", cookie: c})
	if strings.Contains(list.Body.String(), "mc_secret") {
		t.Error("token list leaks the secret")
	}
	if rec := do(d, req{method: "POST", path: "/api/v1/admin/tokens/t1/revoke", cookie: c, csrf: true}); rec.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body)
	}
	if len(hub.disconnectedTokens) != 1 || hub.disconnectedTokens[0] != "t1" {
		t.Error("revoking did not disconnect the token's agents")
	}
	if rec := do(d, req{method: "POST", path: "/api/v1/admin/tokens/t1/revoke", cookie: c, csrf: true}); rec.Code != http.StatusNotFound {
		t.Errorf("second revoke: %d", rec.Code)
	}
}

func TestPasswordResetEndsSessions(t *testing.T) {
	d, st, _ := setup(t)
	c := login(t, d)
	a := st.admins["root"]
	a.PasswordChangedAt = time.Now().Add(time.Second)
	st.admins["root"] = a
	if rec := do(d, req{method: "GET", path: "/api/v1/admin/session", cookie: c}); rec.Code != http.StatusUnauthorized {
		t.Errorf("session survived a password reset: %d", rec.Code)
	}
	delete(st.admins, "root")
	if rec := do(d, req{method: "GET", path: "/api/v1/admin/session", cookie: c}); rec.Code != http.StatusUnauthorized {
		t.Errorf("session survived admin deletion: %d", rec.Code)
	}
}

func TestStaticPageAndHeaders(t *testing.T) {
	d, _, _ := setup(t)
	rec := do(d, req{method: "GET", path: "/dashboard/"})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "app.js") {
		t.Fatalf("index: %d", rec.Code)
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe-inline") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("weak CSP: %q", csp)
	}
	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("missing X-Frame-Options")
	}
	for _, f := range []string{"app.js", "style.css", "theme.js"} {
		if rec := do(d, req{method: "GET", path: "/dashboard/" + f}); rec.Code != http.StatusOK {
			t.Errorf("%s: %d", f, rec.Code)
		}
	}
	// the logo must be served as an image: nosniff makes the browser trust the type
	rec = do(d, req{method: "GET", path: "/dashboard/logo.webp"})
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "image/webp" {
		t.Errorf("logo.webp: %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
}

func TestDisabledWithoutStore(t *testing.T) {
	d := dashboard.New(dashboard.Options{Hub: &fakeHub{}})
	if rec := do(d, req{method: "GET", path: "/api/v1/admin/session"}); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("api without store: %d", rec.Code)
	}
	if rec := do(d, req{method: "GET", path: "/dashboard/"}); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("page without store: %d", rec.Code)
	}
}

func TestOverviewShowsTraffic(t *testing.T) {
	d, st, _ := setup(t)
	st.usage = map[string]postgres.UsageWindows{
		"a.tunnel.example.com": {Day: usage.Totals{Requests: 7, Errors: 2}, Week: usage.Totals{Requests: 70}},
		"b.tunnel.example.com": {Day: usage.Totals{Requests: 30}},
		"idle.example.com":     {Week: usage.Totals{Requests: 5}},
	}
	c := login(t, d)
	rec := do(d, req{method: "GET", path: "/api/v1/admin/overview", cookie: c})
	var o struct {
		Traffic  usage.Totals `json:"traffic_24h"`
		TopHosts []struct {
			Hostname string `json:"hostname"`
		} `json:"top_hosts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &o); err != nil || rec.Code != 200 {
		t.Fatalf("overview: %d %s", rec.Code, rec.Body)
	}
	if o.Traffic.Requests != 37 || o.Traffic.Errors != 2 {
		t.Errorf("24h totals: %+v", o.Traffic)
	}
	if len(o.TopHosts) != 2 || o.TopHosts[0].Hostname != "b.tunnel.example.com" {
		t.Errorf("top hosts (busiest first, idle ones left out): %+v", o.TopHosts)
	}
}
