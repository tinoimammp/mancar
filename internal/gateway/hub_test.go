package gateway_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tinoimammp/mancar/internal/auth"
	"github.com/tinoimammp/mancar/internal/domain"
	"github.com/tinoimammp/mancar/internal/gateway"
	"github.com/tinoimammp/mancar/internal/protocol"
)

func newHub(a auth.Authenticator) *gateway.Hub {
	svc := domain.NewService(domain.NewMemoryRegistry(), domain.ServiceOptions{BaseDomain: "example.com"})
	return gateway.NewHub(a, svc, gateway.Options{})
}

func upgradeReq(token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, protocol.ConnectPath, nil)
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Upgrade", protocol.UpgradeToken)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

func serve(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

type failingAuth struct{}

func (failingAuth) AuthenticateAgent(context.Context, string) (auth.Principal, error) {
	return auth.Principal{}, errors.New("db down")
}

func TestHub_RequiresUpgradeHandshake(t *testing.T) {
	hub := newHub(auth.NewMemory())
	mk := func(mutate func(*http.Request)) *http.Request {
		r := upgradeReq("")
		mutate(r)
		return r
	}
	tests := []struct {
		name string
		req  *http.Request
	}{
		{"plain GET", httptest.NewRequest(http.MethodGet, protocol.ConnectPath, nil)},
		{"POST", mk(func(r *http.Request) { r.Method = http.MethodPost })},
		{"missing Connection header", mk(func(r *http.Request) { r.Header.Del("Connection") })},
		{"Connection without upgrade", mk(func(r *http.Request) { r.Header.Set("Connection", "keep-alive") })},
		{"missing Upgrade header", mk(func(r *http.Request) { r.Header.Del("Upgrade") })},
		{"wrong Upgrade protocol", mk(func(r *http.Request) { r.Header.Set("Upgrade", "websocket") })},
		{"future protocol version", mk(func(r *http.Request) { r.Header.Set("Upgrade", "mancar/2") })},
	}
	for _, tc := range tests {
		rec := serve(hub, tc.req)
		if rec.Code != http.StatusUpgradeRequired {
			t.Errorf("%s: status = %d, want 426", tc.name, rec.Code)
		}
		if got := rec.Header().Get("Upgrade"); got != protocol.UpgradeToken {
			t.Errorf("%s: Upgrade header = %q, want %q", tc.name, got, protocol.UpgradeToken)
		}
	}
}

func TestHub_UpgradeHeaderParsingIsLenient(t *testing.T) {
	// A valid handshake in a different spelling must get past the 426 check
	// (it is then stopped by the missing token).
	hub := newHub(auth.NewMemory())
	for _, conn := range []string{"upgrade", "UPGRADE", "keep-alive, Upgrade", "Upgrade, keep-alive"} {
		r := upgradeReq("")
		r.Header.Set("Connection", conn)
		r.Header.Set("Upgrade", strings.ToUpper(protocol.UpgradeToken))
		if rec := serve(hub, r); rec.Code != http.StatusUnauthorized {
			t.Errorf("Connection=%q: status = %d, want 401 (handshake accepted, token missing)", conn, rec.Code)
		}
	}
}

func TestHub_RejectsBadCredentials(t *testing.T) {
	mem := auth.NewMemory()
	revoked, _ := mem.Issue("alice")
	mem.Revoke(revoked)
	unknown := auth.TokenPrefix + strings.Repeat("0", 64)
	hub := newHub(mem)

	tests := []struct {
		name string
		mut  func(*http.Request)
	}{
		{"no Authorization header", func(r *http.Request) {}},
		{"malformed token", func(r *http.Request) { r.Header.Set("Authorization", "Bearer abc") }},
		{"empty bearer", func(r *http.Request) { r.Header.Set("Authorization", "Bearer ") }},
		{"basic auth", func(r *http.Request) { r.Header.Set("Authorization", "Basic dXNlcjpwYXNz") }},
		{"well-formed but unknown", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+unknown) }},
		{"revoked", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+revoked) }},
		{"token in query string only", func(r *http.Request) { r.URL.RawQuery = "token=" + unknown }},
	}
	for _, tc := range tests {
		r := upgradeReq("")
		tc.mut(r)
		rec := serve(hub, r)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: status = %d, want 401", tc.name, rec.Code)
		}
		for _, secret := range []string{unknown, revoked} {
			if strings.Contains(rec.Body.String(), secret) {
				t.Errorf("%s: response body echoes a token", tc.name)
			}
		}
	}
	if st := hub.Stats(); st.Sessions != 0 || st.Tunnels != 0 {
		t.Errorf("rejected agents created state: %+v", st)
	}
}

func TestHub_AuthBackendFailureIsServiceUnavailable(t *testing.T) {
	hub := newHub(failingAuth{})
	tok := auth.TokenPrefix + strings.Repeat("a", 64)
	rec := serve(hub, upgradeReq(tok))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (not 401: the token may be fine)", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "db down") {
		t.Errorf("backend error text leaked to the client: %q", rec.Body.String())
	}
}

func TestHub_RefusesNewAgentsWhileShuttingDown(t *testing.T) {
	mem := auth.NewMemory()
	tok, _ := mem.Issue("alice")
	hub := newHub(mem)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	hub.Shutdown(ctx)

	variants := map[string]func(*http.Request){
		"plain":                   func(r *http.Request) {},
		"lower-case bearer":       func(r *http.Request) { r.Header.Set("Authorization", "bearer "+tok) },
		"invalid instance header": func(r *http.Request) { r.Header.Set(protocol.HeaderInstance, "bad value!") },
		"over-long instance":      func(r *http.Request) { r.Header.Set(protocol.HeaderInstance, strings.Repeat("a", 65)) },
	}
	for name, mut := range variants {
		r := upgradeReq(tok)
		mut(r)
		rec := serve(hub, r)
		if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "shutting down") {
			t.Errorf("%s: status=%d body=%q, want 503 shutting down", name, rec.Code, rec.Body.String())
		}
	}
}

func TestHub_EmptyHubState(t *testing.T) {
	hub := newHub(auth.NewMemory())
	if st := hub.Stats(); st.Sessions != 0 || st.Tunnels != 0 {
		t.Errorf("Stats = %+v", st)
	}
	if hub.LookupHost("app.example.com") != nil {
		t.Error("LookupHost returned a tunnel from an empty hub")
	}
	if hub.LookupID("nope") != nil {
		t.Error("LookupID returned a tunnel from an empty hub")
	}
}

func TestHub_ShutdownOfEmptyHubReturnsPromptly(t *testing.T) {
	hub := newHub(auth.NewMemory())
	done := make(chan struct{})
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		hub.Shutdown(ctx)
		hub.Shutdown(ctx) // idempotent
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Shutdown blocked on an empty hub")
	}
}

func TestHub_ConcurrentRejectedRequests(t *testing.T) {
	burst := func(hub *gateway.Hub) (unauthorized, tooMany int) {
		done := make(chan int, 50)
		for i := 0; i < 50; i++ {
			go func() {
				rec := serve(hub, upgradeReq(auth.TokenPrefix+strings.Repeat("1", 64)))
				done <- rec.Code
			}()
		}
		for i := 0; i < 50; i++ {
			switch code := <-done; code {
			case http.StatusUnauthorized:
				unauthorized++
			case http.StatusTooManyRequests:
				tooMany++
			default:
				t.Errorf("unexpected status %d", code)
			}
		}
		return
	}

	t.Run("without a limit every attempt is simply rejected", func(t *testing.T) {
		u, tm := burst(newHubWith(auth.NewMemory(), gateway.Options{AuthFailureLimit: -1}))
		if u != 50 || tm != 0 {
			t.Errorf("401s=%d 429s=%d, want 50/0", u, tm)
		}
	})
	t.Run("with the default limit the flood is cut off", func(t *testing.T) {
		u, tm := burst(newHubWith(auth.NewMemory(), gateway.Options{}))
		// Check-then-act means a few concurrent requests may slip through
		// before the block takes effect, but at least the allowance is
		// honoured and most of the flood is refused cheaply.
		if u < 10 || tm == 0 || u+tm != 50 {
			t.Errorf("401s=%d 429s=%d", u, tm)
		}
	})
}

func newHubWith(a auth.Authenticator, opts gateway.Options) *gateway.Hub {
	svc := domain.NewService(domain.NewMemoryRegistry(), domain.ServiceOptions{BaseDomain: "example.com"})
	return gateway.NewHub(a, svc, opts)
}
