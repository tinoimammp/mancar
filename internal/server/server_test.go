package server_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/USERNAME/mancar/internal/auth"
	"github.com/USERNAME/mancar/internal/config"
	"github.com/USERNAME/mancar/internal/domain"
	"github.com/USERNAME/mancar/internal/protocol"
	"github.com/USERNAME/mancar/internal/router"
	"github.com/USERNAME/mancar/internal/server"
	"github.com/USERNAME/mancar/internal/version"
)

func devConfig(t *testing.T) *config.Config {
	t.Helper()
	e := map[string]string{"APP_ENV": "development", "BASE_DOMAIN": "mydomain.com", "STORAGE": "memory"}
	cfg, err := config.Load(func(k string) string { return e[k] })
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func newServer(t *testing.T, mutate func(*server.Deps)) *server.Server {
	t.Helper()
	d := server.Deps{
		Config:   devConfig(t),
		Auth:     auth.NewMemory(),
		Registry: domain.NewMemoryRegistry(),
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if mutate != nil {
		mutate(&d)
	}
	return server.New(d)
}

func get(h http.Handler, host, path string) *httptest.ResponseRecorder {
	return do(h, http.MethodGet, host, path)
}

func do(h http.Handler, method, host, path string) *httptest.ResponseRecorder {
	return doFrom(h, method, host, path, "192.0.2.1:1234")
}

// doFrom sends a request whose TCP peer is remote.
func doFrom(h http.Handler, method, host, path, remote string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "http://"+host+path, nil)
	req.Host = host
	req.RemoteAddr = remote
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// internalGet is a request from inside the deployment (loopback / private
// network), which is allowed to see health details.
func internalGet(h http.Handler, host, path string) *httptest.ResponseRecorder {
	return doFrom(h, http.MethodGet, host, path, "127.0.0.1:1234")
}

type healthBody struct {
	Status   string `json:"status"`
	Version  string `json:"version"`
	Database string `json:"database"`
	Gateway  struct {
		Sessions int `json:"sessions"`
		Tunnels  int `json:"tunnels"`
	} `json:"gateway"`
}

func decodeHealth(t *testing.T, rec *httptest.ResponseRecorder) healthBody {
	t.Helper()
	var h healthBody
	if err := json.Unmarshal(rec.Body.Bytes(), &h); err != nil {
		t.Fatalf("health body is not JSON: %v: %q", err, rec.Body.String())
	}
	return h
}

func TestHealthz(t *testing.T) {
	rec := get(newServer(t, nil).Handler(), "mydomain.com", "/healthz")
	if rec.Code != http.StatusOK || rec.Body.String() != "ok\n" {
		t.Errorf("status=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestHealthz_OnlyGET(t *testing.T) {
	rec := do(newServer(t, nil).Handler(), http.MethodPost, "mydomain.com", "/healthz")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /healthz = %d, want 405", rec.Code)
	}
}

func TestSystemHealth_WithoutDatabaseCheck(t *testing.T) {
	rec := internalGet(newServer(t, nil).Handler(), "mydomain.com", "/api/v1/system/health")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	h := decodeHealth(t, rec)
	if h.Status != "ok" || h.Database != "not_configured" || h.Version != version.Version {
		t.Errorf("health = %+v", h)
	}
	if h.Gateway.Sessions != 0 || h.Gateway.Tunnels != 0 {
		t.Errorf("gateway stats = %+v", h.Gateway)
	}
}

func TestSystemHealth_DatabaseOK(t *testing.T) {
	s := newServer(t, func(d *server.Deps) { d.HealthCheck = func(context.Context) error { return nil } })
	rec := internalGet(s.Handler(), "mydomain.com", "/api/v1/system/health")
	h := decodeHealth(t, rec)
	if rec.Code != http.StatusOK || h.Status != "ok" || h.Database != "ok" {
		t.Errorf("status=%d health=%+v", rec.Code, h)
	}
}

func TestSystemHealth_DatabaseDownIsDegradedWithoutLeakingDetails(t *testing.T) {
	s := newServer(t, func(d *server.Deps) {
		d.HealthCheck = func(context.Context) error {
			return errors.New("dial tcp 10.1.2.3:5432: connection refused (password=hunter2)")
		}
	})
	rec := internalGet(s.Handler(), "mydomain.com", "/api/v1/system/health")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	h := decodeHealth(t, rec)
	if h.Status != "degraded" || h.Database != "unreachable" {
		t.Errorf("health = %+v", h)
	}
	for _, leak := range []string{"10.1.2.3", "hunter2", "connection refused"} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Errorf("health body leaks %q: %s", leak, rec.Body.String())
		}
	}
}

func TestSystemHealth_ChecksGetADeadline(t *testing.T) {
	var hadDeadline bool
	s := newServer(t, func(d *server.Deps) {
		d.HealthCheck = func(ctx context.Context) error {
			_, hadDeadline = ctx.Deadline()
			return nil
		}
	})
	internalGet(s.Handler(), "mydomain.com", "/api/v1/system/health")
	if !hadDeadline {
		t.Error("the health check ran without a timeout; a hung database would hang the endpoint")
	}
}

func TestRootBannerDoesNotRevealTheVersion(t *testing.T) {
	rec := get(newServer(t, nil).Handler(), "mydomain.com", "/")
	if rec.Code != http.StatusOK || rec.Body.String() != "mancar gateway\n" {
		t.Errorf("status=%d body=%q", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), version.Version) && version.Version != "" {
		t.Error("the public banner leaks the version")
	}
}

func TestUnknownManagementPathIs404(t *testing.T) {
	rec := get(newServer(t, nil).Handler(), "mydomain.com", "/definitely/not/here")
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d", rec.Code)
	}
}

func TestConnectEndpointIsMountedOnTheBaseDomain(t *testing.T) {
	rec := get(newServer(t, nil).Handler(), "mydomain.com", protocol.ConnectPath)
	if rec.Code != http.StatusUpgradeRequired {
		t.Errorf("status = %d, want 426 from the agent endpoint", rec.Code)
	}
}

func TestConnectEndpointIsNotReachableThroughTunnelHosts(t *testing.T) {
	// A tunnel hostname must never expose the gateway's control endpoint.
	rec := get(newServer(t, nil).Handler(), "app.mydomain.com", protocol.ConnectPath)
	if rec.Code != http.StatusNotFound || rec.Header().Get(router.HeaderError) != "tunnel_not_found" {
		t.Errorf("status=%d err=%q", rec.Code, rec.Header().Get(router.HeaderError))
	}
}

func TestSubdomainWithoutTunnelIsNotFound(t *testing.T) {
	rec := get(newServer(t, nil).Handler(), "nobody.mydomain.com", "/")
	if rec.Code != http.StatusNotFound || rec.Header().Get(router.HeaderError) != "tunnel_not_found" {
		t.Errorf("status=%d err=%q", rec.Code, rec.Header().Get(router.HeaderError))
	}
}

func TestForeignHostIsNotServed(t *testing.T) {
	for _, host := range []string{"evil.com", "mydomain.com.evil.com", "127.0.0.1:8080"} {
		for _, path := range []string{"/", "/healthz", protocol.ConnectPath} {
			rec := get(newServer(t, nil).Handler(), host, path)
			if rec.Code != http.StatusNotFound || rec.Header().Get(router.HeaderError) != "unknown_host" {
				t.Errorf("host %q path %q: status=%d err=%q", host, path, rec.Code, rec.Header().Get(router.HeaderError))
			}
		}
	}
}

func TestHubIsExposed(t *testing.T) {
	s := newServer(t, nil)
	if s.Hub() == nil {
		t.Fatal("Hub() returned nil")
	}
	if st := s.Hub().Stats(); st.Sessions != 0 || st.Tunnels != 0 {
		t.Errorf("Stats = %+v", st)
	}
}

func TestServe_ServesAndShutsDownGracefully(t *testing.T) {
	s := newServer(t, nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, ln) }()

	req, _ := http.NewRequest(http.MethodGet, "http://"+ln.Addr().String()+"/healthz", nil)
	req.Host = "mydomain.com"
	var resp *http.Response
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err = http.DefaultClient.Do(req)
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		cancel()
		t.Fatalf("GET /healthz over TCP: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "ok\n" {
		t.Errorf("status=%d body=%q", resp.StatusCode, body)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve returned %v after a graceful shutdown, want nil", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Serve did not return after the context was cancelled")
	}
	if _, err := net.DialTimeout("tcp", ln.Addr().String(), 500*time.Millisecond); err == nil {
		t.Error("listener still accepting connections after shutdown")
	}
}

func TestServe_FailsFastWhenRegistryResetFails(t *testing.T) {
	s := newServer(t, func(d *server.Deps) { d.Registry = brokenRegistry{} })
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(context.Background(), ln) }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("Serve succeeded although stale reservations could not be cleared")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve kept running with a broken registry")
	}
	if _, err := net.DialTimeout("tcp", ln.Addr().String(), 500*time.Millisecond); err == nil {
		t.Error("listener left open after a failed start")
	}
}

type brokenRegistry struct{}

func (brokenRegistry) Claim(context.Context, domain.Claim) (string, error) {
	return "", errors.New("down")
}
func (brokenRegistry) Release(context.Context, string, string, time.Duration) error {
	return errors.New("down")
}
func (brokenRegistry) ReleaseAll(context.Context, time.Duration) error { return errors.New("down") }
func (brokenRegistry) Purge(context.Context) error                     { return errors.New("down") }

func failedHandshake(h http.Handler, remote string, i int) int {
	req := httptest.NewRequest(http.MethodGet, "http://mydomain.com"+protocol.ConnectPath, nil)
	req.Host = "mydomain.com"
	req.RemoteAddr = remote
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", protocol.UpgradeToken)
	req.Header.Set("Authorization", "Bearer "+auth.TokenPrefix+strings.Repeat(string(rune('0'+i%10)), 64))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestAgentLoginFailuresAreRateLimitedByDefault(t *testing.T) {
	h := newServer(t, nil).Handler()
	for i := 0; i < 10; i++ {
		if code := failedHandshake(h, "198.51.100.7:1", i); code != http.StatusUnauthorized {
			t.Fatalf("failure %d: %d", i+1, code)
		}
	}
	if code := failedHandshake(h, "198.51.100.7:1", 1); code != http.StatusTooManyRequests {
		t.Errorf("11th failure through the full stack: %d, want 429", code)
	}
}

func TestAgentLoginRateLimitCanBeDisabled(t *testing.T) {
	e := map[string]string{"APP_ENV": "development", "BASE_DOMAIN": "mydomain.com", "STORAGE": "memory", "AUTH_FAILURE_LIMIT_PER_MINUTE": "0"}
	cfg, err := config.Load(func(k string) string { return e[k] })
	if err != nil {
		t.Fatal(err)
	}
	h := server.New(server.Deps{Config: cfg, Auth: auth.NewMemory(), Registry: domain.NewMemoryRegistry()}).Handler()
	for i := 0; i < 50; i++ {
		if code := failedHandshake(h, "198.51.100.7:1", i); code != http.StatusUnauthorized {
			t.Fatalf("failure %d: %d", i+1, code)
		}
	}
}

func TestAgentLoginRateLimitUsesTheRealClientBehindTheEdge(t *testing.T) {
	// Default trusted proxies cover private ranges such as the Docker network
	// the TLS edge lives in.
	h := newServer(t, nil).Handler()
	req := func(client string) int {
		r := httptest.NewRequest(http.MethodGet, "http://mydomain.com"+protocol.ConnectPath, nil)
		r.Host = "mydomain.com"
		r.RemoteAddr = "172.18.0.5:40000" // the edge container
		r.Header.Set("X-Forwarded-For", client)
		r.Header.Set("Connection", "Upgrade")
		r.Header.Set("Upgrade", protocol.UpgradeToken)
		r.Header.Set("Authorization", "Bearer "+auth.TokenPrefix+strings.Repeat("7", 64))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Code
	}
	for i := 0; i < 10; i++ {
		req("198.51.100.7")
	}
	if code := req("198.51.100.7"); code != http.StatusTooManyRequests {
		t.Errorf("abusive client: %d, want 429", code)
	}
	if code := req("203.0.113.9"); code != http.StatusUnauthorized {
		t.Errorf("other client behind the same edge: %d, want 401 (one abuser must not lock out everybody)", code)
	}
}

func TestSystemHealth_ExternalClientsOnlyGetTheVerdict(t *testing.T) {
	check := func(name string, rec *httptest.ResponseRecorder, wantCode int, wantStatus string) {
		t.Helper()
		if rec.Code != wantCode {
			t.Errorf("%s: status %d, want %d", name, rec.Code, wantCode)
		}
		var raw map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
			t.Fatalf("%s: %v: %q", name, err, rec.Body.String())
		}
		if len(raw) != 1 || raw["status"] != wantStatus {
			t.Errorf("%s: body %v, want only {status:%s}", name, raw, wantStatus)
		}
		for _, leak := range []string{version.Version, "sessions", "tunnels", "database", "unreachable"} {
			if strings.Contains(rec.Body.String(), leak) && leak != "" {
				t.Errorf("%s: body leaks %q: %s", name, leak, rec.Body.String())
			}
		}
	}

	h := newServer(t, nil).Handler()
	check("public client", get(h, "mydomain.com", "/api/v1/system/health"), http.StatusOK, "ok")

	down := newServer(t, func(d *server.Deps) {
		d.HealthCheck = func(context.Context) error { return errors.New("boom") }
	}).Handler()
	check("public client, database down", get(down, "mydomain.com", "/api/v1/system/health"), http.StatusServiceUnavailable, "degraded")
}

func TestSystemHealth_ClientIdentityComesFromTheTrustedProxyHeader(t *testing.T) {
	h := newServer(t, nil).Handler()
	hit := func(remote, xff string) map[string]any {
		req := httptest.NewRequest("GET", "http://mydomain.com/api/v1/system/health", nil)
		req.Host = "mydomain.com"
		req.RemoteAddr = remote
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var raw map[string]any
		json.Unmarshal(rec.Body.Bytes(), &raw)
		return raw
	}
	// Through the edge (a private address), the internet client's address
	// decides: a public client sees the minimum...
	if got := hit("172.18.0.5:4000", "198.51.100.7"); len(got) != 1 {
		t.Errorf("public client behind the edge saw details: %v", got)
	}
	// ...while an operator connecting from the private network sees details.
	if got := hit("172.18.0.5:4000", "10.0.0.8"); got["version"] == nil {
		t.Errorf("internal client behind the edge saw no details: %v", got)
	}
	// A public peer cannot claim to be internal by sending a header.
	if got := hit("198.51.100.7:4000", "10.0.0.8"); len(got) != 1 {
		t.Errorf("spoofed X-Forwarded-For unlocked the details: %v", got)
	}
	// Direct loopback access (docker healthcheck, operators on the host).
	if got := hit("127.0.0.1:4000", ""); got["version"] == nil {
		t.Errorf("loopback saw no details: %v", got)
	}
}
