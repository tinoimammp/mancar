package router_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/tinoimammp/mancar/internal/gateway"
	"github.com/tinoimammp/mancar/internal/router"
)

// fakeTunnels is a router.Tunnels that records every lookup.
type fakeTunnels struct {
	mu        sync.Mutex
	hosts     map[string]*gateway.Tunnel
	hostCalls []string
	idCalls   []string
}

func (f *fakeTunnels) LookupHost(h string) *gateway.Tunnel {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hostCalls = append(f.hostCalls, h)
	return f.hosts[h]
}

// LookupID always reports "gone": the tunnel disappeared between the host
// lookup and the dial, which is the stale-tunnel case.
func (f *fakeTunnels) LookupID(id string) *gateway.Tunnel {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.idCalls = append(f.idCalls, id)
	return nil
}

func (f *fakeTunnels) snapshot() (hosts, ids []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.hostCalls...), append([]string(nil), f.idCalls...)
}

type harness struct {
	rt       *router.Router
	tunnels  *fakeTunnels
	mgmtHits int
	logs     *bytes.Buffer
}

func newHarness(t *testing.T, mutate func(*router.Options)) *harness {
	t.Helper()
	h := &harness{
		tunnels: &fakeTunnels{hosts: map[string]*gateway.Tunnel{
			"app.mydomain.com": {ID: "t1", Hostname: "app.mydomain.com"},
		}},
		logs: &bytes.Buffer{},
	}
	opts := router.Options{
		BaseDomain: "mydomain.com",
		Tunnels:    h.tunnels,
		Management: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			h.mgmtHits++
			io.WriteString(w, "management")
		}),
		Logger: slog.New(slog.NewTextHandler(h.logs, nil)),
	}
	if mutate != nil {
		mutate(&opts)
	}
	h.rt = router.New(opts)
	return h
}

func (h *harness) do(method, host, path string, body io.Reader) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "http://"+host+path, body)
	req.Host = host
	rec := httptest.NewRecorder()
	h.rt.ServeHTTP(rec, req)
	return rec
}

func TestBaseDomainGoesToManagement(t *testing.T) {
	for _, host := range []string{"mydomain.com", "MyDomain.COM", "mydomain.com:8443", "mydomain.com."} {
		h := newHarness(t, nil)
		rec := h.do("GET", host, "/healthz", nil)
		if rec.Code != 200 || rec.Body.String() != "management" || h.mgmtHits != 1 {
			t.Errorf("host %q: status=%d body=%q hits=%d", host, rec.Code, rec.Body.String(), h.mgmtHits)
		}
		if hosts, _ := h.tunnels.snapshot(); len(hosts) != 0 {
			t.Errorf("host %q: the tunnel table was consulted for the base domain: %v", host, hosts)
		}
	}
}

func TestForeignHostsAreNeverRouted(t *testing.T) {
	// A host that is not under the base domain must never reach a tunnel or
	// the management handler: that is what prevents open-proxy behaviour.
	for _, host := range []string{
		"evil.com", "notmydomain.com", "mydomain.com.evil.com", "localhost",
		"127.0.0.1:8080", "app.mydomain.com.evil.com", "xmydomain.com",
	} {
		h := newHarness(t, nil)
		rec := h.do("GET", host, "/", nil)
		if rec.Code != http.StatusNotFound {
			t.Errorf("host %q: status = %d, want 404", host, rec.Code)
		}
		if got := rec.Header().Get(router.HeaderError); got != "unknown_host" {
			t.Errorf("host %q: %s = %q, want unknown_host", host, router.HeaderError, got)
		}
		if h.mgmtHits != 0 {
			t.Errorf("host %q reached the management handler", host)
		}
		if hosts, ids := h.tunnels.snapshot(); len(hosts)+len(ids) != 0 {
			t.Errorf("host %q reached the tunnel table: %v %v", host, hosts, ids)
		}
	}
}

func TestUnknownTunnelIsNotFound(t *testing.T) {
	h := newHarness(t, nil)
	rec := h.do("GET", "ghost.mydomain.com", "/", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := rec.Header().Get(router.HeaderError); got != "tunnel_not_found" {
		t.Errorf("%s = %q", router.HeaderError, got)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "ghost.mydomain.com") || !strings.Contains(body, "tunnel_not_found") {
		t.Errorf("body = %q", body)
	}
	if h.mgmtHits != 0 {
		t.Error("management handler was invoked for a tunnel host")
	}
}

func TestHostIsNormalisedBeforeLookup(t *testing.T) {
	h := newHarness(t, func(o *router.Options) { o.BaseDomain = "MyDomain.COM" })
	h.do("GET", "Ghost.MyDomain.com.:8443", "/", nil)
	hosts, _ := h.tunnels.snapshot()
	if len(hosts) != 1 || hosts[0] != "ghost.mydomain.com" {
		t.Errorf("LookupHost calls = %v, want [ghost.mydomain.com]", hosts)
	}
}

func TestNestedSubdomainIsLookedUpVerbatim(t *testing.T) {
	// The router must not strip labels: a.b.mydomain.com is a different
	// hostname from b.mydomain.com and must not inherit its tunnel.
	h := newHarness(t, nil)
	rec := h.do("GET", "x.app.mydomain.com", "/", nil)
	if rec.Code != http.StatusNotFound || rec.Header().Get(router.HeaderError) != "tunnel_not_found" {
		t.Errorf("status=%d err=%q", rec.Code, rec.Header().Get(router.HeaderError))
	}
	hosts, ids := h.tunnels.snapshot()
	if len(hosts) != 1 || hosts[0] != "x.app.mydomain.com" || len(ids) != 0 {
		t.Errorf("lookups: hosts=%v ids=%v", hosts, ids)
	}
}

func TestPlatformErrorsAreHardened(t *testing.T) {
	h := newHarness(t, nil)
	for _, host := range []string{"evil.com", "ghost.mydomain.com"} {
		rec := h.do("GET", host, "/<script>alert(1)</script>", nil)
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
			t.Errorf("%s: Content-Type = %q, want text/plain", host, ct)
		}
		if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: missing X-Content-Type-Options: nosniff", host)
		}
		if strings.Contains(rec.Body.String(), "<script>") {
			t.Errorf("%s: request path reflected into the error body", host)
		}
	}
}

func TestRequestBodyLimit(t *testing.T) {
	limit := func(o *router.Options) { o.MaxBodyBytes = 10 }

	t.Run("declared length over the limit is refused before dialing", func(t *testing.T) {
		h := newHarness(t, limit)
		rec := h.do("POST", "app.mydomain.com", "/upload", strings.NewReader(strings.Repeat("x", 100)))
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want 413", rec.Code)
		}
		if rec.Header().Get(router.HeaderError) != "request_too_large" {
			t.Errorf("%s = %q", router.HeaderError, rec.Header().Get(router.HeaderError))
		}
		if _, ids := h.tunnels.snapshot(); len(ids) != 0 {
			t.Errorf("tunnel was dialed for an oversized request: %v", ids)
		}
	})
	t.Run("exactly at the limit is accepted", func(t *testing.T) {
		h := newHarness(t, limit)
		rec := h.do("POST", "app.mydomain.com", "/upload", strings.NewReader(strings.Repeat("x", 10)))
		if rec.Code == http.StatusRequestEntityTooLarge {
			t.Errorf("a body of exactly the limit was refused")
		}
	})
	t.Run("zero means unlimited", func(t *testing.T) {
		h := newHarness(t, func(o *router.Options) { o.MaxBodyBytes = 0 })
		rec := h.do("POST", "app.mydomain.com", "/upload", strings.NewReader(strings.Repeat("x", 1<<16)))
		if rec.Code == http.StatusRequestEntityTooLarge {
			t.Errorf("unlimited router refused a body")
		}
	})
}

func TestStaleTunnelYieldsBadGateway(t *testing.T) {
	h := newHarness(t, nil)
	rec := h.do("GET", "app.mydomain.com", "/", nil)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	if rec.Header().Get(router.HeaderError) != "tunnel_unreachable" {
		t.Errorf("%s = %q", router.HeaderError, rec.Header().Get(router.HeaderError))
	}
	_, ids := h.tunnels.snapshot()
	if len(ids) == 0 {
		t.Fatal("router never tried to dial the tunnel")
	}
	for _, id := range ids {
		if id != "t1" {
			t.Errorf("dialed tunnel %q, want t1", id)
		}
	}
	// Internal addressing must not leak to the public client.
	for _, leak := range []string{"tunnel.invalid", "t1.", "gateway:"} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Errorf("response leaks internal detail %q: %q", leak, rec.Body.String())
		}
	}
}

func TestClientDisconnectIsNotReportedAsServerError(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest("GET", "http://app.mydomain.com/", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	h.rt.ServeHTTP(rec, req)
	if rec.Code != 499 {
		t.Errorf("status = %d, want 499 (client closed request)", rec.Code)
	}
}

func TestAccessLogOmitsQueryString(t *testing.T) {
	h := newHarness(t, nil)
	h.do("GET", "app.mydomain.com", "/reset?token=SUPERSECRET&q=1", nil)
	out := h.logs.String()
	if !strings.Contains(out, "/reset") || !strings.Contains(out, "app.mydomain.com") {
		t.Errorf("access log is missing host/path: %s", out)
	}
	if strings.Contains(out, "SUPERSECRET") || strings.Contains(out, "token=") {
		t.Errorf("access log leaks the query string: %s", out)
	}
}
