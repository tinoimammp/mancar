package agent_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/USERNAME/mancar/internal/agent"
	"github.com/USERNAME/mancar/internal/protocol"
)

var testToken = "mc_" + strings.Repeat("a", 64)

func httpTunnel() agent.TunnelSpec {
	return agent.TunnelSpec{Proto: protocol.ProtoHTTP, LocalAddr: "127.0.0.1:3000"}
}

func baseOpts(serverURL string) agent.Options {
	return agent.Options{
		ServerURL:  serverURL,
		Token:      testToken,
		Tunnels:    []agent.TunnelSpec{httpTunnel()},
		MinBackoff: 5 * time.Millisecond,
		MaxBackoff: 20 * time.Millisecond,
	}
}

func TestNew_Validation(t *testing.T) {
	mutate := func(f func(*agent.Options)) agent.Options {
		o := baseOpts("https://tunnel.example.com")
		f(&o)
		return o
	}
	valid := map[string]agent.Options{
		"https url":          baseOpts("https://tunnel.example.com"),
		"http url with port": baseOpts("http://localhost:8080"),
		"tcp tunnel": mutate(func(o *agent.Options) {
			o.Tunnels = []agent.TunnelSpec{{Proto: protocol.ProtoTCP, LocalAddr: "127.0.0.1:5432"}}
		}),
		"ipv6 local address":  mutate(func(o *agent.Options) { o.Tunnels[0].LocalAddr = "[::1]:3000" }),
		"hostname local addr": mutate(func(o *agent.Options) { o.Tunnels[0].LocalAddr = "localhost:3000" }),
		"several tunnels": mutate(func(o *agent.Options) {
			o.Tunnels = []agent.TunnelSpec{httpTunnel(), {Proto: protocol.ProtoTCP, LocalAddr: "127.0.0.1:22"}}
		}),
		"custom subdomain": mutate(func(o *agent.Options) { o.Tunnels[0].Subdomain = "my-api" }),
	}
	for name, o := range valid {
		if a, err := agent.New(o); err != nil || a == nil {
			t.Errorf("%s: New() = %v, %v; want success", name, a, err)
		}
	}

	invalid := map[string]agent.Options{
		"empty url":          mutate(func(o *agent.Options) { o.ServerURL = "" }),
		"url without scheme": mutate(func(o *agent.Options) { o.ServerURL = "tunnel.example.com" }),
		"ftp url":            mutate(func(o *agent.Options) { o.ServerURL = "ftp://tunnel.example.com" }),
		"url without host":   mutate(func(o *agent.Options) { o.ServerURL = "https://" }),
		"garbage url":        mutate(func(o *agent.Options) { o.ServerURL = "://bad" }),
		"missing token":      mutate(func(o *agent.Options) { o.Token = "" }),
		"no tunnels":         mutate(func(o *agent.Options) { o.Tunnels = nil }),
		"unsupported proto":  mutate(func(o *agent.Options) { o.Tunnels[0].Proto = "udp" }),
		"empty proto":        mutate(func(o *agent.Options) { o.Tunnels[0].Proto = "" }),
		"port only":          mutate(func(o *agent.Options) { o.Tunnels[0].LocalAddr = "3000" }),
		"host only":          mutate(func(o *agent.Options) { o.Tunnels[0].LocalAddr = "localhost" }),
		"empty local addr":   mutate(func(o *agent.Options) { o.Tunnels[0].LocalAddr = "" }),
		"one bad of many": mutate(func(o *agent.Options) {
			o.Tunnels = []agent.TunnelSpec{httpTunnel(), {Proto: protocol.ProtoTCP, LocalAddr: "nope"}}
		}),
	}
	for name, o := range invalid {
		if a, err := agent.New(o); err == nil || a != nil {
			t.Errorf("%s: New() = %v, %v; want an error", name, a, err)
		}
	}
}

func TestRegistrationError(t *testing.T) {
	err := &agent.RegistrationError{
		Spec: agent.TunnelSpec{Proto: protocol.ProtoHTTP, LocalAddr: "localhost:3000"},
		Err:  &protocol.Error{Code: protocol.CodeHostnameTaken, Message: "that name is taken"},
	}
	want := "tunnel http -> localhost:3000 rejected: that name is taken"
	if err.Error() != want {
		t.Errorf("Error() = %q, want %q", err.Error(), want)
	}
	var target *agent.RegistrationError
	if !errors.As(error(err), &target) || target.Err.Code != protocol.CodeHostnameTaken {
		t.Error("errors.As should recover the registration error")
	}
}

func TestStatesAndSentinels(t *testing.T) {
	if agent.StateConnecting != "connecting" || agent.StateOnline != "online" || agent.StateReconnecting != "reconnecting" {
		t.Errorf("state values changed: %q %q %q", agent.StateConnecting, agent.StateOnline, agent.StateReconnecting)
	}
	if agent.ErrUnauthorized == nil || !strings.Contains(agent.ErrUnauthorized.Error(), "token") {
		t.Errorf("ErrUnauthorized = %v", agent.ErrUnauthorized)
	}
}

// ---- Run() against fake gateways ------------------------------------------

type statusLog struct {
	mu      sync.Mutex
	entries []agent.Status
}

func (l *statusLog) add(s agent.Status) {
	l.mu.Lock()
	l.entries = append(l.entries, s)
	l.mu.Unlock()
}

func (l *statusLog) snapshot() []agent.Status {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]agent.Status(nil), l.entries...)
}

func start(t *testing.T, o agent.Options) (cancel context.CancelFunc, errc <-chan error) {
	t.Helper()
	a, err := agent.New(o)
	if err != nil {
		t.Fatal(err)
	}
	ctx, c := context.WithCancel(context.Background())
	ch := make(chan error, 1)
	go func() { ch <- a.Run(ctx) }()
	t.Cleanup(c)
	return c, ch
}

func waitErr(t *testing.T, errc <-chan error) error {
	t.Helper()
	select {
	case err := <-errc:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return in time")
		return nil
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// countingServer answers every connect attempt with status and counts them.
func countingServer(t *testing.T, status int) (*httptest.Server, func() int) {
	t.Helper()
	var mu sync.Mutex
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		http.Error(w, http.StatusText(status), status)
	}))
	t.Cleanup(srv.Close)
	return srv, func() int { mu.Lock(); defer mu.Unlock(); return hits }
}

func TestRun_UnauthorizedIsFatalAndNotRetried(t *testing.T) {
	srv, hits := countingServer(t, http.StatusUnauthorized)
	_, errc := start(t, baseOpts(srv.URL))
	if err := waitErr(t, errc); !errors.Is(err, agent.ErrUnauthorized) {
		t.Fatalf("Run = %v, want ErrUnauthorized", err)
	}
	if n := hits(); n != 1 {
		t.Errorf("gateway saw %d attempts, want exactly 1 (a bad token must not be retried)", n)
	}
}

func TestRun_ClientErrorsAreFatal(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusUpgradeRequired, http.StatusForbidden} {
		srv, hits := countingServer(t, status)
		_, errc := start(t, baseOpts(srv.URL))
		err := waitErr(t, errc)
		if err == nil || errors.Is(err, agent.ErrUnauthorized) {
			t.Errorf("status %d: Run = %v, want a non-nil, non-auth error", status, err)
			continue
		}
		if !strings.Contains(err.Error(), http.StatusText(status)) && !strings.Contains(err.Error(), "server answered") {
			t.Errorf("status %d: error does not describe the server answer: %v", status, err)
		}
		if n := hits(); n != 1 {
			t.Errorf("status %d: %d attempts, want 1", status, n)
		}
	}
}

func TestRun_ServerErrorsAreRetriedUntilCancelled(t *testing.T) {
	srv, hits := countingServer(t, http.StatusInternalServerError)
	var log statusLog
	o := baseOpts(srv.URL)
	o.OnStatus = log.add
	cancel, errc := start(t, o)

	waitFor(t, "three connection attempts", func() bool { return hits() >= 3 })
	cancel()
	if err := waitErr(t, errc); err != nil {
		t.Fatalf("Run after cancel = %v, want nil", err)
	}

	entries := log.snapshot()
	if len(entries) == 0 || entries[0].State != agent.StateConnecting || entries[0].Err != nil {
		t.Fatalf("first status = %+v, want a clean connecting state", entries)
	}
	var sawReconnect bool
	for _, e := range entries {
		if e.State == agent.StateOnline {
			t.Errorf("agent reported online although the gateway never upgraded: %+v", e)
		}
		if e.State == agent.StateReconnecting && e.Err != nil && strings.Contains(e.Err.Error(), "500") {
			sawReconnect = true
		}
	}
	if !sawReconnect {
		t.Errorf("no reconnecting status carrying the 500 error: %+v", entries)
	}
}

func TestRun_TooManyRequestsIsRetriedNotFatal(t *testing.T) {
	srv, hits := countingServer(t, http.StatusTooManyRequests)
	cancel, errc := start(t, baseOpts(srv.URL))
	waitFor(t, "a retry after 429", func() bool { return hits() >= 2 })
	cancel()
	if err := waitErr(t, errc); err != nil {
		t.Errorf("Run = %v, want nil", err)
	}
}

func TestRun_CancelBeforeStartReturnsNil(t *testing.T) {
	srv, _ := countingServer(t, http.StatusInternalServerError)
	a, err := agent.New(baseOpts(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	if err := waitErr(t, done); err != nil {
		t.Errorf("Run = %v, want nil on a cancelled context", err)
	}
}

func TestRun_ConnectionRefusedIsRetried(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // nothing listens here any more

	var log statusLog
	o := baseOpts("http://" + addr)
	o.OnStatus = log.add
	cancel, errc := start(t, o)

	waitFor(t, "a reconnecting status", func() bool {
		for _, e := range log.snapshot() {
			if e.State == agent.StateReconnecting && e.Err != nil {
				return true
			}
		}
		return false
	})
	cancel()
	if err := waitErr(t, errc); err != nil {
		t.Errorf("Run = %v, want nil", err)
	}
}

func TestRun_SendsExpectedHandshake(t *testing.T) {
	var mu sync.Mutex
	var got *http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if got == nil {
			got = r.Clone(context.Background())
		}
		mu.Unlock()
		http.Error(w, "no", http.StatusUnauthorized)
	}))
	defer srv.Close()

	_, errc := start(t, baseOpts(srv.URL))
	waitErr(t, errc)

	mu.Lock()
	defer mu.Unlock()
	if got == nil {
		t.Fatal("gateway never received a request")
	}
	if got.Method != http.MethodGet || got.URL.Path != protocol.ConnectPath {
		t.Errorf("request line = %s %s", got.Method, got.URL.Path)
	}
	if got.Header.Get("Authorization") != "Bearer "+testToken {
		t.Errorf("Authorization = %q", got.Header.Get("Authorization"))
	}
	if !strings.EqualFold(got.Header.Get("Connection"), "Upgrade") || got.Header.Get("Upgrade") != protocol.UpgradeToken {
		t.Errorf("upgrade headers = %q / %q", got.Header.Get("Connection"), got.Header.Get("Upgrade"))
	}
	if !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(got.Header.Get(protocol.HeaderInstance)) {
		t.Errorf("%s = %q, want 16 hex characters", protocol.HeaderInstance, got.Header.Get(protocol.HeaderInstance))
	}
	if !strings.HasPrefix(got.Header.Get("User-Agent"), "mancar-agent/") {
		t.Errorf("User-Agent = %q", got.Header.Get("User-Agent"))
	}
	if got.Header.Get(protocol.HeaderAgentVersion) == "" {
		t.Errorf("%s is empty", protocol.HeaderAgentVersion)
	}
}

func TestRun_InstanceIDIsStableAcrossReconnects(t *testing.T) {
	var mu sync.Mutex
	var instances []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		instances = append(instances, r.Header.Get(protocol.HeaderInstance))
		mu.Unlock()
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	cancel, errc := start(t, baseOpts(srv.URL))
	waitFor(t, "three attempts", func() bool { mu.Lock(); defer mu.Unlock(); return len(instances) >= 3 })
	cancel()
	waitErr(t, errc)

	mu.Lock()
	defer mu.Unlock()
	for _, id := range instances {
		if id == "" || id != instances[0] {
			t.Fatalf("instance IDs differ across reconnects: %v", instances)
		}
	}
}

func TestRun_DifferentAgentsGetDifferentInstanceIDs(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.Header.Get(protocol.HeaderInstance)] = true
		mu.Unlock()
		http.Error(w, "no", http.StatusUnauthorized)
	}))
	defer srv.Close()

	for i := 0; i < 5; i++ {
		_, errc := start(t, baseOpts(srv.URL))
		waitErr(t, errc)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 5 {
		t.Errorf("got %d distinct instance IDs for 5 agents", len(seen))
	}
}

func TestRun_DialAddrOverridesWhereButNotWhatWeSay(t *testing.T) {
	var mu sync.Mutex
	var host string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		host = r.Host
		mu.Unlock()
		http.Error(w, "no", http.StatusUnauthorized)
	}))
	defer srv.Close()

	o := baseOpts("http://tunnel.invalid")
	o.DialAddr = srv.Listener.Addr().String()
	_, errc := start(t, o)
	if err := waitErr(t, errc); !errors.Is(err, agent.ErrUnauthorized) {
		t.Fatalf("Run = %v, want ErrUnauthorized (proves the override address was dialed)", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if host != "tunnel.invalid" {
		t.Errorf("Host header = %q, want tunnel.invalid", host)
	}
}

func TestRun_ForeignUpgradeAnswerIsFatal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"))
	}))
	defer srv.Close()

	_, errc := start(t, baseOpts(srv.URL))
	err := waitErr(t, errc)
	if err == nil || !strings.Contains(err.Error(), "does not speak the mancar protocol") {
		t.Errorf("Run = %v, want a protocol mismatch error", err)
	}
}
