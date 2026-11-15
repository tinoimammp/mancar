package gateway_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tinoimammp/mancar/internal/agent"
	"github.com/tinoimammp/mancar/internal/auth"
	"github.com/tinoimammp/mancar/internal/domain"
	"github.com/tinoimammp/mancar/internal/gateway"
	"github.com/tinoimammp/mancar/internal/protocol"
)

// countingAuth wraps an Authenticator and counts lookups: the point of the
// failure limiter is that blocked clients cost no lookups at all.
type countingAuth struct {
	inner auth.Authenticator
	calls atomic.Int32
}

func (c *countingAuth) AuthenticateAgent(ctx context.Context, tok string) (auth.Principal, error) {
	c.calls.Add(1)
	return c.inner.AuthenticateAgent(ctx, tok)
}

func hubWith(a auth.Authenticator, opts gateway.Options) *gateway.Hub {
	svc := domain.NewService(domain.NewMemoryRegistry(), domain.ServiceOptions{BaseDomain: "example.com"})
	return gateway.NewHub(a, svc, opts)
}

func unknownToken(n int) string {
	return auth.TokenPrefix + strings.Repeat(strconv.Itoa(n%10), 64)
}

func fromAddr(token, remote string, xff ...string) *http.Request {
	r := upgradeReq(token)
	r.RemoteAddr = remote
	for _, v := range xff {
		r.Header.Add("X-Forwarded-For", v)
	}
	return r
}

func TestHub_FailedAuthenticationsAreRateLimitedPerClient(t *testing.T) {
	mem := auth.NewMemory()
	valid, _ := mem.Issue("alice")
	ca := &countingAuth{inner: mem}
	hub := hubWith(ca, gateway.Options{AuthFailureLimit: 3})
	const attacker = "198.51.100.7:4000"

	for i := 0; i < 3; i++ {
		if rec := serve(hub, fromAddr(unknownToken(i), attacker)); rec.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d: status %d, want 401", i+1, rec.Code)
		}
	}
	if got := ca.calls.Load(); got != 3 {
		t.Fatalf("lookups = %d, want 3", got)
	}

	rec := serve(hub, fromAddr(unknownToken(9), attacker))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("4th failure: status %d, want 429", rec.Code)
	}
	secs, err := strconv.Atoi(rec.Header().Get("Retry-After"))
	if err != nil || secs < 1 || secs > 61 {
		t.Errorf("Retry-After = %q", rec.Header().Get("Retry-After"))
	}

	// Blocked means no work: not even a valid token reaches the backend.
	if rec := serve(hub, fromAddr(valid, attacker)); rec.Code != http.StatusTooManyRequests {
		t.Errorf("valid token from a blocked address: status %d, want 429", rec.Code)
	}
	if got := ca.calls.Load(); got != 3 {
		t.Errorf("lookups = %d while blocked, want still 3", got)
	}

	// Other clients are unaffected.
	if rec := serve(hub, fromAddr(unknownToken(1), "203.0.113.50:1")); rec.Code != http.StatusUnauthorized {
		t.Errorf("another client: status %d, want 401", rec.Code)
	}
}

func TestHub_MalformedAndMissingTokensCountAsFailures(t *testing.T) {
	hub := hubWith(auth.NewMemory(), gateway.Options{AuthFailureLimit: 3})
	for i := 0; i < 3; i++ {
		token := []string{"", "garbage", "mc_short"}[i]
		if rec := serve(hub, fromAddr(token, "198.51.100.7:1")); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i+1, rec.Code)
		}
	}
	if rec := serve(hub, fromAddr("", "198.51.100.7:1")); rec.Code != http.StatusTooManyRequests {
		t.Errorf("status %d, want 429", rec.Code)
	}
}

func TestHub_SpoofedForwardedForDoesNotEvadeTheLimit(t *testing.T) {
	// The peer is not a trusted proxy, so X-Forwarded-For is ignored and the
	// attacker cannot reset its budget by rotating the header.
	hub := hubWith(auth.NewMemory(), gateway.Options{AuthFailureLimit: 3})
	const peer = "198.51.100.7:4000"
	for i := 0; i < 3; i++ {
		serve(hub, fromAddr(unknownToken(i), peer, "10.9.9."+strconv.Itoa(i)))
	}
	if rec := serve(hub, fromAddr(unknownToken(7), peer, "10.1.2.3")); rec.Code != http.StatusTooManyRequests {
		t.Errorf("rotating X-Forwarded-For evaded the limit: status %d", rec.Code)
	}
}

func TestHub_LimitIsKeyedOnTheRealClientBehindATrustedProxy(t *testing.T) {
	proxy := netip.MustParsePrefix("192.0.2.0/24")
	hub := hubWith(auth.NewMemory(), gateway.Options{AuthFailureLimit: 2, TrustedProxies: []netip.Prefix{proxy}})
	const edge = "192.0.2.10:5555" // the TLS edge: every request arrives from here

	for i := 0; i < 2; i++ {
		serve(hub, fromAddr(unknownToken(i), edge, "198.51.100.7"))
	}
	if rec := serve(hub, fromAddr(unknownToken(5), edge, "198.51.100.7")); rec.Code != http.StatusTooManyRequests {
		t.Errorf("abusive client behind the proxy: status %d, want 429", rec.Code)
	}
	// A different real client behind the same proxy keeps its own budget:
	// one abuser must not lock everybody out.
	if rec := serve(hub, fromAddr(unknownToken(5), edge, "203.0.113.50")); rec.Code != http.StatusUnauthorized {
		t.Errorf("innocent client behind the proxy: status %d, want 401", rec.Code)
	}
	// Client-supplied prefix of the chain cannot masquerade as someone else.
	if rec := serve(hub, fromAddr(unknownToken(5), edge, "203.0.113.99", "198.51.100.7")); rec.Code != http.StatusTooManyRequests {
		t.Errorf("forged chain prefix: status %d, want 429 for the real client", rec.Code)
	}
}

func TestHub_BlockEndsWhenTheWindowEnds(t *testing.T) {
	hub := hubWith(auth.NewMemory(), gateway.Options{AuthFailureLimit: 1, AuthFailureWindow: 120 * time.Millisecond})
	const c = "198.51.100.7:1"
	if rec := serve(hub, fromAddr(unknownToken(1), c)); rec.Code != http.StatusUnauthorized {
		t.Fatal(rec.Code)
	}
	if rec := serve(hub, fromAddr(unknownToken(1), c)); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status %d, want 429", rec.Code)
	}
	time.Sleep(200 * time.Millisecond)
	if rec := serve(hub, fromAddr(unknownToken(1), c)); rec.Code != http.StatusUnauthorized {
		t.Errorf("after the window: status %d, want 401", rec.Code)
	}
}

func TestHub_DefaultAndDisabledLimits(t *testing.T) {
	t.Run("default is 10 per window", func(t *testing.T) {
		hub := hubWith(auth.NewMemory(), gateway.Options{})
		for i := 0; i < 10; i++ {
			if rec := serve(hub, fromAddr(unknownToken(i), "198.51.100.7:1")); rec.Code != http.StatusUnauthorized {
				t.Fatalf("failure %d: %d", i+1, rec.Code)
			}
		}
		if rec := serve(hub, fromAddr(unknownToken(1), "198.51.100.7:1")); rec.Code != http.StatusTooManyRequests {
			t.Errorf("11th failure: %d, want 429", rec.Code)
		}
	})
	t.Run("negative disables", func(t *testing.T) {
		hub := hubWith(auth.NewMemory(), gateway.Options{AuthFailureLimit: -1})
		for i := 0; i < 200; i++ {
			if rec := serve(hub, fromAddr(unknownToken(i), "198.51.100.7:1")); rec.Code != http.StatusUnauthorized {
				t.Fatalf("failure %d: %d", i+1, rec.Code)
			}
		}
	})
}

func TestHub_SuccessfulAgentsAreNotCountedAgainstTheBudget(t *testing.T) {
	// Legitimate reconnects (shutting-down hub answers 503 after a valid
	// login) must never consume the failure budget.
	mem := auth.NewMemory()
	valid, _ := mem.Issue("alice")
	hub := hubWith(mem, gateway.Options{AuthFailureLimit: 2})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	hub.Shutdown(ctx)
	for i := 0; i < 20; i++ {
		if rec := serve(hub, fromAddr(valid, "198.51.100.7:1")); rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("attempt %d: %d, want 503", i+1, rec.Code)
		}
	}
}

// ---- per-user session limit under concurrency ---------------------------------

func TestHub_SessionLimitHoldsUnderConcurrentConnects(t *testing.T) {
	mem := auth.NewMemory()
	alice, _ := mem.Issue("alice")
	bob, _ := mem.Issue("bob")
	hub := hubWith(mem, gateway.Options{MaxSessionsPerUser: 3, KeepAliveInterval: time.Second})
	srv := httptest.NewServer(hub)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	launch := func(token string) {
		a, err := agent.New(agent.Options{
			ServerURL: srv.URL, Token: token,
			Tunnels:    []agent.TunnelSpec{{Proto: protocol.ProtoHTTP, LocalAddr: "127.0.0.1:1"}},
			MinBackoff: 20 * time.Millisecond, MaxBackoff: 50 * time.Millisecond,
		})
		if err != nil {
			t.Error(err)
			return
		}
		wg.Add(1)
		go func() { defer wg.Done(); a.Run(ctx) }()
	}
	// 15 agents race for 3 slots of alice, plus one bob.
	start := make(chan struct{})
	for i := 0; i < 15; i++ {
		go func() { <-start; launch(alice) }()
	}
	close(start)
	launch(bob)

	deadline := time.Now().Add(2 * time.Second)
	reached := false
	for time.Now().Before(deadline) {
		n := hub.Stats().Sessions
		if n > 4 { // 3 for alice + 1 for bob
			t.Fatalf("sessions = %d, the per-user limit was exceeded", n)
		}
		if n == 4 {
			reached = true
		}
		time.Sleep(2 * time.Millisecond)
	}
	if !reached {
		t.Errorf("never reached 3+1 sessions (got %d)", hub.Stats().Sessions)
	}

	cancel()
	wg.Wait()
	sctx, scancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer scancel()
	hub.Shutdown(sctx)
}
