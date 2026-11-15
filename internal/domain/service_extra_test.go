package domain_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/USERNAME/mancar/internal/domain"
)

var _ domain.Registry = (*domain.MemoryRegistry)(nil)

// fakeClock lets tests move time without sleeping.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock { return &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newSvc(opts domain.ServiceOptions) (*domain.Service, *domain.MemoryRegistry, *fakeClock) {
	clk := newClock()
	reg := domain.NewMemoryRegistry()
	reg.Now = clk.Now
	if opts.BaseDomain == "" {
		opts.BaseDomain = "example.com"
	}
	return domain.NewService(reg, opts), reg, clk
}

func TestNormalizeLabel(t *testing.T) {
	for in, want := range map[string]string{
		"  My-API \t": "my-api",
		"":            "",
		"ABC":         "abc",
		"already-ok":  "already-ok",
	} {
		if got := domain.NormalizeLabel(in); got != want {
			t.Errorf("NormalizeLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidateLabel_MoreCases(t *testing.T) {
	good := []string{"abc", "123", "a-b", "9lives", "blue-falcon", "x1y2z3"}
	for _, l := range good {
		if err := domain.ValidateLabel(l); err != nil {
			t.Errorf("ValidateLabel(%q) = %v, want nil", l, err)
		}
	}
	bad := []string{
		"abc\n", "abc\r\n", " abc", "abc ", "a\x00b", "ab/cd", "ab:80", "a@b", "a.b.c",
		"tunnel", "gateway", "metrics", "status", "postmaster", "localhost", "ns1", "login", "oauth",
	}
	for _, l := range bad {
		if err := domain.ValidateLabel(l); !errors.Is(err, domain.ErrInvalidLabel) {
			t.Errorf("ValidateLabel(%q) = %v, want ErrInvalidLabel", l, err)
		}
	}
}

func TestService_CustomNameStaysHeldForOwner(t *testing.T) {
	svc, _, clk := newSvc(domain.ServiceOptions{}) // default holds: 24h custom, 5m random
	ctx := context.Background()

	lease, err := svc.Acquire(ctx, "alice", "my-api", "t1")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Release(ctx, lease, "t1"); err != nil {
		t.Fatal(err)
	}

	// The owner can come straight back (agent reconnect) and keeps the kind.
	again, err := svc.Acquire(ctx, "alice", "my-api", "t2")
	if err != nil || again.Kind != domain.KindCustom || again.Hostname != "my-api.example.com" {
		t.Fatalf("owner re-acquire: %+v %v", again, err)
	}
	if err := svc.Release(ctx, again, "t2"); err != nil {
		t.Fatal(err)
	}

	// Somebody else has to wait out the 24h hold.
	if _, err := svc.Acquire(ctx, "bob", "my-api", "t3"); !errors.Is(err, domain.ErrHostnameTaken) {
		t.Fatalf("bob during hold: %v", err)
	}
	clk.Advance(23 * time.Hour)
	if _, err := svc.Acquire(ctx, "bob", "my-api", "t3"); !errors.Is(err, domain.ErrHostnameTaken) {
		t.Fatalf("bob at 23h: %v", err)
	}
	clk.Advance(2 * time.Hour)
	got, err := svc.Acquire(ctx, "bob", "my-api", "t3")
	if err != nil || got.Hostname != "my-api.example.com" {
		t.Fatalf("bob after hold expiry: %+v %v", got, err)
	}
	// ...and now alice is the one locked out.
	if _, err := svc.Acquire(ctx, "alice", "my-api", "t4"); !errors.Is(err, domain.ErrHostnameTaken) {
		t.Fatalf("alice after bob took it: %v", err)
	}
}

func TestService_RandomNameHoldIsShort(t *testing.T) {
	svc, _, clk := newSvc(domain.ServiceOptions{Generate: func() string { return "quick-otter" }})
	ctx := context.Background()

	lease, err := svc.Acquire(ctx, "alice", "", "t1")
	if err != nil || lease.Kind != domain.KindRandom || lease.Hostname != "quick-otter.example.com" {
		t.Fatalf("random lease: %+v %v", lease, err)
	}
	if err := svc.Release(ctx, lease, "t1"); err != nil {
		t.Fatal(err)
	}

	clk.Advance(4 * time.Minute)
	if _, err := svc.Acquire(ctx, "bob", "quick-otter", "t2"); !errors.Is(err, domain.ErrHostnameTaken) {
		t.Fatalf("bob at 4m: %v", err)
	}
	clk.Advance(2 * time.Minute)
	got, err := svc.Acquire(ctx, "bob", "quick-otter", "t2")
	if err != nil || got.Kind != domain.KindCustom {
		t.Fatalf("bob after 6m: %+v %v", got, err)
	}
}

func TestService_RandomNameKeepsKindWhenOwnerReclaimsExplicitly(t *testing.T) {
	// Re-claiming a random name by label must not turn it into a 24h
	// custom reservation.
	svc, _, _ := newSvc(domain.ServiceOptions{Generate: func() string { return "quick-otter" }})
	ctx := context.Background()
	lease, _ := svc.Acquire(ctx, "alice", "", "t1")
	if err := svc.Release(ctx, lease, "t1"); err != nil {
		t.Fatal(err)
	}
	again, err := svc.Acquire(ctx, "alice", "quick-otter", "t2")
	if err != nil {
		t.Fatal(err)
	}
	if again.Kind != domain.KindRandom {
		t.Errorf("Kind = %q, want %q", again.Kind, domain.KindRandom)
	}
}

func TestService_CustomHoldsFromOptionsAreUsed(t *testing.T) {
	svc, _, clk := newSvc(domain.ServiceOptions{HoldCustom: time.Hour, HoldRandom: time.Minute})
	ctx := context.Background()
	lease, _ := svc.Acquire(ctx, "alice", "my-api", "t1")
	svc.Release(ctx, lease, "t1")

	clk.Advance(59 * time.Minute)
	if _, err := svc.Acquire(ctx, "bob", "my-api", "t2"); !errors.Is(err, domain.ErrHostnameTaken) {
		t.Fatalf("at 59m: %v", err)
	}
	clk.Advance(2 * time.Minute)
	if _, err := svc.Acquire(ctx, "bob", "my-api", "t2"); err != nil {
		t.Fatalf("at 61m: %v", err)
	}
}

func TestService_ActiveNameCannotBeTakenByAnyone(t *testing.T) {
	svc, _, _ := newSvc(domain.ServiceOptions{})
	ctx := context.Background()
	lease, err := svc.Acquire(ctx, "alice", "my-api", "t1")
	if err != nil {
		t.Fatal(err)
	}

	// Same owner, different tunnel: still active, so refused.
	if _, err := svc.Acquire(ctx, "alice", "my-api", "t2"); !errors.Is(err, domain.ErrHostnameTaken) {
		t.Fatalf("same owner, second tunnel: %v", err)
	}

	// Releasing with a tunnel ID that does not own the name changes nothing.
	if err := svc.Release(ctx, lease, "t-other"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Acquire(ctx, "bob", "my-api", "t3"); !errors.Is(err, domain.ErrHostnameTaken) {
		t.Fatalf("name freed by a foreign release: %v", err)
	}
	if _, err := svc.Acquire(ctx, "alice", "my-api", "t2"); !errors.Is(err, domain.ErrHostnameTaken) {
		t.Fatalf("name freed by a foreign release (owner): %v", err)
	}
}

func TestService_ResetAndPurge(t *testing.T) {
	svc, reg, clk := newSvc(domain.ServiceOptions{})
	ctx := context.Background()
	if _, err := svc.Acquire(ctx, "alice", "my-api", "t1"); err != nil {
		t.Fatal(err)
	}

	// Simulated crash + restart: nothing can be connected any more.
	if err := svc.Reset(ctx); err != nil {
		t.Fatal(err)
	}
	if reg.Len() != 1 {
		t.Fatalf("Len = %d; Reset must keep held reservations", reg.Len())
	}
	if _, err := svc.Acquire(ctx, "bob", "my-api", "t2"); !errors.Is(err, domain.ErrHostnameTaken) {
		t.Fatalf("bob right after reset: %v", err)
	}

	clk.Advance(6 * time.Minute) // Reset holds with the (short) random duration
	if err := svc.Purge(ctx); err != nil {
		t.Fatal(err)
	}
	if reg.Len() != 0 {
		t.Fatalf("Len = %d after purge, want 0", reg.Len())
	}
	if _, err := svc.Acquire(ctx, "bob", "my-api", "t2"); err != nil {
		t.Fatalf("bob after purge: %v", err)
	}
}

func TestService_ConcurrentAcquireExactlyOneWinner(t *testing.T) {
	svc, _, _ := newSvc(domain.ServiceOptions{})
	ctx := context.Background()
	const n = 100

	var wins, taken int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			owner := "user-" + strings.Repeat("x", i%7) + string(rune('a'+i%26))
			_, err := svc.Acquire(ctx, owner, "contested", "tunnel-"+string(rune('A'+i%26))+string(rune('a'+i/26)))
			switch {
			case err == nil:
				atomic.AddInt32(&wins, 1)
			case errors.Is(err, domain.ErrHostnameTaken):
				atomic.AddInt32(&taken, 1)
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	if wins != 1 || wins+taken != n {
		t.Errorf("wins=%d taken=%d (want exactly one winner out of %d)", wins, taken, n)
	}
}

func TestService_ConcurrentRandomNamesAreUnique(t *testing.T) {
	svc, _, _ := newSvc(domain.ServiceOptions{})
	ctx := context.Background()
	const n = 200
	var mu sync.Mutex
	seen := map[string]int{}
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			l, err := svc.Acquire(ctx, "alice", "", "t"+string(rune('A'+i%26))+string(rune('a'+i/26)))
			if err != nil {
				t.Errorf("acquire: %v", err)
				return
			}
			mu.Lock()
			seen[l.Hostname]++
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	for host, c := range seen {
		if c != 1 {
			t.Errorf("hostname %s handed out %d times", host, c)
		}
	}
}

// stubRegistry records calls and returns canned errors.
type stubRegistry struct {
	claimErr, releaseErr, releaseAllErr, purgeErr error
	claims, purges                                atomic.Int32
}

func (r *stubRegistry) Claim(context.Context, domain.Claim) (string, error) {
	r.claims.Add(1)
	if r.claimErr != nil {
		return "", r.claimErr
	}
	return domain.KindCustom, nil
}
func (r *stubRegistry) Release(context.Context, string, string, time.Duration) error {
	return r.releaseErr
}
func (r *stubRegistry) ReleaseAll(context.Context, time.Duration) error { return r.releaseAllErr }
func (r *stubRegistry) Purge(context.Context) error                     { r.purges.Add(1); return r.purgeErr }

func TestService_RegistryErrorsPropagate(t *testing.T) {
	boom := errors.New("db down")
	ctx := context.Background()

	t.Run("custom claim", func(t *testing.T) {
		reg := &stubRegistry{claimErr: boom}
		svc := domain.NewService(reg, domain.ServiceOptions{BaseDomain: "example.com"})
		if _, err := svc.Acquire(ctx, "alice", "my-api", "t1"); !errors.Is(err, boom) {
			t.Errorf("err = %v, want the registry error", err)
		}
		if reg.claims.Load() != 1 {
			t.Errorf("claims = %d", reg.claims.Load())
		}
	})
	t.Run("random claim does not retry on infrastructure errors", func(t *testing.T) {
		reg := &stubRegistry{claimErr: boom}
		svc := domain.NewService(reg, domain.ServiceOptions{BaseDomain: "example.com"})
		_, err := svc.Acquire(ctx, "alice", "", "t1")
		if !errors.Is(err, boom) || errors.Is(err, domain.ErrExhausted) {
			t.Errorf("err = %v", err)
		}
		if reg.claims.Load() != 1 {
			t.Errorf("claims = %d, want 1", reg.claims.Load())
		}
	})
	t.Run("release", func(t *testing.T) {
		svc := domain.NewService(&stubRegistry{releaseErr: boom}, domain.ServiceOptions{BaseDomain: "example.com"})
		if err := svc.Release(ctx, domain.Lease{Hostname: "a.example.com", Kind: domain.KindCustom}, "t1"); !errors.Is(err, boom) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("reset stops before purge when release-all fails", func(t *testing.T) {
		reg := &stubRegistry{releaseAllErr: boom}
		svc := domain.NewService(reg, domain.ServiceOptions{BaseDomain: "example.com"})
		if err := svc.Reset(ctx); !errors.Is(err, boom) {
			t.Errorf("err = %v", err)
		}
		if reg.purges.Load() != 0 {
			t.Error("Purge ran even though ReleaseAll failed")
		}
	})
	t.Run("purge", func(t *testing.T) {
		svc := domain.NewService(&stubRegistry{purgeErr: boom}, domain.ServiceOptions{BaseDomain: "example.com"})
		if err := svc.Purge(ctx); !errors.Is(err, boom) {
			t.Errorf("err = %v", err)
		}
	})
}

func TestService_InvalidLabelNeverReachesRegistry(t *testing.T) {
	reg := &stubRegistry{}
	svc := domain.NewService(reg, domain.ServiceOptions{BaseDomain: "example.com"})
	for _, l := range []string{"ab", "admin", "bad_label", "a--b", strings.Repeat("a", 64)} {
		if _, err := svc.Acquire(context.Background(), "alice", l, "t1"); !errors.Is(err, domain.ErrInvalidLabel) {
			t.Errorf("Acquire(%q) err = %v, want ErrInvalidLabel", l, err)
		}
	}
	if reg.claims.Load() != 0 {
		t.Errorf("registry saw %d claims for invalid labels", reg.claims.Load())
	}
}

func TestService_RandomGivesUpAfterBoundedAttempts(t *testing.T) {
	t.Run("always taken", func(t *testing.T) {
		reg := &stubRegistry{claimErr: domain.ErrHostnameTaken}
		svc := domain.NewService(reg, domain.ServiceOptions{BaseDomain: "example.com"})
		if _, err := svc.Acquire(context.Background(), "alice", "", "t1"); !errors.Is(err, domain.ErrExhausted) {
			t.Fatalf("err = %v, want ErrExhausted", err)
		}
		if got := reg.claims.Load(); got != 20 {
			t.Errorf("claims = %d, want 20 bounded attempts", got)
		}
	})
	t.Run("generator only produces invalid labels", func(t *testing.T) {
		reg := &stubRegistry{}
		svc := domain.NewService(reg, domain.ServiceOptions{BaseDomain: "example.com", Generate: func() string { return "" }})
		if _, err := svc.Acquire(context.Background(), "alice", "", "t1"); !errors.Is(err, domain.ErrExhausted) {
			t.Fatalf("err = %v, want ErrExhausted", err)
		}
		if reg.claims.Load() != 0 {
			t.Errorf("invalid candidates reached the registry: %d claims", reg.claims.Load())
		}
	})
}

func TestMemoryRegistry_KindIsKeptOnlyWhileHeld(t *testing.T) {
	clk := newClock()
	reg := domain.NewMemoryRegistry()
	reg.Now = clk.Now
	ctx := context.Background()
	const host = "kind.example.com"

	if k, err := reg.Claim(ctx, domain.Claim{Hostname: host, OwnerID: "alice", Kind: domain.KindRandom, TunnelID: "t1"}); err != nil || k != domain.KindRandom {
		t.Fatalf("first claim: %q %v", k, err)
	}
	if err := reg.Release(ctx, host, "t1", time.Hour); err != nil {
		t.Fatal(err)
	}
	if k, err := reg.Claim(ctx, domain.Claim{Hostname: host, OwnerID: "alice", Kind: domain.KindCustom, TunnelID: "t2"}); err != nil || k != domain.KindRandom {
		t.Fatalf("re-claim inside hold: kind=%q err=%v, want original kind", k, err)
	}
	if err := reg.Release(ctx, host, "t2", time.Hour); err != nil {
		t.Fatal(err)
	}
	clk.Advance(2 * time.Hour)
	if k, err := reg.Claim(ctx, domain.Claim{Hostname: host, OwnerID: "alice", Kind: domain.KindCustom, TunnelID: "t3"}); err != nil || k != domain.KindCustom {
		t.Fatalf("re-claim after hold: kind=%q err=%v, want the requested kind", k, err)
	}
}

func TestMemoryRegistry_HoldExpiresExactlyAtDeadline(t *testing.T) {
	clk := newClock()
	reg := domain.NewMemoryRegistry()
	reg.Now = clk.Now
	ctx := context.Background()
	const host = "edge.example.com"

	reg.Claim(ctx, domain.Claim{Hostname: host, OwnerID: "alice", Kind: domain.KindCustom, TunnelID: "t1"})
	reg.Release(ctx, host, "t1", time.Minute)

	clk.Advance(time.Minute - time.Nanosecond)
	if _, err := reg.Claim(ctx, domain.Claim{Hostname: host, OwnerID: "bob", Kind: domain.KindCustom, TunnelID: "t2"}); !errors.Is(err, domain.ErrHostnameTaken) {
		t.Fatalf("1ns before deadline: %v", err)
	}
	clk.Advance(time.Nanosecond)
	if _, err := reg.Claim(ctx, domain.Claim{Hostname: host, OwnerID: "bob", Kind: domain.KindCustom, TunnelID: "t2"}); err != nil {
		t.Fatalf("at the deadline: %v", err)
	}
}

func TestMemoryRegistry_ReleaseAllAndPurge(t *testing.T) {
	clk := newClock()
	reg := domain.NewMemoryRegistry()
	reg.Now = clk.Now
	ctx := context.Background()

	reg.Claim(ctx, domain.Claim{Hostname: "a.example.com", OwnerID: "alice", Kind: domain.KindCustom, TunnelID: "t1"})
	reg.Claim(ctx, domain.Claim{Hostname: "b.example.com", OwnerID: "bob", Kind: domain.KindCustom, TunnelID: "t2"})

	// Purge never touches active reservations.
	reg.Purge(ctx)
	if reg.Len() != 2 {
		t.Fatalf("Len = %d, active entries must survive Purge", reg.Len())
	}

	reg.ReleaseAll(ctx, time.Hour)
	reg.Purge(ctx)
	if reg.Len() != 2 {
		t.Fatalf("Len = %d, entries inside their hold must survive Purge", reg.Len())
	}
	// Previously active names are now inactive: other owners are still blocked, owners are not.
	if _, err := reg.Claim(ctx, domain.Claim{Hostname: "a.example.com", OwnerID: "bob", Kind: domain.KindCustom, TunnelID: "t3"}); !errors.Is(err, domain.ErrHostnameTaken) {
		t.Fatalf("foreign claim during hold: %v", err)
	}
	if _, err := reg.Claim(ctx, domain.Claim{Hostname: "a.example.com", OwnerID: "alice", Kind: domain.KindCustom, TunnelID: "t3"}); err != nil {
		t.Fatalf("owner claim during hold: %v", err)
	}

	clk.Advance(2 * time.Hour)
	reg.Purge(ctx)
	if reg.Len() != 1 { // a.example.com is active again, b.example.com expired
		t.Fatalf("Len = %d, want 1", reg.Len())
	}
}

func TestMemoryRegistry_ReleaseOfUnknownHostIsHarmless(t *testing.T) {
	reg := domain.NewMemoryRegistry()
	if err := reg.Release(context.Background(), "nope.example.com", "t1", time.Hour); err != nil {
		t.Errorf("err = %v", err)
	}
	if reg.Len() != 0 {
		t.Errorf("Len = %d", reg.Len())
	}
}
