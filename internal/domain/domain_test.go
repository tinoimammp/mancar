package domain_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	. "github.com/tinoimammp/mancar/internal/domain"
	"github.com/tinoimammp/mancar/internal/domain/domaintest"
)

func TestValidateLabel(t *testing.T) {
	good := []string{"my-api", "abc", "a1b2c3", "blue-falcon-0042", strings.Repeat("a", 63)}
	bad := []string{"", "ab", "-abc", "abc-", "my_api", "My-Api", "a.b", "xn--80ak6aa92e", "a--b",
		"www", "admin", "api", strings.Repeat("a", 64), "caf\u00e9", "a b"}
	for _, l := range good {
		if err := ValidateLabel(l); err != nil {
			t.Errorf("ValidateLabel(%q) = %v, want nil", l, err)
		}
	}
	for _, l := range bad {
		if err := ValidateLabel(l); !errors.Is(err, ErrInvalidLabel) {
			t.Errorf("ValidateLabel(%q) = %v, want ErrInvalidLabel", l, err)
		}
	}
}

func TestRandomLabelsAreValid(t *testing.T) {
	for i := 0; i < 500; i++ {
		if l := RandomLabel(); ValidateLabel(l) != nil {
			t.Fatalf("generated invalid label %q", l)
		}
	}
}

func TestMemoryRegistryContract(t *testing.T) {
	reg := NewMemoryRegistry()
	var mu sync.Mutex
	offset := time.Duration(0)
	reg.Now = func() time.Time { mu.Lock(); defer mu.Unlock(); return time.Now().Add(offset) }
	domaintest.RunRegistryContract(t, reg, func(d time.Duration) { mu.Lock(); offset += d; mu.Unlock() })
}

func TestServiceRandomAndCustom(t *testing.T) {
	svc := NewService(NewMemoryRegistry(), ServiceOptions{BaseDomain: "Example.COM"})
	ctx := context.Background()

	l, err := svc.Acquire(ctx, "alice", "", "t1")
	if err != nil {
		t.Fatal(err)
	}
	if l.Kind != KindRandom || !strings.HasSuffix(l.Hostname, ".example.com") {
		t.Fatalf("unexpected lease %+v", l)
	}

	c, err := svc.Acquire(ctx, "alice", "  My-API ", "t2")
	if err != nil || c.Hostname != "my-api.example.com" || c.Kind != KindCustom {
		t.Fatalf("custom lease %+v err=%v", c, err)
	}
	if _, err := svc.Acquire(ctx, "bob", "my-api", "t3"); !errors.Is(err, ErrHostnameTaken) {
		t.Fatalf("duplicate custom hostname accepted: %v", err)
	}
	if _, err := svc.Acquire(ctx, "bob", "admin", "t4"); !errors.Is(err, ErrInvalidLabel) {
		t.Fatalf("reserved label accepted: %v", err)
	}
}

func TestServiceRandomRetriesOnCollision(t *testing.T) {
	// A generator that always returns the same label forces the suffix path.
	svc := NewService(NewMemoryRegistry(), ServiceOptions{BaseDomain: "example.com", Generate: func() string { return "blue-falcon" }})
	ctx := context.Background()
	seen := map[string]bool{}
	for i := 0; i < 5; i++ {
		l, err := svc.Acquire(ctx, "alice", "", "t"+string(rune('a'+i)))
		if err != nil {
			t.Fatalf("acquire %d: %v", i, err)
		}
		if seen[l.Hostname] {
			t.Fatalf("hostname %s handed out twice", l.Hostname)
		}
		seen[l.Hostname] = true
	}
}

// slowRegistry writes the claim but answers as if the database timed out.
type slowRegistry struct{ *MemoryRegistry }

func (r slowRegistry) Claim(ctx context.Context, c Claim) (string, error) {
	r.MemoryRegistry.Claim(ctx, c)
	return "", context.DeadlineExceeded
}

func TestTimedOutClaimDoesNotStickTheName(t *testing.T) {
	reg := NewMemoryRegistry()
	svc := NewService(slowRegistry{reg}, ServiceOptions{BaseDomain: "example.com"})
	if _, err := svc.Acquire(context.Background(), "u1", "shop", "t1"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Acquire: %v", err)
	}
	// the owner can have the name again once the background release ran
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, err := reg.Claim(context.Background(), Claim{Hostname: "shop.example.com", OwnerID: "u1", Kind: KindCustom, TunnelID: "t2"})
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the name stayed active: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
