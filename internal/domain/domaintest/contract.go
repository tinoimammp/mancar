// Package domaintest holds the shared Registry contract test-suite.
package domaintest

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	. "github.com/tinoimammp/mancar/internal/domain"
)

// RunRegistryContract exercises the behaviour every Registry implementation
// must share. advance moves the registry's clock forward (for PostgreSQL it
// rewrites hold_until). It lives in a non-test file so the postgres package
// can reuse it.
func RunRegistryContract(t *testing.T, reg Registry, advance func(d time.Duration)) {
	ctx := context.Background()
	host := func(s string) string { return s + ".contract.test" }

	t.Run("duplicate active claim is rejected", func(t *testing.T) {
		if _, err := reg.Claim(ctx, cl(host("dup"), "alice", KindCustom, "t1")); err != nil {
			t.Fatal(err)
		}
		for _, owner := range []string{"alice", "bob"} {
			if _, err := reg.Claim(ctx, cl(host("dup"), owner, KindCustom, "t2")); !errors.Is(err, ErrHostnameTaken) {
				t.Fatalf("owner %s: want ErrHostnameTaken, got %v", owner, err)
			}
		}
	})

	t.Run("hold protects the owner then expires", func(t *testing.T) {
		h := host("held")
		if _, err := reg.Claim(ctx, cl(h, "alice", KindCustom, "t1")); err != nil {
			t.Fatal(err)
		}
		if err := reg.Release(ctx, h, "t1", time.Hour); err != nil {
			t.Fatal(err)
		}
		if _, err := reg.Claim(ctx, cl(h, "bob", KindCustom, "t2")); !errors.Is(err, ErrHostnameTaken) {
			t.Fatalf("bob claimed a held name: %v", err)
		}
		if _, err := reg.Claim(ctx, cl(h, "alice", KindCustom, "t3")); err != nil {
			t.Fatalf("owner could not re-claim: %v", err)
		}
		if err := reg.Release(ctx, h, "t3", time.Hour); err != nil {
			t.Fatal(err)
		}
		advance(2 * time.Hour)
		if _, err := reg.Claim(ctx, cl(h, "bob", KindCustom, "t4")); err != nil {
			t.Fatalf("expired hold not claimable: %v", err)
		}
	})

	t.Run("release by a stale tunnel is ignored", func(t *testing.T) {
		h := host("stale")
		if _, err := reg.Claim(ctx, cl(h, "alice", KindCustom, "new")); err != nil {
			t.Fatal(err)
		}
		if err := reg.Release(ctx, h, "old", 0); err != nil {
			t.Fatal(err)
		}
		if _, err := reg.Claim(ctx, cl(h, "alice", KindCustom, "x")); !errors.Is(err, ErrHostnameTaken) {
			t.Fatalf("stale release freed an active name: %v", err)
		}
	})

	t.Run("kind is kept when the owner re-claims within the hold", func(t *testing.T) {
		h := host("kind")
		reg.Claim(ctx, cl(h, "alice", KindRandom, "t1"))
		reg.Release(ctx, h, "t1", time.Hour)
		kind, err := reg.Claim(ctx, cl(h, "alice", KindCustom, "t2"))
		if err != nil || kind != KindRandom {
			t.Fatalf("kind=%q err=%v, want random", kind, err)
		}
	})

	t.Run("concurrent claims have exactly one winner", func(t *testing.T) {
		h := host("race")
		var wins int32
		var wg sync.WaitGroup
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				_, err := reg.Claim(ctx, cl(h, fmt.Sprintf("user-%d", i%5), KindCustom, fmt.Sprintf("t-%d", i)))
				if err == nil {
					atomic.AddInt32(&wins, 1)
				} else if !errors.Is(err, ErrHostnameTaken) {
					t.Errorf("unexpected error: %v", err)
				}
			}(i)
		}
		wg.Wait()
		if wins != 1 {
			t.Fatalf("winners = %d, want exactly 1", wins)
		}
	})

	t.Run("ReleaseAll and Purge", func(t *testing.T) {
		h := host("restart")
		reg.Claim(ctx, cl(h, "alice", KindRandom, "t1"))
		if err := reg.ReleaseAll(ctx, time.Minute); err != nil {
			t.Fatal(err)
		}
		if _, err := reg.Claim(ctx, cl(h, "alice", KindRandom, "t2")); err != nil {
			t.Fatalf("claim after ReleaseAll: %v", err)
		}
		reg.Release(ctx, h, "t2", time.Minute)
		advance(time.Hour)
		if err := reg.Purge(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := reg.Claim(ctx, cl(h, "bob", KindRandom, "t3")); err != nil {
			t.Fatalf("claim after Purge: %v", err)
		}
	})
}

func cl(hostname, owner, kind, tunnelID string) Claim {
	return Claim{Hostname: hostname, OwnerID: owner, Kind: kind, TunnelID: tunnelID}
}
