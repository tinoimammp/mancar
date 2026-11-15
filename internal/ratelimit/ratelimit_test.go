package ratelimit_test

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/USERNAME/mancar/internal/ratelimit"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newLimiter(max int, w time.Duration) (*ratelimit.FailureLimiter, *clock) {
	c := &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	l := ratelimit.NewFailureLimiter(max, w)
	l.SetClock(c.Now)
	return l, c
}

func TestBlocksAfterMaxFailures(t *testing.T) {
	l, _ := newLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		if _, blocked := l.Blocked("ip"); blocked {
			t.Fatalf("blocked after only %d failures", i)
		}
		l.Fail("ip")
	}
	retry, blocked := l.Blocked("ip")
	if !blocked {
		t.Fatal("not blocked after reaching the allowance")
	}
	if retry <= 0 || retry > time.Minute {
		t.Errorf("retryAfter = %v", retry)
	}
}

func TestKeysAreIndependent(t *testing.T) {
	l, _ := newLimiter(2, time.Minute)
	l.Fail("a")
	l.Fail("a")
	if _, b := l.Blocked("a"); !b {
		t.Fatal("a should be blocked")
	}
	if _, b := l.Blocked("b"); b {
		t.Error("b was blocked by a's failures")
	}
}

func TestWindowExpiryUnblocksAndRestartsCounting(t *testing.T) {
	l, c := newLimiter(2, time.Minute)
	l.Fail("ip")
	l.Fail("ip")
	c.Advance(59 * time.Second)
	retry, blocked := l.Blocked("ip")
	if !blocked || retry != time.Second {
		t.Errorf("at 59s: blocked=%v retry=%v", blocked, retry)
	}
	c.Advance(time.Second)
	if _, blocked := l.Blocked("ip"); blocked {
		t.Error("still blocked when the window ended")
	}
	// a fresh window starts from zero, not from the old count
	l.Fail("ip")
	if _, blocked := l.Blocked("ip"); blocked {
		t.Error("one failure in a new window blocked the key")
	}
	l.Fail("ip")
	if _, blocked := l.Blocked("ip"); !blocked {
		t.Error("two failures in the new window did not block")
	}
}

func TestFailuresAfterBlockDoNotExtendIt(t *testing.T) {
	l, c := newLimiter(1, time.Minute)
	l.Fail("ip")
	for i := 0; i < 100; i++ {
		l.Fail("ip") // hammering while blocked
	}
	c.Advance(time.Minute)
	if _, blocked := l.Blocked("ip"); blocked {
		t.Error("hammering extended the block beyond the window")
	}
}

func TestDisabledLimiterNeverBlocks(t *testing.T) {
	for _, max := range []int{0, -1} {
		l, _ := newLimiter(max, time.Minute)
		for i := 0; i < 1000; i++ {
			l.Fail("ip")
		}
		if _, blocked := l.Blocked("ip"); blocked {
			t.Errorf("max=%d: blocked", max)
		}
	}
	var nilLimiter *ratelimit.FailureLimiter
	nilLimiter.Fail("x")
	if _, blocked := nilLimiter.Blocked("x"); blocked {
		t.Error("nil limiter blocked")
	}
}

func TestMemoryStaysBounded(t *testing.T) {
	l, c := newLimiter(5, time.Minute)
	for i := 0; i < 120_000; i++ {
		l.Fail(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255))
	}
	if n := l.Len(); n > 50_000 {
		t.Errorf("table holds %d keys, want at most 50000", n)
	}
	// expired entries are reclaimed first
	c.Advance(2 * time.Minute)
	for i := 0; i < 50_001; i++ {
		l.Fail(fmt.Sprintf("late-%d", i))
	}
	if n := l.Len(); n > 50_000 {
		t.Errorf("table holds %d keys after expiry sweep", n)
	}
}

func TestConcurrentUse(t *testing.T) {
	l := ratelimit.NewFailureLimiter(1000, time.Minute)
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			key := fmt.Sprintf("k%d", g%4)
			for i := 0; i < 500; i++ {
				l.Fail(key)
				l.Blocked(key)
			}
		}(g)
	}
	wg.Wait()
	// 4 goroutines x 500 failures per key = 2000 >= 1000
	for g := 0; g < 4; g++ {
		if _, b := l.Blocked(fmt.Sprintf("k%d", g)); !b {
			t.Errorf("k%d should be blocked", g)
		}
	}
}
