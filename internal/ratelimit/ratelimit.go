// Package ratelimit contains small, dependency-free limiters.
package ratelimit

import (
	"sync"
	"time"
)

// maxKeys bounds memory: an attacker rotating through addresses cannot make
// the table grow without limit.
const maxKeys = 50_000

type window struct {
	start time.Time
	count int
}

// FailureLimiter counts failures per key in fixed windows and reports keys
// that exceeded the allowance. It is used to stop credential guessing and
// the database load that comes with it: while a key is blocked callers must
// refuse the request without doing any expensive work.
type FailureLimiter struct {
	max    int
	window time.Duration
	now    func() time.Time

	mu sync.Mutex
	m  map[string]*window
}

// NewFailureLimiter allows max failures per key in each window. max <= 0
// disables the limiter (nothing is ever blocked).
func NewFailureLimiter(max int, w time.Duration) *FailureLimiter {
	return &FailureLimiter{max: max, window: w, now: time.Now, m: map[string]*window{}}
}

// SetClock replaces the clock (tests).
func (l *FailureLimiter) SetClock(now func() time.Time) { l.now = now }

// Blocked reports whether key has used up its allowance and, if so, how
// long until its window ends.
func (l *FailureLimiter) Blocked(key string) (retryAfter time.Duration, blocked bool) {
	if l == nil || l.max <= 0 {
		return 0, false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	w, ok := l.m[key]
	if !ok {
		return 0, false
	}
	now := l.now()
	if !now.Before(w.start.Add(l.window)) {
		delete(l.m, key)
		return 0, false
	}
	if w.count < l.max {
		return 0, false
	}
	return w.start.Add(l.window).Sub(now), true
}

// Fail records one failure for key.
func (l *FailureLimiter) Fail(key string) {
	if l == nil || l.max <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	w, ok := l.m[key]
	if ok && !now.Before(w.start.Add(l.window)) {
		ok = false
	}
	if !ok {
		if len(l.m) >= maxKeys {
			l.sweepLocked(now)
		}
		w = &window{start: now}
		l.m[key] = w
	}
	w.count++
}

// Forgive takes back one failure recorded for key. Callers record a
// failure before slow work (password hashing) and forgive it on success, so
// a burst of simultaneous attempts cannot all slip past Blocked.
func (l *FailureLimiter) Forgive(key string) {
	if l == nil || l.max <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if w, ok := l.m[key]; ok && w.count > 0 {
		w.count--
	}
}

// sweepLocked drops expired windows; if the table is still full it evicts
// arbitrary entries so memory stays bounded even under a spray of keys.
func (l *FailureLimiter) sweepLocked(now time.Time) {
	for k, w := range l.m {
		if !now.Before(w.start.Add(l.window)) {
			delete(l.m, k)
		}
	}
	for k := range l.m {
		if len(l.m) < maxKeys*9/10 {
			break
		}
		delete(l.m, k)
	}
}

// Len returns the number of tracked keys (tests).
func (l *FailureLimiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.m)
}
