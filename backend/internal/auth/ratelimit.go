package auth

import (
	"math"
	"sync"
	"time"
)

// Rate limiting is in-process. Every WebSocket and PTY is pinned to this process
// already, so a shared counter would add a dependency without adding a
// capability (ADR 0005). Account lockout, which must survive a restart, lives in
// the database instead -- an attacker who can trigger a crash should not thereby
// clear the counter.

// Limiter provides token-bucket and fixed-window rate limiting.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	windows map[string]*window
	now     func() time.Time
}

type bucket struct {
	tokens   float64
	lastSeen time.Time
}

type window struct {
	count    int
	resetAt  time.Time
	lastSeen time.Time
}

// NewLimiter creates a limiter. now may be nil.
func NewLimiter(now func() time.Time) *Limiter {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Limiter{
		buckets: make(map[string]*bucket),
		windows: make(map[string]*window),
		now:     now,
	}
}

// Allow applies a token bucket refilling at ratePerMinute with the given burst.
//
// Used for general API traffic, where the right behaviour is to absorb a burst
// (a user opening ten tabs) while bounding the sustained rate.
func (l *Limiter) Allow(key string, ratePerMinute, burst int) bool {
	if ratePerMinute <= 0 {
		return true
	}
	if burst <= 0 {
		burst = 1
	}
	now := l.now()
	perSecond := float64(ratePerMinute) / 60.0

	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: float64(burst)}
		l.buckets[key] = b
	} else {
		elapsed := now.Sub(b.lastSeen).Seconds()
		if elapsed > 0 {
			b.tokens = math.Min(float64(burst), b.tokens+elapsed*perSecond)
		}
	}
	b.lastSeen = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// AllowWindow applies a fixed-window counter and reports when to retry.
//
// Used for login attempts, where a burst allowance would be wrong: five tries in
// five minutes means five, not five plus a burst.
func (l *Limiter) AllowWindow(key string, limit int, size time.Duration) (bool, time.Duration) {
	if limit <= 0 || size <= 0 {
		return true, 0
	}
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	w, ok := l.windows[key]
	if !ok || now.After(w.resetAt) {
		w = &window{count: 0, resetAt: now.Add(size)}
		l.windows[key] = w
	}
	w.lastSeen = now

	if w.count >= limit {
		return false, w.resetAt.Sub(now)
	}
	w.count++
	return true, 0
}

// ResetWindow clears a window counter, called after a successful login so a user
// who mistyped twice is not throttled for the rest of the window.
func (l *Limiter) ResetWindow(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.windows, key)
}

// Sweep discards entries untouched for longer than idle, so the maps do not grow
// without bound on an instance that sees many distinct client addresses.
func (l *Limiter) Sweep(idle time.Duration) {
	if idle <= 0 {
		idle = 15 * time.Minute
	}
	cutoff := l.now().Add(-idle)

	l.mu.Lock()
	defer l.mu.Unlock()
	for k, b := range l.buckets {
		if b.lastSeen.Before(cutoff) {
			delete(l.buckets, k)
		}
	}
	for k, w := range l.windows {
		if w.lastSeen.Before(cutoff) && w.resetAt.Before(l.now()) {
			delete(l.windows, k)
		}
	}
}

// Size reports tracked key counts, for metrics and tests.
func (l *Limiter) Size() (buckets, windows int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets), len(l.windows)
}
