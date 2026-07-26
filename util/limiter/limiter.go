// Package limiter throttles repeated failed attempts against a keyed resource.
package limiter

import (
	"sync"
	"time"
)

// maxTrackedKeys bounds memory use. An attacker can otherwise grow the map
// without limit by rotating the key (a fresh username or spoofed IP per
// request), turning the defence into a memory exhaustion primitive.
const maxTrackedKeys = 8192

// Limiter counts consecutive failures per key and locks the key out for an
// exponentially growing period once a threshold is crossed.
//
// It is intended for login throttling and holds state in memory only: a restart
// clears it, which is an acceptable trade for not putting a write on the
// database in the unauthenticated request path.
type Limiter struct {
	mu      sync.Mutex
	entries map[string]*entry

	threshold int
	baseDelay time.Duration
	maxDelay  time.Duration
	idle      time.Duration

	// now is overridable in tests.
	now func() time.Time
}

type entry struct {
	failures    int
	lockedUntil time.Time
	lastSeen    time.Time
}

// New returns a Limiter that allows threshold consecutive failures per key
// before locking it out. The lockout starts at baseDelay and doubles with every
// further failure, capped at maxDelay. A key with no activity for idle is
// forgotten.
func New(threshold int, baseDelay, maxDelay, idle time.Duration) *Limiter {
	if threshold < 1 {
		threshold = 1
	}
	return &Limiter{
		entries:   make(map[string]*entry),
		threshold: threshold,
		baseDelay: baseDelay,
		maxDelay:  maxDelay,
		idle:      idle,
		now:       time.Now,
	}
}

// Allow reports whether key may attempt now. When it may not, retryAfter is how
// long the caller should tell the client to wait.
func (l *Limiter) Allow(key string) (retryAfter time.Duration, ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	e := l.entries[key]
	if e == nil {
		return 0, true
	}
	now := l.now()
	if now.Before(e.lockedUntil) {
		return e.lockedUntil.Sub(now), false
	}
	return 0, true
}

// Fail records a failed attempt for key and returns the resulting lockout, which
// is zero while the key is still under the threshold.
func (l *Limiter) Fail(key string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	l.evictLocked(now)

	e := l.entries[key]
	if e == nil {
		if len(l.entries) >= maxTrackedKeys {
			// Full even after eviction: drop this observation rather than grow.
			// Legitimate lockouts already in the map keep their state.
			return 0
		}
		e = &entry{}
		l.entries[key] = e
	}
	e.failures++
	e.lastSeen = now

	if e.failures <= l.threshold {
		return 0
	}
	delay := l.baseDelay << uint(e.failures-l.threshold-1)
	if delay > l.maxDelay || delay <= 0 {
		delay = l.maxDelay
	}
	e.lockedUntil = now.Add(delay)
	return delay
}

// Reset clears the failure history for key. Call it after a successful attempt.
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

// evictLocked drops entries that are both idle and not currently locked out.
func (l *Limiter) evictLocked(now time.Time) {
	if len(l.entries) < maxTrackedKeys/2 {
		return
	}
	for key, e := range l.entries {
		if now.Before(e.lockedUntil) {
			continue
		}
		if now.Sub(e.lastSeen) >= l.idle {
			delete(l.entries, key)
		}
	}
}
