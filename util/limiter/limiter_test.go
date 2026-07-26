package limiter

import (
	"testing"
	"time"
)

// newAt returns a Limiter whose clock the test controls.
func newAt(threshold int, base, max, idle time.Duration, clock *time.Time) *Limiter {
	l := New(threshold, base, max, idle)
	l.now = func() time.Time { return *clock }
	return l
}

func TestAllowsUpToThresholdThenLocksOut(t *testing.T) {
	now := time.Unix(1700000000, 0)
	l := newAt(3, 30*time.Second, 10*time.Minute, time.Hour, &now)

	for i := 1; i <= 3; i++ {
		if lock := l.Fail("ip:1.2.3.4"); lock != 0 {
			t.Fatalf("failure %d locked out early (%v)", i, lock)
		}
		if _, ok := l.Allow("ip:1.2.3.4"); !ok {
			t.Fatalf("blocked after only %d failures, threshold is 3", i)
		}
	}

	lock := l.Fail("ip:1.2.3.4")
	if lock != 30*time.Second {
		t.Fatalf("first lockout = %v, want 30s", lock)
	}
	retryAfter, ok := l.Allow("ip:1.2.3.4")
	if ok {
		t.Fatal("Allow() permitted an attempt while locked out")
	}
	if retryAfter != 30*time.Second {
		t.Errorf("retryAfter = %v, want 30s", retryAfter)
	}

	// An unrelated key must be unaffected.
	if _, ok := l.Allow("ip:5.6.7.8"); !ok {
		t.Error("lockout leaked to a different key")
	}
}

func TestLockoutGrowsExponentiallyAndIsCapped(t *testing.T) {
	now := time.Unix(1700000000, 0)
	l := newAt(1, time.Second, 4*time.Second, time.Hour, &now)

	l.Fail("k") // reaches threshold, no lockout yet
	for _, want := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 4 * time.Second} {
		if got := l.Fail("k"); got != want {
			t.Fatalf("lockout = %v, want %v", got, want)
		}
	}
}

func TestLockoutExpires(t *testing.T) {
	now := time.Unix(1700000000, 0)
	l := newAt(1, 30*time.Second, time.Minute, time.Hour, &now)

	l.Fail("k")
	l.Fail("k")
	if _, ok := l.Allow("k"); ok {
		t.Fatal("Allow() permitted an attempt while locked out")
	}

	now = now.Add(31 * time.Second)
	if _, ok := l.Allow("k"); !ok {
		t.Fatal("Allow() still blocked after the lockout expired")
	}
}

func TestResetClearsHistory(t *testing.T) {
	now := time.Unix(1700000000, 0)
	l := newAt(1, 30*time.Second, time.Minute, time.Hour, &now)

	l.Fail("k")
	l.Fail("k")
	if _, ok := l.Allow("k"); ok {
		t.Fatal("Allow() permitted an attempt while locked out")
	}

	l.Reset("k")
	if _, ok := l.Allow("k"); !ok {
		t.Fatal("Reset() did not clear the lockout")
	}
	if lock := l.Fail("k"); lock != 0 {
		t.Fatalf("failure count survived Reset(): lockout = %v", lock)
	}
}

// The map must not grow without bound: the key is partly attacker-chosen (the
// submitted username), so an unbounded map would be a memory exhaustion vector.
func TestTrackedKeysAreBounded(t *testing.T) {
	now := time.Unix(1700000000, 0)
	l := newAt(1, time.Second, time.Second, time.Nanosecond, &now)

	for i := 0; i < maxTrackedKeys*2; i++ {
		l.Fail(string(rune(i%1114112)) + "-" + time.Duration(i).String())
		now = now.Add(time.Millisecond)
	}
	if len(l.entries) > maxTrackedKeys {
		t.Fatalf("tracked %d keys, want at most %d", len(l.entries), maxTrackedKeys)
	}
}
