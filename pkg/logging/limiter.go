package logging

import (
	"sync"
	"time"
)

// RateLimiter bounds repetitive diagnostics per owner, without per-flow labels.
// A zero value is ready to use. Suppressed events do not affect error counters.
type RateLimiter struct {
	mu   sync.Mutex
	next time.Time
}

func (l *RateLimiter) Allow(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Before(l.next) {
		return false
	}
	l.next = now.Add(30 * time.Second)
	return true
}
