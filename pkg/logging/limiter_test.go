package logging

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRateLimiterBoundsConcurrentFailures(t *testing.T) {
	var l RateLimiter
	now := time.Unix(1000, 0)
	var allowed atomic.Int32
	var workers sync.WaitGroup
	for i := 0; i < 20; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if l.Allow(now) {
				allowed.Add(1)
			}
		}()
	}
	workers.Wait()
	if allowed.Load() != 1 || l.Allow(now.Add(29*time.Second)) || !l.Allow(now.Add(30*time.Second)) {
		t.Fatal("diagnostics not bounded")
	}
}
