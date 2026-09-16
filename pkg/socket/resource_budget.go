package socket

import (
	"errors"
	"sync"
)

const (
	// Charge each retained queue entry as well as its payload, preventing a
	// stream of tiny segments from bypassing the byte budget via metadata.
	bufferEntryAllowance    = 128
	DefaultPendingTCPDials  = 64
	DefaultSocketBufferCap  = 64 * 1024 * 1024
	DefaultTCPPendingCap    = 64 * 1024
	DefaultTCPRetransmitCap = 1024 * 1024
)

func bufferCharge(payloadBytes int) int { return payloadBytes + bufferEntryAllowance }

var (
	ErrDialLimit   = errors.New("pending TCP dial limit reached")
	ErrBufferLimit = errors.New("socket buffer limit reached")
)

// resourceBudget reserves capacity before work/allocation. It counts live
// owned bytes/slots, not Go allocator overhead, garbage awaiting GC or RSS.
// No callback or flow lock is acquired while its mutex is held.
type resourceBudget struct {
	mu       sync.Mutex
	limit    int
	used     int
	peak     int
	rejected uint64
}

func (b *resourceBudget) acquire(n int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if n < 0 || n > b.limit-b.used {
		b.rejected++
		return false
	}
	b.used += n
	if b.used > b.peak {
		b.peak = b.used
	}
	return true
}

func (b *resourceBudget) release(n int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if n < 0 || n > b.used {
		panic("socket resource reservation accounting mismatch")
	}
	b.used -= n
}

func (b *resourceBudget) snapshot() (used, peak, limit uint64, rejected uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return uint64(b.used), uint64(b.peak), uint64(b.limit), b.rejected
}

func budgetDefault(value, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}

func (s *SocketInterface) buffers() *resourceBudget {
	s.budgetOnce.Do(func() {
		s.bufferBudget = &resourceBudget{limit: budgetDefault(s.config.SocketBufferCapBytes, DefaultSocketBufferCap)}
	})
	return s.bufferBudget
}
