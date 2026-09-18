package socket

import (
	"errors"
	"sync"
)

const (
	// Charge each retained queue entry as well as its payload, preventing a
	// stream of tiny segments from bypassing the byte budget via metadata.
	bufferEntryAllowance    = 128
	DefaultMaxTCPFlows      = 64
	DefaultMaxUDPFlows      = 256
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

// PacketBufferReserver admits retained packet storage, including an allowance
// for the queue entry. The returned release function is safe to call repeatedly.
// Reserving never calls back into a queue or acquires a flow lock.
type PacketBufferReserver interface {
	ReservePacketBuffer(bytes int) (release func(), err error)
}

// PacketBufferBudgetFor shares a writer's budget when supported. Other writers
// get a finite standalone budget for their adapter; constructors remain compatible.
func PacketBufferBudgetFor(writer SocketWriter) PacketBufferReserver {
	if budget, ok := writer.(PacketBufferReserver); ok {
		return budget
	}
	return &resourceBudget{limit: DefaultSocketBufferCap}
}

// ReservePacketBuffer includes downstream queues in the socket's shared budget.
func (s *SocketInterface) ReservePacketBuffer(bytes int) (func(), error) {
	return s.buffers().ReservePacketBuffer(bytes)
}

func (b *resourceBudget) ReservePacketBuffer(bytes int) (func(), error) {
	charge := -1
	if bytes >= 0 && bytes <= int(^uint(0)>>1)-bufferEntryAllowance {
		charge = bufferCharge(bytes)
	}
	if !b.acquire(charge) {
		return nil, ErrBufferLimit
	}
	var once sync.Once
	return func() { once.Do(func() { b.release(charge) }) }, nil
}

// resourceBudget reserves capacity before work/allocation. It counts live
// owned bytes/slots, not Go allocator overhead, garbage awaiting GC or RSS.
// No callback or flow lock is acquired while its mutex is held.
type resourceBudget struct {
	mu       sync.Mutex
	limit    int
	used     int
	peak     int
	rejected uint64
	invalid  uint64
}

func (b *resourceBudget) acquire(n int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if n < 0 || n > b.limit-b.used {
		b.rejected++
		if n < 0 {
			b.invalid++
		}
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
