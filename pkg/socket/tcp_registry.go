package socket

import (
	"fmt"
	"github.com/irctrakz/wgslirp/pkg/logging"
	"sync/atomic"
	"time"
)

// lookupFlow observes membership only; callers acquire stateMu after releasing
// the registry lock and check closed before operating on the returned identity.
func (b *tcpBridge) lookupFlow(key string) *tcpFlow {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.flows[key]
}

func (b *tcpBridge) atFlowCapacity() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.maxFlows > 0 && len(b.flows) >= b.maxFlows
}

// registerCandidateLocked requires candidate.stateMu and returns with that lock
// still held. The caller owns candidate socket cleanup and guest error delivery.
// Registry publication rechecks shutdown, tuple identity and the flow cap after
// dialing; no registry lock is held during any dial or delivery callback.
func (b *tcpBridge) registerCandidateLocked(candidate *tcpFlow) (*tcpFlow, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	select {
	case <-b.stopCh:
		return nil, fmt.Errorf("TCP bridge stopped")
	default:
	}
	if existing := b.flows[candidate.key]; existing != nil {
		return existing, nil
	}
	if b.maxFlows > 0 && len(b.flows) >= b.maxFlows {
		b.parent.admission.tcpFlows.Add(1)
		return nil, fmt.Errorf("tcp: %w", ErrFlowLimit)
	}
	b.flows[candidate.key] = candidate
	atomic.AddUint64(&b.metrics.ConnectionsCreated, 1)
	atomic.AddUint64(&b.parent.metrics.ConnectionsCreated, 1)
	return candidate, nil
}

// beginWork serializes WaitGroup admission with shutdown. No work may be
// admitted once stopCh is closed, including children of existing workers.
func (b *tcpBridge) beginWork() bool {
	b.lifecycleMu.Lock()
	defer b.lifecycleMu.Unlock()
	select {
	case <-b.stopCh:
		return false
	default:
	}
	b.workers.Add(1)
	return true
}

func (b *tcpBridge) launch(work func()) bool {
	if !b.beginWork() {
		return false
	}
	go func() { defer b.workers.Done(); work() }()
	return true
}

func (b *tcpBridge) flowSnapshot() []*tcpFlow {
	b.mu.RLock()
	defer b.mu.RUnlock()
	flows := make([]*tcpFlow, 0, len(b.flows))
	for _, f := range b.flows {
		flows = append(flows, f)
	}
	return flows
}

// start owns periodic work; construction performs no I/O or goroutine launch.
func (b *tcpBridge) start() {
	b.startOnce.Do(func() { b.launch(b.reaper); b.launch(b.monitorConnectionHealth) })
}

// monitorConnectionHealth periodically checks for stalled connections and resets them.
// This helps prevent indefinite stalls that can exhaust resources.
func (b *tcpBridge) monitorConnectionHealth() {
	// Check every 15 seconds for stalled connections
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	// Configure stall detection parameters
	stallThreshold := 30 * time.Second // Consider connection stalled after 30s without ACK progress
	minInFlight := 1024                // Only check connections with at least 1KB in flight

	for {
		select {
		case <-b.stopCh:
			return
		case <-ticker.C:
			now := time.Now()
			stalledFlows := make([]*tcpFlow, 0)

			// Identify stalled flows
			for _, f := range b.flowSnapshot() {
				f.stateMu.Lock()
				k := f.key
				// Only check established connections with in-flight data
				if f.state == tcpEstablished {
					inFlight := int(f.serverNxt - f.sndUna)
					idleTime := now.Sub(f.lastAckTime)

					// Connection is stalled if:
					// 1. It has meaningful in-flight data
					// 2. No ACK progress for a significant period
					if inFlight >= minInFlight && idleTime >= stallThreshold {
						stalledFlows = append(stalledFlows, f)
						logging.Warnf("Stalled connection detected: flow=%s idle=%v inFlight=%d bytes",
							k, idleTime.Round(time.Second), inFlight)
					}
				}
				f.stateMu.Unlock()
			}

			// Reset stalled flows
			reset := 0
			for _, f := range stalledFlows {
				// Recheck progress after taking a snapshot: an ACK may have arrived.
				if b.removeFlowIf(f, func(f *tcpFlow) bool {
					return f.state == tcpEstablished && int(f.serverNxt-f.sndUna) >= minInFlight && now.Sub(f.lastAckTime) >= stallThreshold
				}) {
					reset++
				}
			}

			// Log health check summary if any issues found
			if reset > 0 {
				logging.Infof("Connection health check: reset %d stalled flows", reset)
			}
		}
	}
}

func (b *tcpBridge) requestStop() {
	b.lifecycleMu.Lock()
	defer b.lifecycleMu.Unlock()
	select {
	case <-b.stopCh:
		return
	default:
	}
	close(b.stopCh)
	b.cancel()
}

func (b *tcpBridge) stop() {
	b.requestStop()
	b.stopOnce.Do(func() {
		for _, f := range b.flowSnapshot() {
			b.removeFlowIf(f, nil)
		}
		b.workers.Wait()
	})
}

func (b *tcpBridge) removeFlow(key string) {
	b.mu.RLock()
	f := b.flows[key]
	b.mu.RUnlock()
	if f == nil {
		return
	}
	b.removeFlowIf(f, nil)
}

// removeFlowIf acts on the observed identity, never a later tuple replacement.
// The predicate runs under stateMu so expiry/health checks cannot race progress.
func (b *tcpBridge) removeFlowIf(f *tcpFlow, predicate func(*tcpFlow) bool) bool {
	f.stateMu.Lock()
	defer f.stateMu.Unlock()
	b.mu.RLock()
	current := b.flows[f.key] == f
	b.mu.RUnlock()
	if !current || f.closed || (predicate != nil && !predicate(f)) {
		return false
	}
	b.removeFlowLocked(f)
	return true
}

// removeFlowLocked requires stateMu; removal is conditional on identity so an
// old reader cannot remove a replacement connection with the same tuple.
func (b *tcpBridge) removeFlowLocked(f *tcpFlow) {
	if f.closed {
		return
	}
	b.mu.Lock()
	if b.flows[f.key] == f {
		delete(b.flows, f.key)
	}
	b.mu.Unlock()
	f.closed = true
	f.state = tcpClosed
	if f.cancelDial != nil {
		f.cancelDial()
	}
	b.buffers.release(f.pendingBytes + f.futureBytes + f.txBytes + (len(f.pending)+len(f.ooo)+len(f.txQueue))*bufferEntryAllowance)
	f.pending = nil
	f.ooo = nil
	f.txQueue = nil
	f.pendingBytes = 0
	f.futureBytes = 0
	f.txBytes = 0
	if f.conn != nil {
		_ = f.conn.Close()
	}
	if f.rtoStop != nil {
		close(f.rtoStop)
	}
	b.rtoMu.Lock()
	if b.rtoActiveFlows[f.key] == f {
		delete(b.rtoActiveFlows, f.key)
	}
	b.rtoMu.Unlock()
	atomic.AddUint64(&b.metrics.ConnectionsClosed, 1)
	atomic.AddUint64(&b.parent.metrics.ConnectionsClosed, 1)
}

func (b *tcpBridge) reaper() {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-b.stopCh:
			return
		case <-t.C:
			cutoff := time.Now().Add(-b.lifetime)
			b.expireFlows(cutoff)
		}
	}
}

// expireFlows rechecks liveness under flow state after registry observation.
func (b *tcpBridge) expireFlows(cutoff time.Time) {
	for _, f := range b.flowSnapshot() {
		if f.lastActive().Before(cutoff) {
			b.removeFlowIf(f, func(f *tcpFlow) bool { return f.closeDeadline.IsZero() && f.lastActive().Before(cutoff) })
		}
	}
}

func (f *tcpFlow) touch() {
	f.lastMu.Lock()
	f.lastActivity = time.Now()
	f.lastMu.Unlock()
}

func (f *tcpFlow) lastActive() time.Time {
	f.lastMu.Lock()
	defer f.lastMu.Unlock()
	return f.lastActivity
}
