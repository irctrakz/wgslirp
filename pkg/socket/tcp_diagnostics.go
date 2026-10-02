package socket

import (
	"github.com/irctrakz/wgslirp/pkg/logging"
	"sync/atomic"
	"time"
)

// trackRTOFlow adds a flow to the RTO tracking map and checks if we need to dump metrics
func (b *tcpBridge) trackRTOFlow(f *tcpFlow) {
	f.stateMu.Lock()
	b.mu.RLock()
	current := b.flows[f.key] == f
	b.mu.RUnlock()
	if f.closed || !current {
		f.stateMu.Unlock()
		return
	}
	// Decide whether a dump is needed without holding the lock during the dump
	needDump := false
	b.rtoMu.Lock()
	// Add this flow to the active RTO flows map
	b.rtoActiveFlows[f.key] = f
	if len(b.rtoActiveFlows) >= 3 {
		if !b.rtoMetricsDumped || time.Since(b.rtoMetricsDumpTime) > 30*time.Second {
			// Mark as dumped and record time under lock
			b.rtoMetricsDumped = true
			b.rtoMetricsDumpTime = time.Now()
			needDump = true
			// Own the reset timer so bridge shutdown joins all diagnostics.
			b.launch(func() {
				timer := time.NewTimer(10 * time.Second)
				defer timer.Stop()
				select {
				case <-b.stopCh:
					return
				case <-timer.C:
				}
				b.rtoMu.Lock()
				b.rtoMetricsDumped = false
				b.rtoActiveFlows = make(map[string]*tcpFlow)
				b.rtoMu.Unlock()
			})
		}
	}
	b.rtoMu.Unlock()
	f.stateMu.Unlock()
	if needDump {
		b.dumpDetailedMetrics()
	}
}

// dumpDetailedMetrics logs detailed system metrics when multiple flows are in RTO state
// This function is designed to be robust against errors and always complete the metrics dump
func (b *tcpBridge) dumpDetailedMetrics() {
	// Snapshot registry membership first; never lock flow state under b.mu.
	for _, f := range b.flowSnapshot() {
		f.stateMu.Lock()
		logging.Warnf("TCP flow=%s inflight=%d window=%d rto=%v closed=%v",
			f.key, f.serverNxt-f.sndUna, f.advWnd, f.rto, f.closed)
		f.stateMu.Unlock()
	}
}

// logACKLocked formats the existing trace under flow.stateMu. It does not take
// registry locks or change classification/counters; the caller checks ackTrace.
func (b *tcpBridge) logACKLocked(flow *tcpFlow, ack uint32, payloadLen int, wnd, prevWnd uint32) {
	class := "adv"
	if ack == flow.sndUna && payloadLen == 0 {
		class = "dup"
	} else if ack <= flow.sndUna && wnd > prevWnd {
		class = "wnd"
	}
	logging.Infof("TCP ACK trace: flow=%s class=%s ack=%d sndUna=%d nxt=%d wnd=%d ws=%d txq=%d",
		flow.key, class, ack, flow.sndUna, flow.serverNxt, flow.advWnd, flow.wsIn, len(flow.txQueue))

}

// snapshotMetrics owns TCP-specific counters and registry/flow observations.
// Membership is sampled before taking any state lock. As before, the aggregate
// is a safe observational snapshot, not a transaction across all counters/flows.
func (tcp *tcpBridge) snapshotMetrics() (metrics BridgeMetrics, extended map[string]uint64) {
	flows := tcp.flowSnapshot()
	active := uint64(len(flows))
	// Snapshot membership before taking individual flow locks.
	ackIdle := uint64(0)
	if tcp.ackIdleGate > 0 {
		for _, f := range flows {
			f.stateMu.Lock()
			if tcp.ackIdleGatedLocked(f, time.Now()) {
				ackIdle++
			}
			f.stateMu.Unlock()
		}
	}
	metrics.DeliveryRefused = tcp.deliveryRefused.Load()
	metrics.Counters = loadSocketMetrics(&tcp.metrics)
	metrics.ActiveFlows = active
	// TCP extra debug counters
	tcp.rtoMu.Lock()
	activeRTOFlows := uint64(len(tcp.rtoActiveFlows))
	tcp.rtoMu.Unlock()
	// Compose TCPExt with RTO and ACK classification counters
	dialUsed, dialPeak, dialLimit, dialRejected := tcp.dialSlots.snapshot()
	bufferUsed, bufferPeak, bufferLimit, bufferRejected := tcp.buffers.snapshot()
	extended = map[string]uint64{
		"dial_reserved":         dialUsed,
		"dial_peak":             dialPeak,
		"dial_limit":            dialLimit,
		"dial_refused":          dialRejected,
		"socket_buffer_bytes":   bufferUsed,
		"socket_buffer_peak":    bufferPeak,
		"socket_buffer_limit":   bufferLimit,
		"socket_buffer_refused": bufferRejected,
		"buffer_dropped":        tcp.bufferDrops.Load(),
		"rto":                   atomic.LoadUint64(&tcp.rtoCount),
		"active_rto_flows":      activeRTOFlows,
		"ack_advanced":          atomic.LoadUint64(&tcp.ackAdv),
		"ack_duplicate":         atomic.LoadUint64(&tcp.ackDup),
		"ack_window_update":     atomic.LoadUint64(&tcp.ackWndOnly),
		"ack_idle_flows":        ackIdle,
		// Async dial and pending-buffer instrumentation
		"dial_start":    atomic.LoadUint64(&tcp.dialStart),
		"dial_ok":       atomic.LoadUint64(&tcp.dialOk),
		"dial_fail":     atomic.LoadUint64(&tcp.dialFail),
		"dial_inflight": uint64(atomic.LoadInt64(&tcp.dialInflight)),
		"pend_enq":      atomic.LoadUint64(&tcp.pendEnq),
		"pend_flush":    atomic.LoadUint64(&tcp.pendFlush),
		"pend_drop":     atomic.LoadUint64(&tcp.pendDrop),
	}

	return metrics, extended
}
