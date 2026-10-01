package socket

import "sync/atomic"

// Counters belong to an interface, survive Stop, and never use peer/flow labels.
// Each owner increments only at the check that denies admission, not again when
// the failure propagates through a handler, worker, or packet processor.
type admissionCounters struct {
	tcpFlows        atomic.Uint64
	udpFlows        atomic.Uint64
	icmpEchoes      atomic.Uint64
	pendingDials    atomic.Uint64
	pendingBytes    atomic.Uint64
	reassemblyBytes atomic.Uint64
	retransmitWaits atomic.Uint64
}

func (s *SocketInterface) admissionSnapshot() map[string]uint64 {
	b := s.buffers()
	b.mu.Lock()
	aggregate, invalid := b.rejected-b.invalid, b.invalid
	b.mu.Unlock()
	return map[string]uint64{
		"tcp_flow_limit":         s.admission.tcpFlows.Load(),
		"udp_flow_limit":         s.admission.udpFlows.Load(),
		"icmp_echo_limit":        s.admission.icmpEchoes.Load(),
		"pending_dial_limit":     s.admission.pendingDials.Load(),
		"tcp_pending_limit":      s.admission.pendingBytes.Load(),
		"tcp_reassembly_limit":   s.admission.reassemblyBytes.Load(),
		"aggregate_buffer_limit": aggregate,
		"invalid_buffer_request": invalid,
		"tcp_retransmit_waits":   s.admission.retransmitWaits.Load(),
	}
}

// reservePending requires the flow's state and pending locks. Per-flow checks
// precede the aggregate check so one denied reservation has exactly one reason.
func (b *tcpBridge) reservePending(f *tcpFlow, size int) bool {
	if size > f.pendCap-f.pendingBytes {
		b.parent.admission.pendingBytes.Add(1)
		return false
	}
	return b.buffers.acquire(bufferCharge(size))
}
