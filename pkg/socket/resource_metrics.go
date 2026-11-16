package socket

// TCPResourceMetrics describes the TCP registry and its shared resource limits.
type TCPResourceMetrics struct {
	ActiveFlows         uint64
	BufferBytesInUse    uint64
	FlowRefusals        uint64
	PendingDialRefusals uint64
	BufferRefusals      uint64
}

// TCPResourceMetrics samples aggregate counters without acquiring flow locks.
// It returns false if the TCP bridge is unavailable.
func (s *SocketInterface) TCPResourceMetrics() (TCPResourceMetrics, bool) {
	s.mu.Lock()
	tcp := s.tcp
	running := s.running
	s.mu.Unlock()
	if !running || tcp == nil {
		return TCPResourceMetrics{}, false
	}
	tcp.mu.RLock()
	active := len(tcp.flows)
	tcp.mu.RUnlock()
	budget := s.buffers()
	budget.mu.Lock()
	used, refused := budget.used, budget.rejected-budget.invalid
	budget.mu.Unlock()
	return TCPResourceMetrics{
		ActiveFlows:         uint64(active),
		BufferBytesInUse:    uint64(used),
		FlowRefusals:        s.admission.tcpFlows.Load(),
		PendingDialRefusals: s.admission.pendingDials.Load(),
		BufferRefusals:      refused,
	}, true
}
