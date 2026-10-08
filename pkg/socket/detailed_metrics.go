package socket

import (
	"sync/atomic"

	"github.com/irctrakz/wgslirp/pkg/core"
)

// BridgeMetrics captures per-bridge counters and active flow count.
type BridgeMetrics struct {
	DeliveryRefused uint64
	Counters        core.SocketMetrics
	ActiveFlows     uint64
}

// SocketDetailedMetrics exposes total and per-bridge metrics for the socket interface.
type SocketDetailedMetrics struct {
	// Admission contains cumulative, fixed-reason counters; see OBSERVABILITY.md.
	Admission map[string]uint64
	Total     core.SocketMetrics
	UDP       BridgeMetrics
	TCP       BridgeMetrics
	Processor map[string]uint64
	UDPExt    map[string]uint64
	TCPExt    map[string]uint64
}

func loadSocketMetrics(m *core.SocketMetrics) core.SocketMetrics {
	if m == nil {
		return core.SocketMetrics{}
	}
	return core.SocketMetrics{
		ConnectionsCreated: atomic.LoadUint64(&m.ConnectionsCreated),
		ConnectionsClosed:  atomic.LoadUint64(&m.ConnectionsClosed),
		PacketsSent:        atomic.LoadUint64(&m.PacketsSent),
		PacketsReceived:    atomic.LoadUint64(&m.PacketsReceived),
		BytesSent:          atomic.LoadUint64(&m.BytesSent),
		BytesReceived:      atomic.LoadUint64(&m.BytesReceived),
		Errors:             atomic.LoadUint64(&m.Errors),
	}
}

// (FlowManager and limiter types removed)

// (Fallback removed)
