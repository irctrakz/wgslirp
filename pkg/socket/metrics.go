package socket

import (
	"github.com/irctrakz/wgslirp/pkg/core"
	"sync/atomic"
)

// Metrics is an alias for core.SocketMetrics
type Metrics = core.SocketMetrics

// Reset resets all metrics to zero
func ResetMetrics(m *Metrics) {
	atomic.StoreUint64(&m.PacketsReceived, 0)
	atomic.StoreUint64(&m.PacketsSent, 0)
	atomic.StoreUint64(&m.BytesReceived, 0)
	atomic.StoreUint64(&m.BytesSent, 0)
	atomic.StoreUint64(&m.Errors, 0)
	atomic.StoreUint64(&m.ConnectionsCreated, 0)
	atomic.StoreUint64(&m.ConnectionsClosed, 0)
}
