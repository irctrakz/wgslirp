package socket

import (
	"github.com/irctrakz/wgslirp/pkg/core"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// captureProcessor records packets sent back from bridges for assertions.
type captureProcessor struct {
	mu   sync.Mutex
	pkts [][]byte
}

func (c *captureProcessor) ProcessPacket(p core.Packet) error {
	defer core.ReleasePacket(p)
	c.mu.Lock()
	defer c.mu.Unlock()
	d := make([]byte, p.Length())
	copy(d, p.Data())
	c.pkts = append(c.pkts, d)
	return nil
}

// snapshot returns an immutable view of all packets observed so far.
func (c *captureProcessor) snapshot() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]byte(nil), c.pkts...)
}

type localCapture = captureProcessor
type mockProc = captureProcessor

// The host finishing its Write/Close does not mean the bridge has consumed EOF.
func waitTCPClosed(t *testing.T, b *tcpBridge) {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for atomic.LoadUint64(&b.metrics.ConnectionsClosed) == 0 {
		select {
		case <-deadline.C:
			t.Fatal("bridge did not close the completed flow")
		case <-tick.C:
		}
	}
}
