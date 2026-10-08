//go:build linux

package socket

import (
	"errors"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Consume the real peer reset before exercising shutdown: no sleep or errno
// injection, and a bounded deadline distinguishes an actual reset from a stall.
func disconnectedHostSocket(t *testing.T) *net.TCPConn {
	t.Helper()
	conn, peer := tcpBudgetPair(t)
	if err := peer.SetLinger(0); err != nil {
		t.Fatal(err)
	}
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	var data [1]byte
	if _, err := conn.Read(data[:]); !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("peer reset not observed: %v", err)
	}
	return conn
}

func TestTCPDisconnectedWriteShutdownPaths(t *testing.T) {
	for _, pending := range []bool{false, true} {
		name := "immediate FIN"
		if pending {
			name = "post-dial pending flush"
		}
		t.Run(name, func(t *testing.T) {
			b, f, capture := concurrentFlow(t)
			b.ackDelay = 0
			// Server bytes awaiting guest ACK still belong to this flow.
			f.stateMu.Lock()
			if !b.buffers.acquire(bufferCharge(5)) {
				t.Fatal("reserve")
			}
			f.txQueue = append(f.txQueue, struct {
				seq     uint32
				data    []byte
				sentAt  time.Time
				retries int
			}{1000, []byte("owned"), time.Now(), 0})
			f.txBytes = 5
			f.serverNxt = 1005
			f.stateMu.Unlock()
			conn := disconnectedHostSocket(t)
			if pending {
				if err := b.HandleOutbound(closeGuestPacket(f, 100, 1000, 0x11, nil)); err != nil {
					t.Fatal(err)
				}
				f.stateMu.Lock()
				f.conn = conn
				b.flushPending(f)
				f.stateMu.Unlock()
			} else {
				f.stateMu.Lock()
				f.conn = conn
				f.stateMu.Unlock()
				err := b.HandleOutbound(closeGuestPacket(f, 100, 1000, 0x11, nil))
				if !errors.Is(err, ErrTCPTeardown) || !errors.Is(err, syscall.ENOTCONN) {
					t.Fatalf("real shutdown: %v", err)
				}
				b.parent.outboundPacketError("TCP", 40, err)
			}
			if b.hostWriteDisconnected.Load() != 1 || b.hostWriteCloseFailed.Load() != 0 || atomic.LoadUint64(&b.metrics.Errors) != 0 || atomic.LoadUint64(&b.parent.metrics.Errors) != 0 {
				t.Fatal("wrong teardown accounting")
			}
			f.stateMu.Lock()
			closed := f.closed
			remaining := f.txBytes
			f.stateMu.Unlock()
			if !closed || remaining != 0 || b.lookupFlow(f.key) != nil {
				t.Fatal("flow not retired")
			}
			assertBudget(t, b.buffers, 0)
			packets := capture.snapshot()
			if len(packets) == 0 || packets[len(packets)-1][33]&0x04 == 0 {
				t.Fatal("RST behavior changed")
			}
			b.stop()
			assertBudget(t, b.buffers, 0)
			if atomic.LoadUint64(&b.metrics.ConnectionsClosed) != 1 {
				t.Fatal("shutdown repeated retirement")
			}
		})
	}
}
