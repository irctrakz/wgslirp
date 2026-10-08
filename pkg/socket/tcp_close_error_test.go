package socket

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestTCPWriteShutdownClassificationAndRelease(t *testing.T) {
	for _, tc := range []struct {
		name              string
		cause             error
		stopping, retired bool
		expected          bool
		counter           string
	}{
		{name: "wrapped disconnected", cause: syscall.ENOTCONN, expected: true, counter: "close_write_disconnected"},
		{name: "local shutdown", cause: net.ErrClosed, stopping: true, expected: true, counter: "close_write_local_shutdown"},
		{name: "retired flow", cause: net.ErrClosed, retired: true, expected: true, counter: "close_write_local_shutdown"},
		{name: "unrecorded local close", cause: net.ErrClosed, counter: "close_write_failed"},
		{name: "unexpected shutdown failure", cause: syscall.EINVAL, counter: "close_write_failed"},
		{name: "shutdown reset", cause: syscall.ECONNRESET, counter: "close_write_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, f, capture := concurrentFlow(t)
			cause := &net.OpError{Op: "close", Net: "tcp", Err: &os.SyscallError{Syscall: "shutdown", Err: tc.cause}}
			if tc.stopping {
				b.requestStop()
			}
			f.stateMu.Lock()
			locked := true
			defer func() {
				if locked {
					f.stateMu.Unlock()
				}
			}()
			// Independent charges exercise all three ownership queues during retirement.
			if !b.buffers.acquire(bufferCharge(3) + bufferCharge(4) + bufferCharge(5)) {
				t.Fatal("reserve")
			}
			f.pending = [][]byte{[]byte("abc")}
			f.pendingBytes = 3
			f.ooo = append(f.ooo, struct {
				seq  uint32
				data []byte
			}{200, []byte("defg")})
			f.futureBytes = 4
			f.txQueue = append(f.txQueue, struct {
				seq     uint32
				data    []byte
				sentAt  time.Time
				retries int
			}{1000, []byte("hijkl"), time.Now(), 0})
			f.txBytes = 5
			f.serverNxt = 1005
			if tc.retired {
				b.removeFlowLocked(f)
			}
			err := b.hostWriteCloseErrorLocked(f, fmt.Errorf("outer: %w", cause))
			if errors.Is(err, ErrTCPTeardown) != tc.expected || !errors.Is(err, tc.cause) {
				t.Fatalf("classification/cause: %v", err)
			}
			var op *net.OpError
			if !errors.As(err, &op) || op != cause {
				t.Fatal("original operation lost")
			}
			if !f.closed || b.lookupFlow(f.key) != nil || len(f.pending)+len(f.ooo)+len(f.txQueue) != 0 || f.pendingBytes+f.futureBytes+f.txBytes != 0 {
				t.Fatal("retirement lost ownership")
			}
			b.removeFlowLocked(f)
			f.stateMu.Unlock()
			locked = false
			assertBudget(t, b.buffers, 0)
			if atomic.LoadUint64(&b.metrics.ConnectionsClosed) != 1 || atomic.LoadUint64(&b.parent.metrics.ConnectionsClosed) != 1 {
				t.Fatal("duplicate retirement")
			}
			_, metrics := b.snapshotMetrics()
			for _, key := range []string{"close_write_disconnected", "close_write_local_shutdown", "close_write_failed"} {
				want := uint64(0)
				if key == tc.counter {
					want = 1
				}
				if metrics[key] != want {
					t.Fatalf("%s=%d want=%d", key, metrics[key], want)
				}
			}
			packets := capture.snapshot()
			if len(packets) == 0 || packets[len(packets)-1][33]&0x04 == 0 {
				t.Fatal("abort must retain guest RST")
			}
			wrapped := b.parent.outboundPacketError("TCP", 40, err)
			if errors.Is(wrapped, ErrTCPTeardown) != tc.expected || !errors.Is(wrapped, tc.cause) {
				t.Fatal("socket wrapper lost classification")
			}
			wantErrors := uint64(1)
			if tc.expected {
				wantErrors = 0
			}
			if atomic.LoadUint64(&b.parent.metrics.Errors) != wantErrors {
				t.Fatal("wrong generic error count")
			}
		})
	}
}

func TestTCPPendingFlushUnrecordedClosedSocketRemainsFailure(t *testing.T) {
	b, f, _ := concurrentFlow(t)
	conn, _ := tcpBudgetPair(t)
	_ = conn.Close()
	f.stateMu.Lock()
	f.conn = conn
	f.finReceived = true
	b.flushPending(f)
	f.stateMu.Unlock()
	if b.hostWriteCloseFailed.Load() != 1 || b.hostWriteLocalClosed.Load() != 0 || atomic.LoadUint64(&b.metrics.Errors) != 1 || atomic.LoadUint64(&b.parent.metrics.Errors) != 1 {
		t.Fatal("unrecorded close was hidden")
	}
	assertBudget(t, b.buffers, 0)
}

func TestTCPPayloadWriteDisconnectionIsNotTeardown(t *testing.T) {
	b, _, _ := concurrentFlow(t)
	err := b.parent.outboundPacketError("TCP", 40, fmt.Errorf("tcp: write: %w", syscall.ENOTCONN))
	if errors.Is(err, ErrTCPTeardown) || atomic.LoadUint64(&b.parent.metrics.Errors) != 1 {
		t.Fatal("payload failure hidden")
	}
}
