package socket

import (
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestStatusMetricsWhileHostWriteStalled(t *testing.T) {
	bridge, flow, _ := concurrentFlow(t)
	bridge.parent.running = true
	bridge.ackIdleGate = time.Second
	conn, unreadHost := tcpBudgetPair(t)
	if err := conn.SetWriteBuffer(4096); err != nil {
		t.Fatal(err)
	}
	if err := unreadHost.SetReadBuffer(4096); err != nil {
		t.Fatal(err)
	}
	// Flush a pending batch through the real host-write path while holding
	// the flow lock. The receiver leaves its small TCP window unread.
	payload := make([]byte, 1024*1024)
	charge := bufferCharge(len(payload))
	if !bridge.buffers.acquire(charge) {
		t.Fatal("reserve pending bytes")
	}
	flow.conn, flow.pending, flow.pendingBytes = conn, [][]byte{payload}, len(payload)
	bridge.parent.admission.tcpFlows.Add(2)
	bridge.parent.admission.pendingDials.Add(3)
	if bridge.buffers.acquire(bridge.buffers.limit) || bridge.buffers.acquire(-1) {
		t.Fatal("expected buffer reservations to be refused")
	}
	writeDone := make(chan struct{})
	go func() {
		flow.stateMu.Lock()
		bridge.flushPending(flow)
		flow.stateMu.Unlock()
		close(writeDone)
	}()
	defer func() {
		_ = conn.Close()
		<-writeDone
	}()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		var queued int
		var ioctlErr error
		if err := raw.Control(func(fd uintptr) { queued, ioctlErr = unix.IoctlGetInt(int(fd), unix.TIOCOUTQ) }); err != nil {
			t.Fatal(err)
		}
		if ioctlErr != nil {
			t.Fatal(ioctlErr)
		}
		if queued > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("host write never queued data")
		}
		time.Sleep(time.Millisecond)
	}
	type result struct {
		sample TCPResourceMetrics
		ok     bool
	}
	status := make(chan result, 1)
	go func() {
		sample, ok := bridge.parent.TCPResourceMetrics()
		status <- result{sample, ok}
	}()
	select {
	case got := <-status:
		want := TCPResourceMetrics{
			ActiveFlows: 1, BufferBytesInUse: uint64(charge),
			FlowRefusals: 2, PendingDialRefusals: 3, BufferRefusals: 1,
		}
		if !got.ok || got.sample != want {
			t.Fatalf("status metrics = %+v, want %+v", got, want)
		}
	case <-time.After(time.Second):
		t.Fatal("status metrics blocked behind the host write")
	}
	select {
	case <-writeDone:
		t.Fatal("host write finished before the metrics snapshot")
	default:
	}
}
