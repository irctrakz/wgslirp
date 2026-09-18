package socket

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func closeGuestPacket(f *tcpFlow, seq, ack uint32, flags byte, data []byte) []byte {
	p := buildIPv4TCP(f.srcIP, f.dstIP, f.srcPort, f.dstPort, seq, ack, flags, data)
	binary.BigEndian.PutUint16(p[34:36], 1200)
	return p
}

func closeOutbound(t *testing.T, b *tcpBridge, f *tcpFlow, seq, ack uint32, flags byte, data []byte) {
	t.Helper()
	if err := b.HandleOutbound(closeGuestPacket(f, seq, ack, flags, data)); err != nil {
		t.Fatal(err)
	}
}

func closePacket(t *testing.T, c *notifyingCapture, from int, match func([]byte) bool) ([]byte, int) {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for {
		packets := c.snapshot()
		for i := from; i < len(packets); i++ {
			if match(packets[i]) {
				return packets[i], i + 1
			}
		}
		from = len(packets)
		select {
		case <-c.changed:
		case <-deadline.C:
			t.Fatal("close packet not delivered")
			return nil, 0
		}
	}
}

func closePair(t *testing.T) (*tcpBridge, *tcpFlow, *notifyingCapture, *net.TCPConn) {
	t.Helper()
	b, f, c := concurrentFlow(t)
	conn, peer := tcpBudgetPair(t)
	f.stateMu.Lock()
	f.conn = conn
	f.rto = 200 * time.Millisecond
	f.stateMu.Unlock()
	t.Cleanup(b.stop)
	if !b.launch(func() { b.reader(f) }) {
		t.Fatal("reader rejected")
	}
	_ = peer.SetDeadline(time.Now().Add(3 * time.Second))
	return b, f, c, peer
}

func TestTCPHostHalfCloseRecoversLostDataFINAndFinalACK(t *testing.T) {
	b, f, c, peer := closePair(t)
	response := []byte("response before EOF")
	if _, err := peer.Write(response); err != nil {
		t.Fatal(err)
	}
	if err := peer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	first, after := closePacket(t, c, 0, func(p []byte) bool { return p[33]&1 != 0 })
	finSeq := binary.BigEndian.Uint32(first[24:28])
	if finSeq != 1000+uint32(len(response)) {
		t.Fatal("FIN preceded data")
	}
	// Drop the first data/FIN: recovery must retain and retransmit both.
	_, _ = closePacket(t, c, after, func(p []byte) bool { return bytes.Equal(p[40:], response) })
	retry, _ := closePacket(t, c, after, func(p []byte) bool { return p[33]&1 != 0 })
	if binary.BigEndian.Uint32(retry[24:28]) != finSeq {
		t.Fatal("FIN retry consumed sequence space twice")
	}
	f.stateMu.Lock()
	intact := !f.closed && f.txBytes == len(response)
	f.stateMu.Unlock()
	if !intact {
		t.Fatal("host EOF discarded unacknowledged data")
	}
	closeOutbound(t, b, f, 100, finSeq+2, 0x10, nil) // future ACK must not finish close
	f.stateMu.Lock()
	state := f.state
	f.stateMu.Unlock()
	if state != tcpFinWait1 {
		t.Fatal("invalid ACK advanced close")
	}
	closeOutbound(t, b, f, 100, finSeq+1, 0x10, nil)
	// ACKing the host FIN does not close the opposite stream direction.
	closeOutbound(t, b, f, 100, finSeq+1, 0x11, []byte("late request"))
	got, err := io.ReadAll(peer)
	if err != nil || string(got) != "late request" {
		t.Fatalf("half-close lost data: %q, %v", got, err)
	}
	f.stateMu.Lock()
	state = f.state
	next := f.clientNxt
	f.stateMu.Unlock()
	if state != tcpTimeWait || next != 113 {
		t.Fatalf("state=%v next=%d", state, next)
	}
	before := len(c.snapshot())
	// Drop our final ACK. A duplicate peer FIN must receive the same ACK.
	closeOutbound(t, b, f, 100, finSeq+1, 0x11, []byte("late request"))
	ack, _ := closePacket(t, c, before, func(p []byte) bool { return p[33] == 0x10 })
	if binary.BigEndian.Uint32(ack[28:32]) != next {
		t.Fatal("duplicate FIN changed receive sequence")
	}
	f.stateMu.Lock()
	b.closeTickLocked(f, f.timeWaitUntil)
	f.stateMu.Unlock()
	if len(b.flowSnapshot()) != 0 {
		t.Fatal("TIME-WAIT did not remove flow")
	}
	b.stop()
	assertBudget(t, b.buffers, 0)
}

func TestTCPGuestHalfCloseDrainsResponseAcrossWindows(t *testing.T) {
	b, f, c, peer := closePair(t)
	closeOutbound(t, b, f, 100, 1000, 0x11, []byte("ask"))
	request, err := io.ReadAll(peer)
	if err != nil || string(request) != "ask" {
		t.Fatalf("payload+FIN: %q %v", request, err)
	}
	// Lose the FIN ACK and retransmit the entire payload+FIN. No duplicate write.
	closeOutbound(t, b, f, 100, 1000, 0x11, []byte("ask"))
	response := bytes.Repeat([]byte("reply"), 1200) // exceeds the 1200-byte guest window
	if _, err := peer.Write(response); err != nil {
		t.Fatal(err)
	}
	if err := peer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	next := uint32(1000)
	var received []byte
	from := 0
	for {
		packet, index := closePacket(t, c, from, func(p []byte) bool { return len(p) > 40 || p[33]&1 != 0 })
		from = index
		seq := binary.BigEndian.Uint32(packet[24:28])
		if len(packet) > 40 && seq == next {
			received = append(received, packet[40:]...)
			next += uint32(len(packet) - 40)
		}
		if packet[33]&1 != 0 {
			if seq != next || !bytes.Equal(received, response) {
				t.Fatal("FIN arrived before complete response")
			}
			closeOutbound(t, b, f, 104, next+1, 0x10, nil)
			break
		}
		closeOutbound(t, b, f, 104, next, 0x10, nil)
	}
	if len(b.flowSnapshot()) != 0 {
		t.Fatal("passive close retained flow before cleanup")
	}
	b.stop()
	assertBudget(t, b.buffers, 0)
}

func TestTCPFINBeforeDialFlushesPendingBeforeCloseWrite(t *testing.T) {
	b, f, _ := concurrentFlow(t)
	f.pendCap = b.defaultPendCap
	closeOutbound(t, b, f, 100, 1000, 0x11, []byte("pending"))
	f.stateMu.Lock()
	if !f.finReceived || f.hostWriteClosed || f.pendingBytes != 7 || f.clientNxt != 108 || len(f.pending) != 1 || cap(f.pending[0]) != 7 {
		f.stateMu.Unlock()
		t.Fatal("pending FIN acceptance")
	}
	f.stateMu.Unlock()
	conn, peer := tcpBudgetPair(t)
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	f.stateMu.Lock()
	f.conn = conn
	b.flushPending(f)
	closedWrite := f.hostWriteClosed
	f.stateMu.Unlock()
	got, err := io.ReadAll(peer)
	if err != nil || string(got) != "pending" || !closedWrite {
		t.Fatalf("pending drain: %q %v", got, err)
	}
	assertBudget(t, b.buffers, 0)
}

func TestTCPOutOfOrderFINWaitsForMissingBytes(t *testing.T) {
	b, f, _ := concurrentFlow(t)
	conn, peer := tcpBudgetPair(t)
	f.conn = conn
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	closeOutbound(t, b, f, 103, 1000, 0x11, []byte("DEF"))
	if f.finReceived || f.clientNxt != 100 {
		t.Fatal("consumed future FIN")
	}
	closeOutbound(t, b, f, 100, 1000, 0x18, []byte("ABC"))
	if f.finReceived || f.clientNxt != 106 {
		t.Fatal("incorrect reassembly progress")
	}
	// Payload is now duplicate but its FIN is new; consume FIN once.
	closeOutbound(t, b, f, 103, 1000, 0x11, []byte("DEF"))
	closeOutbound(t, b, f, 103, 1000, 0x11, []byte("DEF"))
	got, err := io.ReadAll(peer)
	if err != nil || string(got) != "ABCDEF" || f.clientNxt != 107 {
		t.Fatalf("reordered close: %q %v next=%d", got, err, f.clientNxt)
	}
	assertBudget(t, b.buffers, 0)
}

func TestTCPHandshakeACKCanCarryPayloadAndFIN(t *testing.T) {
	b, f, _ := concurrentFlow(t)
	conn, peer := tcpBudgetPair(t)
	f.conn = conn
	f.state = tcpSynRcvd
	f.serverISN = 999
	closeOutbound(t, b, f, 100, 1000, 0x11, []byte("third ACK"))
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	got, err := io.ReadAll(peer)
	if err != nil || string(got) != "third ACK" || f.state != tcpCloseWait {
		t.Fatalf("third ACK: %q %v", got, err)
	}
}

func TestTCPFINRefusalRetryWrapAndSimultaneousClose(t *testing.T) {
	b, f, c := concurrentFlow(t)
	now := time.Now()
	f.serverNxt = ^uint32(0)
	f.sndUna = f.serverNxt
	f.clientNxt = ^uint32(0)
	b.buffers.limit = 0
	f.stateMu.Lock()
	b.startFINLocked(f, now)
	f.stateMu.Unlock()
	if f.serverNxt != 0 || len(c.snapshot()) != 0 {
		t.Fatal("failed FIN allocation did not retain sequence")
	}
	b.buffers.limit = DefaultSocketBufferCap
	f.stateMu.Lock()
	b.closeTickLocked(f, now.Add(time.Second))
	f.stateMu.Unlock()
	fin, _ := closePacket(t, c, 0, func(p []byte) bool { return p[33]&1 != 0 })
	if binary.BigEndian.Uint32(fin[24:28]) != ^uint32(0) {
		t.Fatal("wrapped FIN sequence changed")
	}
	// Simultaneous FIN before ACK of our FIN enters CLOSING.
	closeOutbound(t, b, f, ^uint32(0), ^uint32(0), 0x11, nil)
	if f.state != tcpClosing || f.clientNxt != 0 {
		t.Fatal("simultaneous FIN state")
	}
	closeOutbound(t, b, f, 0, 0, 0x10, nil)
	if f.state != tcpTimeWait || f.sndUna != 0 {
		t.Fatal("wrapped FIN ACK not recognized")
	}
	before := len(c.snapshot())
	f.stateMu.Lock()
	b.closeTickLocked(f, now.Add(10*time.Second))
	f.stateMu.Unlock()
	if len(c.snapshot()) != before {
		t.Fatal("retransmitted acknowledged FIN")
	}
}

func TestTCPBoundedCloseExpiryAndDuplicateFINLinger(t *testing.T) {
	for _, active := range []bool{false, true} {
		t.Run(map[bool]string{false: "guest", true: "host"}[active], func(t *testing.T) {
			b, f, c := concurrentFlow(t)
			now := time.Now()
			if !b.sendPayload(f, []byte("unacknowledged")) {
				t.Fatal("send failed")
			}
			f.stateMu.Lock()
			if active {
				b.startFINLocked(f, now)
			} else {
				if err := b.receiveFINLocked(f, now); err != nil {
					f.stateMu.Unlock()
					t.Fatal(err)
				}
			}
			deadline := f.closeDeadline
			b.closeTickLocked(f, deadline.Add(-time.Nanosecond))
			if f.closed {
				f.stateMu.Unlock()
				t.Fatal("expired close early")
			}
			b.closeTickLocked(f, deadline)
			b.closeTickLocked(f, deadline.Add(time.Second))
			f.stateMu.Unlock()
			packets := c.snapshot()
			if packets[len(packets)-1][33]&4 == 0 {
				t.Fatal("timeout silently discarded data")
			}
			assertBudget(t, b.buffers, 0)
			if loadSocketMetrics(&b.metrics).ConnectionsClosed != 1 {
				t.Fatal("close counted more than once")
			}
		})
	}
	b, f, _ := concurrentFlow(t)
	now := time.Now()
	f.stateMu.Lock()
	b.startFINLocked(f, now)
	f.stateMu.Unlock()
	closeOutbound(t, b, f, 100, 1001, 0x11, nil)
	if f.state != tcpTimeWait {
		t.Fatal("expected TIME-WAIT")
	}
	b.expireFlows(now.Add(time.Hour))
	if f.closed {
		t.Fatal("idle reaper truncated TIME-WAIT")
	}
	f.stateMu.Lock()
	b.enterTimeWaitLocked(f, now.Add(5*time.Minute))
	if f.timeWaitUntil != f.closeDeadline.Add(tcpTimeWaitDuration) {
		f.stateMu.Unlock()
		t.Fatal("duplicate FIN can extend forever")
	}
	b.closeTickLocked(f, f.timeWaitUntil)
	f.stateMu.Unlock()
	if len(b.flowSnapshot()) != 0 {
		t.Fatal("TIME-WAIT did not expire")
	}
}

func TestTCPShutdownDuringHalfClosedTraffic(t *testing.T) {
	b, f, c, peer := closePair(t)
	closeOutbound(t, b, f, 100, 1000, 0x11, nil)
	if _, err := io.ReadAll(peer); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.Write(bytes.Repeat([]byte{1}, 4096)); err != nil {
		t.Fatal(err)
	}
	_, _ = closePacket(t, c, 0, func(p []byte) bool { return len(p) > 40 })
	// No guest ACK: the sender eventually blocks at its window. Stop must join it.
	done := make(chan struct{})
	go func() { b.stop(); close(done) }()
	awaitLifecycle(t, done)
	assertBudget(t, b.buffers, 0)
	if len(b.flowSnapshot()) != 0 {
		t.Fatal("half-closed shutdown leaked flow")
	}
}

func TestTCPHalfCloseDeadlineRequiresRealProgress(t *testing.T) {
	b, f, _ := concurrentFlow(t)
	if !b.sendPayload(f, []byte("response")) {
		t.Fatal("send failed")
	}
	f.stateMu.Lock()
	if err := b.receiveFINLocked(f, time.Now().Add(-time.Minute)); err != nil {
		f.stateMu.Unlock()
		t.Fatal(err)
	}
	oldDeadline := f.closeDeadline
	f.stateMu.Unlock()
	closeOutbound(t, b, f, 101, 1000, 0x10, nil) // duplicate ACK, not progress
	closeOutbound(t, b, f, 100, 1000, 0x11, nil) // duplicate FIN, not progress
	f.stateMu.Lock()
	unchanged := f.closeDeadline == oldDeadline
	f.stateMu.Unlock()
	if !unchanged {
		t.Fatal("duplicate control traffic extended close deadline")
	}
	closeOutbound(t, b, f, 101, 1004, 0x10, nil) // cumulative data ACK advances
	f.stateMu.Lock()
	extended := f.closeDeadline.After(oldDeadline)
	b.closeTickLocked(f, oldDeadline)
	stillOpen := !f.closed
	f.stateMu.Unlock()
	if !extended || !stillOpen {
		t.Fatal("real progress did not preserve half-closed response")
	}
	b.stop()
	assertBudget(t, b.buffers, 0)
}

func TestTCPRefusedPayloadDoesNotConsumeFIN(t *testing.T) {
	b, f, c := concurrentFlow(t)
	f.pendCap = 2
	closeOutbound(t, b, f, 100, 1000, 0x11, []byte("three"))
	f.stateMu.Lock()
	intact := f.clientNxt == 100 && !f.finReceived && f.state == tcpEstablished && f.pendingBytes == 0
	f.stateMu.Unlock()
	if !intact {
		t.Fatal("FIN acknowledged refused payload")
	}
	packets := c.snapshot()
	if len(packets) == 0 || binary.BigEndian.Uint32(packets[len(packets)-1][28:32]) != 100 {
		t.Fatal("ACK advanced over refused bytes")
	}
	b.stop()
	assertBudget(t, b.buffers, 0)
}
