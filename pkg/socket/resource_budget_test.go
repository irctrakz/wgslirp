package socket

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func assertBudget(t *testing.T, b *resourceBudget, want uint64) {
	t.Helper()
	used, peak, limit, _ := b.snapshot()
	if used != want || peak > limit {
		t.Fatalf("budget used=%d want=%d peak=%d limit=%d", used, want, peak, limit)
	}
}

func awaitBudgetWorker(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("worker failed to complete")
	}
}

func TestResourceBudgetConcurrentSaturation(t *testing.T) {
	budget := &resourceBudget{limit: 4096}
	var workers sync.WaitGroup
	for i := 0; i < 32; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 500; j++ {
				if budget.acquire(1024) {
					budget.release(1024)
				}
			}
		}()
	}
	workers.Wait()
	assertBudget(t, budget, 0)
	if budget.acquire(4097) {
		t.Fatal("oversized reservation accepted")
	}
	assertBudget(t, budget, 0)
}

func TestDialLimitIncludesFastAttemptsAndPreservesExistingFlow(t *testing.T) {
	b, f, _ := concurrentFlow(t)
	b.dialSlots.limit = 2
	started := make(chan struct{}, 2)
	b.dial = func(ctx context.Context, _ string, _ time.Duration) (*net.TCPConn, error) {
		started <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	var handlers sync.WaitGroup
	for port := uint16(40001); port < 40003; port++ {
		handlers.Add(1)
		go func(p uint16) {
			defer handlers.Done()
			_ = b.HandleOutbound(buildIPv4TCP(f.srcIP, f.dstIP, p, 80, 1, 0, 2, nil))
		}(port)
	}
	awaitBudgetWorker(t, started)
	awaitBudgetWorker(t, started)
	if err := b.HandleOutbound(buildIPv4TCP(f.srcIP, f.dstIP, 40003, 80, 1, 0, 2, nil)); !errors.Is(err, ErrDialLimit) {
		t.Fatalf("admission: %v", err)
	}
	assertBudget(t, b.dialSlots, 2)
	assertAdmission(t, b.parent, map[string]uint64{"pending_dial_limit": 1})
	if err := b.HandleOutbound(buildIPv4TCP(f.srcIP, f.dstIP, 40000, 80, 100, 1000, 0x10, nil)); err != nil {
		t.Fatalf("existing flow blocked: %v", err)
	}
	stopped := make(chan struct{})
	go func() { b.stop(); handlers.Wait(); close(stopped) }()
	awaitBudgetWorker(t, stopped)
	assertBudget(t, b.dialSlots, 0)
	assertBudget(t, b.buffers, 0)
}

func TestDialReservationTransfersToFallbackAndCancelsOnRST(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxPendingTCPDials = 1
	parent := NewSocketInterface(cfg)
	parent.processor = &captureProcessor{}
	b := newTCPBridge(parent)
	defer b.stop()
	started := make(chan struct{}, 1)
	b.dial = func(ctx context.Context, _ string, timeout time.Duration) (*net.TCPConn, error) {
		if timeout < time.Second {
			return nil, &net.DNSError{IsTimeout: true}
		}
		started <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	src, dst := [4]byte{10, 0, 0, 2}, [4]byte{127, 0, 0, 1}
	if err := b.HandleOutbound(buildIPv4TCP(src, dst, 40000, 80, 1, 0, 2, nil)); err != nil {
		t.Fatal(err)
	}
	awaitBudgetWorker(t, started)
	assertBudget(t, b.dialSlots, 1)
	if err := b.HandleOutbound(buildIPv4TCP(src, dst, 40001, 80, 1, 0, 2, nil)); !errors.Is(err, ErrDialLimit) {
		t.Fatalf("fallback lost reservation: %v", err)
	}
	if err := b.HandleOutbound(buildIPv4TCP(src, dst, 40000, 80, 2, 0, 4, nil)); err != nil {
		t.Fatal(err)
	}
	b.stop()
	assertBudget(t, b.dialSlots, 0)
	assertBudget(t, b.buffers, 0)
}

func TestDialHardFailureReleasesReservation(t *testing.T) {
	b, f, _ := concurrentFlow(t)
	b.dial = func(context.Context, string, time.Duration) (*net.TCPConn, error) { return nil, errors.New("refused") }
	for i := 0; i < 5; i++ {
		_ = b.HandleOutbound(buildIPv4TCP(f.srcIP, f.dstIP, 40001, 80, 1, 0, 2, nil))
		assertBudget(t, b.dialSlots, 0)
	}
}

func TestDuplicateSuccessfulDialsReleaseBothReservations(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	parent := NewSocketInterface(DefaultConfig())
	parent.processor = &captureProcessor{}
	b := newTCPBridge(parent)
	defer b.stop()
	started, gate := make(chan struct{}, 2), make(chan struct{})
	b.dial = func(ctx context.Context, address string, _ time.Duration) (*net.TCPConn, error) {
		started <- struct{}{}
		select {
		case <-gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return dialTCP(ctx, address, time.Second)
	}
	pkt := buildIPv4TCP([4]byte{10, 0, 0, 2}, [4]byte{127, 0, 0, 1}, 40000, uint16(listener.Addr().(*net.TCPAddr).Port), 1, 0, 2, nil)
	var workers sync.WaitGroup
	for i := 0; i < 2; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if err := b.HandleOutbound(pkt); err != nil {
				t.Errorf("dial failed: %v", err)
			}
		}()
	}
	awaitBudgetWorker(t, started)
	awaitBudgetWorker(t, started)
	assertBudget(t, b.dialSlots, 2)
	close(gate)
	workers.Wait()
	if len(b.flowSnapshot()) != 1 {
		t.Fatal("duplicate flow admitted")
	}
	assertBudget(t, b.dialSlots, 0)
	b.stop()
	assertBudget(t, b.buffers, 0)
}

func TestAggregateSendExhaustionDoesNotDiscardOtherFlow(t *testing.T) {
	b, first, _ := concurrentFlow(t)
	b.buffers.limit = bufferCharge(4)
	second := &tcpFlow{key: "other", state: tcpEstablished, serverNxt: 1000, sndUna: 1000, clientMSS: 600, advWnd: 1200, rtoStop: make(chan struct{}), ackCh: make(chan struct{}, 1)}
	b.mu.Lock()
	b.flows[second.key] = second
	b.mu.Unlock()
	if !b.sendPayload(first, []byte("held")) {
		t.Fatal("first send failed")
	}
	if b.sendPayload(second, []byte("drop")) {
		t.Fatal("aggregate cap ignored")
	}
	assertBudget(t, b.buffers, uint64(bufferCharge(4)))
	first.stateMu.Lock()
	intact := !first.closed && first.txBytes == 4 && string(first.txQueue[0].data) == "held"
	first.stateMu.Unlock()
	if !intact {
		t.Fatal("exhaustion discarded unrelated flow")
	}
	if !second.closed {
		t.Fatal("affected flow left open after reset")
	}
	if err := b.HandleOutbound(buildIPv4TCP(first.srcIP, first.dstIP, 40000, 80, 100, 1004, 0x10, nil)); err != nil {
		t.Fatal(err)
	}
	assertBudget(t, b.buffers, 0)
	if !b.sendPayload(first, []byte("next")) {
		t.Fatal("existing flow did not recover capacity")
	}
	b.stop()
	assertBudget(t, b.buffers, 0)
}

func tcpBudgetPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	server, err := listener.AcceptTCP()
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close(); server.Close() })
	return client, server
}

func TestTCPQueueReservationsOverlapFlushACKAndTeardown(t *testing.T) {
	b, f, _ := concurrentFlow(t)
	b.buffers.limit = 4096
	b.reasmCap = 32
	f.pendCap = 16
	f.stateMu.Lock()
	if !b.queueFuture(f, 104, []byte("efgh")) {
		t.Fatal("initial queue failed")
	}
	if !b.queueFuture(f, 104, []byte("efgh")) {
		t.Fatal("duplicate queue failed")
	}
	assertBudget(t, b.buffers, uint64(bufferCharge(4)))
	if !b.queueFuture(f, 106, []byte("ghij")) {
		t.Fatal("overlap queue failed")
	}
	if f.futureBytes != 6 || len(f.ooo) != 1 || string(f.ooo[0].data) != "efghij" {
		t.Fatal("overlap accounting/data incorrect")
	}
	f.stateMu.Unlock()
	packet := buildIPv4TCP(f.srcIP, f.dstIP, 40000, 80, 100, 1000, 0x18, []byte("abcd"))
	if err := b.HandleOutbound(packet); err != nil {
		t.Fatal(err)
	}
	assertBudget(t, b.buffers, uint64(bufferCharge(6)+bufferCharge(4)))
	conn, server := tcpBudgetPair(t)
	f.stateMu.Lock()
	f.conn = conn
	b.flushPending(f)
	f.stateMu.Unlock()
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	data := make([]byte, 10)
	if _, err := io.ReadFull(server, data); err != nil || string(data) != "abcdefghij" {
		t.Fatalf("flushed %q: %v", data, err)
	}
	assertBudget(t, b.buffers, 0)
	if !b.sendPayload(f, []byte("reply")) {
		t.Fatal("reply failed")
	}
	assertBudget(t, b.buffers, uint64(bufferCharge(5)))
	if err := b.HandleOutbound(buildIPv4TCP(f.srcIP, f.dstIP, 40000, 80, 110, 1005, 0x10, nil)); err != nil {
		t.Fatal(err)
	}
	assertBudget(t, b.buffers, 0)
	f.stateMu.Lock()
	b.queueFuture(f, 120, []byte("held"))
	f.stateMu.Unlock()
	b.stop()
	assertBudget(t, b.buffers, 0)
}

func TestReassemblyRejectsBeforeAllocationAndKeepsOldData(t *testing.T) {
	b, f, _ := concurrentFlow(t)
	b.buffers.limit = bufferCharge(8)
	b.reasmCap = 8
	f.stateMu.Lock()
	if !b.queueFuture(f, 104, []byte("abcd")) {
		t.Fatal("queue failed")
	}
	if b.queueFuture(f, 106, []byte("cdef")) {
		t.Fatal("merge exceeded transient budget")
	}
	if b.queueFuture(f, 120, make([]byte, 9)) {
		t.Fatal("per-flow cap ignored")
	}
	if string(f.ooo[0].data) != "abcd" || f.futureBytes != 4 {
		t.Fatal("rejection changed buffered data")
	}
	f.stateMu.Unlock()
	assertBudget(t, b.buffers, uint64(bufferCharge(4)))
	b.stop()
	assertBudget(t, b.buffers, 0)
}

func TestRetransmissionCapBackpressuresUntilACK(t *testing.T) {
	b, f, capture := concurrentFlow(t)
	b.retransmitCap = 8
	done := make(chan struct{})
	b.launch(func() {
		if !b.sendPayload(f, []byte("abcdefghijkl")) {
			t.Error("send failed")
		}
		close(done)
	})
	awaitBudgetWorker(t, capture.changed)
	assertBudget(t, b.buffers, uint64(bufferCharge(8)))
	if err := b.HandleOutbound(buildIPv4TCP(f.srcIP, f.dstIP, 40000, 80, 100, 1008, 0x10, nil)); err != nil {
		t.Fatal(err)
	}
	awaitBudgetWorker(t, done)
	assertBudget(t, b.buffers, uint64(bufferCharge(4)))
	b.stop()
	assertBudget(t, b.buffers, 0)
}

func TestUDPAndTCPShareBufferBudget(t *testing.T) {
	b, f, _ := concurrentFlow(t)
	b.buffers.limit = 65535
	udp := newUDPBridge(b.parent)
	defer udp.stop()
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	pkt := buildIPv4UDP(f.srcIP, f.dstIP, 40000, uint16(listener.LocalAddr().(*net.UDPAddr).Port), []byte("hello"))
	f.stateMu.Lock()
	b.queueFuture(f, 120, []byte("held"))
	f.stateMu.Unlock()
	if err := udp.HandleOutbound(pkt); !errors.Is(err, ErrBufferLimit) {
		t.Fatalf("UDP did not share TCP budget: %v", err)
	}
	b.removeFlow(f.key)
	assertBudget(t, b.buffers, 0)
	if err := udp.HandleOutbound(pkt); err != nil {
		t.Fatal(err)
	}
	assertBudget(t, b.buffers, 65535)
	udp.stop()
	assertBudget(t, b.buffers, 0)
}

func TestPacketReservationsAreSharedFiniteAndReleaseOnce(t *testing.T) {
	s := NewSocketInterface(Config{SocketBufferCapBytes: 300})
	budget := PacketBufferBudgetFor(s)
	first, err := budget.ReservePacketBuffer(20)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.ReservePacketBuffer(20)
	if err != nil {
		t.Fatal(err)
	}
	assertBudget(t, s.buffers(), 296)
	for _, bytes := range []int{20, -1, int(^uint(0) >> 1)} {
		if release, err := budget.ReservePacketBuffer(bytes); !errors.Is(err, ErrBufferLimit) || release != nil {
			t.Fatalf("invalid/saturated request %d accepted: %v", bytes, err)
		}
	}
	var workers sync.WaitGroup
	for i := 0; i < 16; i++ {
		workers.Add(1)
		go func() { defer workers.Done(); first(); second() }()
	}
	workers.Wait()
	assertBudget(t, s.buffers(), 0)
	fallback := PacketBufferBudgetFor(nil)
	if _, err := fallback.ReservePacketBuffer(DefaultSocketBufferCap); !errors.Is(err, ErrBufferLimit) {
		t.Fatal("fallback was not finite")
	}
}
