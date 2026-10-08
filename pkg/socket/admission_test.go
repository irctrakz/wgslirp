package socket

import (
	"encoding/binary"
	"errors"
	"github.com/irctrakz/wgslirp/pkg/core"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func assertAdmission(t *testing.T, s *SocketInterface, want map[string]uint64) {
	t.Helper()
	got := s.DetailedMetrics().Admission
	if len(got) != 9 {
		t.Fatalf("unstable admission keys: %v", got)
	}
	for key, value := range got {
		if value != want[key] {
			t.Errorf("%s=%d want=%d (%v)", key, value, want[key], got)
		}
	}
}

func TestFlowAdmissionSignalsAndCounters(t *testing.T) {
	b, f, capture := concurrentFlow(t)
	b.maxFlows = 1
	for i := 0; i < 3; i++ {
		err := b.HandleOutbound(buildIPv4TCP(f.srcIP, f.dstIP, uint16(41000+i), 80, 7, 0, 2, nil))
		if !errors.Is(err, ErrFlowLimit) {
			t.Fatal(err)
		}
	}
	assertAdmission(t, b.parent, map[string]uint64{"tcp_flow_limit": 3})
	for _, pkt := range capture.snapshot() {
		if pkt[33] != 0x14 || binary.BigEndian.Uint32(pkt[28:32]) != 8 {
			t.Fatal("expected RST/ACK for refused SYN")
		}
	}
	if len(capture.snapshot()) != 3 {
		t.Fatal("missing refusal response")
	}
	b.stop()
	assertAdmission(t, b.parent, map[string]uint64{"tcp_flow_limit": 3})

	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	cfg := DefaultConfig()
	cfg.MaxUDPFlows = 1
	s := NewSocketInterface(cfg)
	cp := &captureProcessor{}
	var rejectDelivery atomic.Bool
	s.processor = packetConsumer(func(p core.Packet) error {
		if rejectDelivery.Load() {
			return errors.New("delivery refused")
		}
		return cp.ProcessPacket(p)
	})
	udp := newUDPBridge(s)
	s.udp = udp
	defer udp.stop()
	packet := func(port uint16) []byte {
		return buildIPv4UDP([4]byte{10, 0, 0, 2}, [4]byte{127, 0, 0, 1}, port, uint16(listener.LocalAddr().(*net.UDPAddr).Port), []byte{1})
	}
	if err := udp.HandleOutbound(packet(40000)); err != nil {
		t.Fatal(err)
	}
	if err := udp.HandleOutbound(packet(40001)); !errors.Is(err, ErrFlowLimit) {
		t.Fatal(err)
	}
	if err := udp.HandleOutbound(packet(40000)); err != nil {
		t.Fatal("existing flow blocked", err)
	}
	assertAdmission(t, s, map[string]uint64{"udp_flow_limit": 1})
	replies := cp.snapshot()
	if len(replies) != 1 || replies[0][9] != 1 || replies[0][20] != 3 || replies[0][21] != 1 {
		t.Fatal("expected ICMP unreachable")
	}
	// Refusal replies must participate in aggregate admission too.
	used, _, limit, _ := s.buffers().snapshot()
	held := int(limit - used)
	if !s.buffers().acquire(held) {
		t.Fatal("fixture reservation")
	}
	if err := udp.HandleOutbound(packet(40002)); !errors.Is(err, ErrFlowLimit) {
		t.Fatal(err)
	}
	s.buffers().release(held)
	assertAdmission(t, s, map[string]uint64{"udp_flow_limit": 2, "aggregate_buffer_limit": 1})
	if len(cp.snapshot()) != 1 {
		t.Fatal("UDP refusal response bypassed the budget")
	}
	// Rejected delivery must release the synthesized ICMP reservation.
	rejectDelivery.Store(true)
	if err := udp.HandleOutbound(packet(40003)); !errors.Is(err, ErrFlowLimit) {
		t.Fatal(err)
	}
	assertBudget(t, s.buffers(), used)
	assertAdmission(t, s, map[string]uint64{"udp_flow_limit": 3, "aggregate_buffer_limit": 1})
}

func TestBufferAdmissionReasonsAreExclusive(t *testing.T) {
	b, f, _ := concurrentFlow(t)
	f.pendCap = 2
	b.reasmCap = 2
	// Per-flow refusal does not attempt an aggregate reservation.
	if b.reservePending(f, 3) || b.queueFuture(f, 110, []byte{1, 2, 3}) {
		t.Fatal("per-flow cap ignored")
	}
	assertAdmission(t, b.parent, map[string]uint64{"tcp_pending_limit": 1, "tcp_reassembly_limit": 1})
	if !b.queueFuture(f, 110, []byte{1, 2}) || !b.queueFuture(f, 110, []byte{1, 2}) {
		t.Fatal("duplicate should not need capacity")
	}
	assertAdmission(t, b.parent, map[string]uint64{"tcp_pending_limit": 1, "tcp_reassembly_limit": 1})
	used, _, limit, _ := b.buffers.snapshot()
	held := int(limit - used)
	if !b.buffers.acquire(held) {
		t.Fatal("fixture reservation")
	}
	if b.reservePending(f, 1) {
		t.Fatal("aggregate cap ignored")
	}
	// A replacement within the reassembly cap must reserve while old bytes live.
	b.reasmCap = 4
	if b.queueFuture(f, 112, []byte{3}) {
		t.Fatal("aggregate replacement cap ignored")
	}
	b.buffers.release(held)
	assertAdmission(t, b.parent, map[string]uint64{"tcp_pending_limit": 1, "tcp_reassembly_limit": 1, "aggregate_buffer_limit": 2})
	if !b.reservePending(f, 1) {
		t.Fatal("did not recover")
	}
	b.buffers.release(bufferCharge(1))
	b.stop()
	assertAdmission(t, b.parent, map[string]uint64{"tcp_pending_limit": 1, "tcp_reassembly_limit": 1, "aggregate_buffer_limit": 2})
}

func TestAggregateAdmissionConcurrentAndInvalidRequests(t *testing.T) {
	s := NewSocketInterface(DefaultConfig())
	release, err := s.ReservePacketBuffer(DefaultSocketBufferCap - bufferEntryAllowance)
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for i := 0; i < 32; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if _, err := s.ReservePacketBuffer(1); !errors.Is(err, ErrBufferLimit) {
				t.Error(err)
			}
			_ = s.DetailedMetrics()
		}()
	}
	workers.Wait()
	if _, err := s.ReservePacketBuffer(-1); !errors.Is(err, ErrBufferLimit) {
		t.Fatal(err)
	}
	assertAdmission(t, s, map[string]uint64{"aggregate_buffer_limit": 32, "invalid_buffer_request": 1})
	release()
	release()
	next, err := s.ReservePacketBuffer(1)
	if err != nil {
		t.Fatal(err)
	}
	next()
	snap := s.DetailedMetrics()
	snap.Admission["aggregate_buffer_limit"] = 999
	assertAdmission(t, s, map[string]uint64{"aggregate_buffer_limit": 32, "invalid_buffer_request": 1})
}

func TestRetransmitCapCountsWaitEpisodesNotPolls(t *testing.T) {
	b, f, _ := concurrentFlow(t)
	b.retransmitCap = 10
	f.txBytes = 10
	for i := 0; i < 100; i++ {
		if b.sendAllowanceLocked(f) != 0 {
			t.Fatal("cap did not gate")
		}
	}
	assertAdmission(t, b.parent, map[string]uint64{"tcp_retransmit_waits": 1})
	f.txBytes = 0
	if b.sendAllowanceLocked(f) != 10 {
		t.Fatal("cap did not recover")
	}
	f.txBytes = 10
	b.sendAllowanceLocked(f)
	assertAdmission(t, b.parent, map[string]uint64{"tcp_retransmit_waits": 2})
	// No tx payload was actually allocated in this fixture.
	f.txBytes = 0
}

func TestPendingRefusalDoesNotAcknowledgeDroppedBytes(t *testing.T) {
	b, f, cp := concurrentFlow(t)
	b.ackDelay = 0
	f.pendCap = 2
	if err := b.HandleOutbound(buildIPv4TCP(f.srcIP, f.dstIP, f.srcPort, f.dstPort, 100, 1000, 0x18, []byte{1, 2, 3})); err != nil {
		t.Fatal(err)
	}
	assertAdmission(t, b.parent, map[string]uint64{"tcp_pending_limit": 1})
	f.stateMu.Lock()
	nxt := f.clientNxt
	f.stateMu.Unlock()
	if nxt != 100 {
		t.Fatal("acknowledged refused data")
	}
	select {
	case <-cp.changed:
	case <-time.After(2 * time.Second):
		t.Fatal("ACK timeout")
	}
	packets := cp.snapshot()
	if len(packets) != 1 || binary.BigEndian.Uint32(packets[0][28:32]) != 100 {
		t.Fatal("missing ACK of accepted bytes only")
	}
}

func TestRefusalResponseAllocationIsASeparateAttempt(t *testing.T) {
	b, f, cp := concurrentFlow(t)
	b.maxFlows = 1
	_, _, limit, _ := b.buffers.snapshot()
	if !b.buffers.acquire(int(limit)) {
		t.Fatal("fixture reservation")
	}
	defer b.buffers.release(int(limit))
	err := b.HandleOutbound(buildIPv4TCP(f.srcIP, f.dstIP, 41000, 80, 1, 0, 2, nil))
	if !errors.Is(err, ErrFlowLimit) {
		t.Fatal(err)
	}
	assertAdmission(t, b.parent, map[string]uint64{"tcp_flow_limit": 1, "aggregate_buffer_limit": 1})
	if len(cp.snapshot()) != 0 {
		t.Fatal("response allocated beyond budget")
	}
}
