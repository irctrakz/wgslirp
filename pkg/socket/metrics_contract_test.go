package socket

import (
	"errors"
	"github.com/irctrakz/wgslirp/pkg/core"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSocketCountsFramesOnceWhileTCPCountsHostWrites(t *testing.T) {
	b, f, _ := concurrentFlow(t)
	s := b.parent
	s.running = true
	f.pendCap = b.defaultPendCap
	packet := buildIPv4TCP(f.srcIP, f.dstIP, f.srcPort, f.dstPort, 100, 1000, 0x18, []byte("data"))
	if err := s.WritePacket(core.NewCopiedPacket(packet)); err != nil {
		t.Fatal(err)
	}
	m := s.DetailedMetrics()
	if m.Total.PacketsSent != 1 || m.Total.BytesSent != 44 || m.TCP.Counters.PacketsSent != 0 {
		t.Fatal(m)
	}
	conn, _ := tcpBudgetPair(t)
	f.stateMu.Lock()
	f.conn = conn
	b.flushPending(f)
	f.stateMu.Unlock()
	m = s.DetailedMetrics()
	if m.Total.PacketsSent != 1 || m.Total.BytesSent != 44 || m.TCP.Counters.PacketsSent != 1 || m.TCP.Counters.BytesSent != 4 {
		t.Fatal(m)
	}
	conn.Close()
	packet = buildIPv4TCP(f.srcIP, f.dstIP, f.srcPort, f.dstPort, 104, 1000, 0x18, []byte("lost"))
	if err := s.WritePacket(core.NewCopiedPacket(packet)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("cause lost: %v", err)
	}
	m = s.DetailedMetrics()
	if m.Total.Errors != 1 || m.TCP.Counters.Errors != 1 || m.Total.PacketsSent != 1 {
		t.Fatal(m)
	}
}

func TestAsyncHostWriteFailureResetsOnceAndReleasesBuffers(t *testing.T) {
	for _, stage := range []string{"pending", "reassembly", "half-close"} {
		t.Run(stage, func(t *testing.T) {
			b, f, capture := concurrentFlow(t)
			conn, _ := tcpBudgetPair(t)
			conn.Close() // Deterministic host write/deadline/half-close failure.
			f.stateMu.Lock()
			defer f.stateMu.Unlock()
			f.conn = conn
			if stage == "pending" {
				f.pending = [][]byte{[]byte("first"), []byte("later")}
				f.pendingBytes = 10
				if !b.buffers.acquire(10 + 2*bufferEntryAllowance) {
					t.Fatal("pending reservation")
				}
			}
			if stage != "half-close" && !b.queueFuture(f, f.clientNxt, []byte("queued")) {
				t.Fatal("reassembly reservation")
			}
			f.finReceived = true
			b.flushPending(f)
			if !f.closed || f.hostWriteClosed || f.clientNxt != 100 {
				t.Fatal("failed write advanced stream or half-close")
			}
			if b.metrics.Errors != 1 || b.parent.metrics.Errors != 1 || b.metrics.PacketsSent != 0 || b.metrics.BytesSent != 0 || b.pendFlush != 0 || f.toSrvBytes != 0 || f.toSrvPkts != 0 || b.bufferDrops.Load() != 1 {
				t.Fatal("failed host operation changed counters")
			}
			packets := capture.snapshot()
			if len(packets) != 1 || packets[0][33] != fRST|fACK {
				t.Fatal("failure did not emit exactly one reset")
			}
			assertBudget(t, b.buffers, 0)
			if len(b.flowSnapshot()) != 0 {
				t.Fatal("failed flow remained registered")
			}
		})
	}
}

func TestUDPInjectedDialAndDeliveryCounters(t *testing.T) {
	s := NewSocketInterface(Config{Protocol: "ip4:udp", MTU: 1500})
	s.SetPacketProcessor(&captureProcessor{})
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	cause := errors.New("dial fixture")
	attempts := 0
	s.udp.dial = func(string, *net.UDPAddr, *net.UDPAddr) (*net.UDPConn, error) { attempts++; return nil, cause }
	packet := buildIPv4UDP([4]byte{10, 0, 0, 1}, [4]byte{127, 0, 0, 1}, 40000, 12345, []byte("data"))
	if err := s.WritePacket(core.NewCopiedPacket(packet)); !errors.Is(err, cause) {
		t.Fatal(err)
	}
	m := s.DetailedMetrics()
	if attempts != 1 || m.Total.Errors != 1 || m.UDP.Counters.Errors != 1 || m.Total.PacketsSent != 0 || m.UDP.ActiveFlows != 0 {
		t.Fatal(attempts, m)
	}
	// The generated ICMP refusal is one frame delivered by the UDP bridge.
	if m.Total.PacketsReceived != 1 || m.UDP.Counters.PacketsReceived != 1 || m.UDPExt["tx_enq"] != 1 || m.UDPExt["tx_proc"] != 1 {
		t.Fatal(m)
	}
	s.udp.deliver = func(p core.Packet) bool { core.ReleasePacket(p); return false }
	if err := s.WritePacket(core.NewCopiedPacket(packet)); !errors.Is(err, cause) {
		t.Fatal(err)
	}
	m = s.DetailedMetrics()
	if m.Total.Errors != 2 || m.UDP.Counters.Errors != 2 || m.Total.PacketsReceived != 1 || m.UDP.DeliveryRefused != 1 || m.UDPExt["tx_enq"] != 2 || m.UDPExt["tx_proc"] != 1 {
		t.Fatal(m)
	}
	other := NewSocketInterface(Config{Protocol: "ip4:udp", MTU: 1500})
	other.SetPacketProcessor(&captureProcessor{})
	if err := other.Start(); err != nil {
		t.Fatal(err)
	}
	defer other.Stop()
	if other.DetailedMetrics().UDPExt["tx_enq"] != 0 {
		t.Fatal("interfaces share UDP history")
	}
}

func TestBridgeConstructionAndExplicitMaintenanceLifecycle(t *testing.T) {
	parent := NewSocketInterface(DefaultConfig())
	tcp, udp := newTCPBridge(parent), newUDPBridge(parent)
	defer tcp.stop()
	defer udp.stop()
	// No sockets/flows or periodic work are required to configure collaborators.
	called := false
	udp.dial = func(string, *net.UDPAddr, *net.UDPAddr) (*net.UDPConn, error) {
		called = true
		return nil, errors.New("unexpected dial")
	}
	if called || len(tcp.flows) != 0 || len(udp.flows) != 0 {
		t.Fatal("constructor did work")
	}
	tcp.start()
	tcp.start()
	udp.start()
	udp.start()
	tcp.stop()
	udp.stop()
	tcp.start()
	udp.start() // stopped components cannot restart workers
}

func TestMetricResetAndSnapshotRaceSafe(t *testing.T) {
	var m Metrics
	var workers sync.WaitGroup
	for i := 0; i < 4; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 100; j++ {
				atomic.AddUint64(&m.PacketsSent, 1)
				_ = loadSocketMetrics(&m)
				ResetMetrics(&m)
			}
		}()
	}
	workers.Wait()
	ResetMetrics(&m)
	if got := loadSocketMetrics(&m); got != (Metrics{}) {
		t.Fatal(got)
	}
}

func TestWorkerCompletionAndErrorCause(t *testing.T) {
	cause := errors.New("writer failure")
	writer := &mockSocketWriter{writePacketFunc: func(core.Packet) error { return cause }}
	p := newSocketPacketProcessor(writer, ProcessorConfig{Workers: 1, QueueCapacity: 1})
	if err := p.processPacketInternal(core.NewCopiedPacket(make([]byte, 20))); !errors.Is(err, cause) {
		t.Fatal(err)
	}
	m := p.Metrics()
	if m["writeErrors"] != 1 || m["packetsDelivered"] != 0 || m["packetsProcessed"] != 0 {
		t.Fatal(m)
	}
	writer.writePacketFunc = func(core.Packet) error { return nil }
	if err := p.processPacketInternal(core.NewCopiedPacket(make([]byte, 20))); err != nil {
		t.Fatal(err)
	}
	if p.Metrics()["packetsDelivered"] != 1 {
		t.Fatal(p.Metrics())
	}
}

func TestEmptyUDPDatagramForwardedAndCounted(t *testing.T) {
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	s := NewSocketInterface(Config{Protocol: "ip4:udp", MTU: 1500})
	s.SetPacketProcessor(&captureProcessor{})
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	packet := buildIPv4UDP([4]byte{10, 0, 0, 2}, [4]byte{127, 0, 0, 1}, 40000, uint16(listener.LocalAddr().(*net.UDPAddr).Port), nil)
	if err := s.WritePacket(core.NewCopiedPacket(packet)); err != nil {
		t.Fatal(err)
	}
	_ = listener.SetReadDeadline(time.Now().Add(time.Second))
	if n, _, err := listener.ReadFromUDP(make([]byte, 1)); n != 0 || err != nil {
		t.Fatal(n, err)
	}
	m := s.DetailedMetrics()
	if m.Total.PacketsSent != 1 || m.Total.BytesSent != 28 || m.UDP.Counters.PacketsSent != 1 || m.UDP.Counters.BytesSent != 0 {
		t.Fatal(m)
	}
}
