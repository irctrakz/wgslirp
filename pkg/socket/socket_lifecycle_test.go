package socket

import (
	"github.com/irctrakz/wgslirp/pkg/core"
	"net"
	"sync"
	"testing"
	"time"
)

func TestSocketConcurrentTrafficMetricsAndStop(t *testing.T) {
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
	packet := core.NewPacket(buildIPv4UDP([4]byte{10, 0, 0, 2}, [4]byte{127, 0, 0, 1}, 40000, uint16(listener.LocalAddr().(*net.UDPAddr).Port), []byte("hello")))
	if err := s.WritePacket(packet); err != nil {
		t.Fatal(err)
	}
	if s.DetailedMetrics().UDP.ActiveFlows != 1 {
		t.Fatal("expected live UDP flow")
	}
	var workers sync.WaitGroup
	gate := make(chan struct{})
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-gate
			for j := 0; j < 30; j++ {
				_ = s.WritePacket(packet)
				_ = s.DetailedMetrics()
			}
		}()
	}
	for i := 0; i < 4; i++ {
		workers.Add(1)
		go func() { defer workers.Done(); <-gate; _ = s.Stop() }()
	}
	close(gate)
	done := make(chan struct{})
	go func() { workers.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("concurrent shutdown stalled")
	}
	if err := s.WritePacket(packet); err == nil {
		t.Fatal("write accepted after stop")
	}
	if err := s.Start(); err == nil {
		t.Fatal("restart accepted with closed lifecycle channels")
	}
	dm := s.DetailedMetrics()
	if dm.UDP.ActiveFlows != 0 || dm.UDP.Counters.ConnectionsCreated != dm.UDP.Counters.ConnectionsClosed {
		t.Fatalf("leaked flows: %+v", dm.UDP)
	}
}

func TestSocketStopBeforeStart(t *testing.T) {
	s := NewSocketInterface(Config{Protocol: "ip4:udp", MTU: 1500})
	if err := s.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := s.Stop(); err != nil {
		t.Fatal(err)
	}
	s.SetPacketProcessor(&captureProcessor{})
	if err := s.Start(); err == nil {
		t.Fatal("started stopped socket")
	}
}

func TestUDPRemovalPreservesReplacement(t *testing.T) {
	parent := NewSocketInterface(Config{})
	b := newUDPBridge(parent)
	defer b.stop()
	address := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	oldConn, err := net.DialUDP("udp4", nil, address)
	if err != nil {
		t.Fatal(err)
	}
	defer oldConn.Close()
	newConn, err := net.DialUDP("udp4", nil, address)
	if err != nil {
		t.Fatal(err)
	}
	old := &udpFlow{key: "same", conn: oldConn}
	replacement := &udpFlow{key: "same", conn: newConn}
	b.flowsMu.Lock()
	b.flows[replacement.key] = replacement
	b.flowsMu.Unlock()
	b.removeFlow(old)
	b.flowsMu.RLock()
	got := b.flows[replacement.key]
	b.flowsMu.RUnlock()
	if got != replacement {
		t.Fatal("removed replacement")
	}
	if err := newConn.SetReadDeadline(time.Now()); err != nil {
		t.Fatalf("closed replacement: %v", err)
	}
	b.removeFlow(replacement)
	b.removeFlow(replacement)
	if loadSocketMetrics(&b.metrics).ConnectionsClosed != 1 {
		t.Fatal("counted removal more than once")
	}
	b.stop()
	b.stop()
	if err := b.HandleOutbound(nil); err == nil {
		t.Fatal("accepted work after shutdown")
	}
}
