package socket

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBridgeResourceConfiguration(t *testing.T) {
	t.Setenv("TCP_ACK_DELAY_MS", "999") // typed configuration is authoritative
	cfg := DefaultConfig()
	if cfg.MaxTCPFlows != 256 || cfg.MaxUDPFlows != 512 {
		t.Fatalf("unexpected default flow limits: TCP=%d UDP=%d", cfg.MaxTCPFlows, cfg.MaxUDPFlows)
	}
	cfg.TCPAckDelayMs = 7
	cfg.TCPFlowLifetimeSec = 31
	cfg.UDPFlowLifetimeSec = 17
	cfg.TCPReassemblyCapBytes = 4096
	cfg.MaxTCPFlows = 2
	cfg.MaxUDPFlows = 3
	parent := NewSocketInterface(cfg)
	tcp := newTCPBridge(parent)
	defer tcp.stop()
	udp := newUDPBridge(parent)
	defer udp.stop()
	if tcp.ackDelay != 7*time.Millisecond || tcp.lifetime != 31*time.Second || tcp.reasmCap != 4096 || tcp.maxFlows != 2 || udp.lifetime != 17*time.Second || udp.maxFlows != 3 {
		t.Fatal("bridge ignored typed resource configuration")
	}
	t.Setenv("TCP_ACK_DELAY_MS", "1")
	if tcp.ackDelay != 7*time.Millisecond {
		t.Fatal("environment mutated existing configuration")
	}
}

func TestInvalidResourceConfigFailsBeforeStartup(t *testing.T) {
	s := NewSocketInterface(Config{Protocol: "ip4:icmp", MaxTCPFlows: -1})
	s.SetPacketProcessor(&captureProcessor{})
	if err := s.Start(); err == nil {
		t.Fatal("accepted negative cap")
	}
	if s.conn != nil || s.tcp != nil || s.udp != nil {
		t.Fatal("created resources before validation")
	}
	cfg := DefaultConfig()
	cfg.TCPFlowLifetimeSec = int(^uint(0) >> 1)
	if cfg.Validate() == nil && uint64(cfg.TCPFlowLifetimeSec) > uint64((1<<63-1)/int64(time.Second)) {
		t.Fatal("accepted duration overflow")
	}
}

func TestConcurrentTCPAdmissionHonorsCap(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	// Keep accepted connections open until the test completes.
	done := make(chan struct{})
	var accepted sync.WaitGroup
	accepted.Add(1)
	go func() {
		defer accepted.Done()
		var conns []net.Conn
		defer func() {
			for _, c := range conns {
				c.Close()
			}
		}()
		for {
			c, err := listener.Accept()
			if err != nil {
				<-done
				return
			}
			conns = append(conns, c)
		}
	}()
	defer func() { close(done); listener.Close(); accepted.Wait() }()
	cfg := DefaultConfig()
	cfg.MaxTCPFlows = 2
	parent := NewSocketInterface(cfg)
	parent.processor = &captureProcessor{}
	b := newTCPBridge(parent)
	defer b.stop()
	var workers sync.WaitGroup
	gate := make(chan struct{})
	var limited atomic.Int32
	for i := 0; i < 24; i++ {
		workers.Add(1)
		go func(port uint16) {
			defer workers.Done()
			<-gate
			pkt := buildIPv4TCP([4]byte{10, 0, 0, 2}, [4]byte{127, 0, 0, 1}, port, uint16(listener.Addr().(*net.TCPAddr).Port), 1, 0, 2, nil)
			if err := b.HandleOutbound(pkt); errors.Is(err, ErrFlowLimit) {
				limited.Add(1)
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		}(uint16(40000 + i))
	}
	close(gate)
	workers.Wait()
	if got := len(b.flowSnapshot()); got != 2 {
		t.Fatalf("active=%d want=2", got)
	}
	assertAdmission(t, parent, map[string]uint64{"tcp_flow_limit": 22})
	if limited.Load() != 22 {
		t.Fatalf("refused=%d want=22", limited.Load())
	}
}
