//go:build integration

package socket

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/irctrakz/wgslirp/pkg/core"
)

// The fixture uses loopback peers and production SocketInterface/bridges plus
// SocketPacketProcessor. The bounded sink replaces only the guest, not transport.
// It never forces GC or changes the runtime memory limit.
type workloadSink struct {
	*SocketInterface
	replies map[uint16]chan []byte
}

func (w *workloadSink) WritePacket(p core.Packet) error {
	data := core.BorrowPacketData(p)
	ihl := int(data[0]&15) * 4
	port := binary.BigEndian.Uint16(data[ihl+2 : ihl+4])
	ch := w.replies[port]
	if ch == nil {
		return nil
	} // refused probe's RST
	cp := make([]byte, len(data))
	copy(cp, data)
	select {
	case ch <- cp:
		return nil
	default:
		return fmt.Errorf("bounded guest sink full")
	}
}

type workloadGuest struct {
	s            *SocketInterface
	replies      chan []byte
	port, remote uint16
	tcp          bool
	seq, ack     uint32
	udpGate      chan struct{}
}

var workloadClientIP = [4]byte{10, 0, 0, 2}
var workloadServerIP = [4]byte{127, 0, 0, 1}

func (g *workloadGuest) send(flags byte, payload []byte) error {
	var data []byte
	if g.tcp {
		data = buildIPv4TCP(workloadClientIP, workloadServerIP, g.port, g.remote, g.seq, g.ack, flags, payload)
	} else {
		data = buildIPv4UDP(workloadClientIP, workloadServerIP, g.port, g.remote, payload)
	}
	packet := core.NewPooledPacket(data, func(buf []byte) {
		if g.tcp && poolingEnabled() && pktShouldPut(buf) {
			pktPut(buf)
		}
	})
	defer core.ReleasePacket(packet)
	return g.s.WritePacket(packet)
}
func (g *workloadGuest) receive() ([]byte, error) {
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case p := <-g.replies:
		return p, nil
	case <-timer.C:
		return nil, fmt.Errorf("guest %d reply deadline", g.port)
	}
}
func (g *workloadGuest) handshake() error {
	if err := g.send(2, nil); err != nil {
		return err
	}
	p, err := g.receive()
	if err != nil {
		return err
	}
	_, _, _, _, seq, _, flags, _ := parseTCP(p)
	if flags&0x12 != 0x12 {
		return fmt.Errorf("guest %d expected SYN-ACK", g.port)
	}
	g.seq++
	g.ack = seq + 1
	return g.send(0x10, nil)
}
func (g *workloadGuest) exchange(payload []byte) error {
	if !g.tcp && g.udpGate != nil {
		g.udpGate <- struct{}{}
		defer func() { <-g.udpGate }()
	}
	if err := g.send(0x18, payload); err != nil {
		return err
	}
	if !g.tcp {
		p, err := g.receive()
		if err != nil {
			return err
		}
		_, _, _, _, got, ok := parseIPv4UDP(p)
		if !ok || !bytes.Equal(got, payload) {
			return fmt.Errorf("UDP echo mismatch")
		}
		return nil
	}
	g.seq += uint32(len(payload))
	received := 0
	for attempts := 0; attempts < 32 && received < len(payload); attempts++ {
		p, err := g.receive()
		if err != nil {
			return err
		}
		_, _, _, _, seq, _, flags, data := parseTCP(p)
		if flags&4 != 0 {
			return fmt.Errorf("unexpected reset")
		}
		if len(data) == 0 {
			continue
		}
		if seq == g.ack {
			if received+len(data) > len(payload) || !bytes.Equal(data, payload[received:received+len(data)]) {
				return fmt.Errorf("TCP echo mismatch")
			}
			received += len(data)
			g.ack += uint32(len(data))
		}
		if err := g.send(0x10, nil); err != nil {
			return err
		}
	}
	if received != len(payload) {
		return fmt.Errorf("incomplete echo")
	}
	return nil
}

func workloadServers(t *testing.T) (uint16, uint16, func()) {
	t.Helper()
	tcp, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		tcp.Close()
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []*net.TCPConn
	var workers sync.WaitGroup
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, err := tcp.AcceptTCP()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(45 * time.Second))
				var buf [1024]byte
				for {
					n, err := conn.Read(buf[:])
					if err != nil {
						return
					}
					if _, err = conn.Write(buf[:n]); err != nil {
						return
					}
				}
			}()
		}
	}()
	udpDone := make(chan struct{})
	go func() {
		defer close(udpDone)
		var buf [2048]byte
		for {
			n, addr, err := udp.ReadFromUDP(buf[:])
			if err != nil {
				return
			}
			if _, err = udp.WriteToUDP(buf[:n], addr); err != nil {
				return
			}
		}
	}()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			tcp.Close()
			udp.Close()
			<-acceptDone
			mu.Lock()
			for _, c := range conns {
				c.Close()
			}
			mu.Unlock()
			workers.Wait()
			<-udpDone
		})
	}
	t.Cleanup(stop)
	return uint16(tcp.Addr().(*net.TCPAddr).Port), uint16(udp.LocalAddr().(*net.UDPAddr).Port), stop
}

func TestMixedTrafficMemoryRecovery(t *testing.T) {
	t.Setenv("PROCESSOR_QUEUE_CAP", "512")
	t.Setenv("PROCESSOR_WORKERS", "4")
	for _, profile := range []struct {
		name     string
		tcp, udp int
		pooled   bool
	}{{"small", 8, 32, false}, {"capacity", 64, 256, false}, {"capacity_repeat", 64, 256, false}, {"capacity_pooled", 64, 256, true}} {
		t.Run(profile.name, func(t *testing.T) {
			originalPool := poolPolicy.Load()
			t.Cleanup(func() { poolPolicy.Store(originalPool) })
			poolPolicy.Store(&PoolConfig{})
			if profile.pooled {
				poolPolicy.Store(&PoolConfig{Enabled: true})
			}
			tcpPort, udpPort, stopServers := workloadServers(t)
			cfg := DefaultConfig()
			cfg.Protocol = "ip4:tcp"
			cfg.TCPAckDelayMs = 0
			cfg.MaxTCPFlows = profile.tcp
			cfg.MaxUDPFlows = profile.udp
			s := NewSocketInterface(cfg)
			sink := &workloadSink{s, make(map[uint16]chan []byte)}
			guests := make([]*workloadGuest, 0, profile.tcp+profile.udp)
			udpGate := make(chan struct{}, 16)
			for i := 0; i < profile.tcp+profile.udp; i++ {
				isTCP := i < profile.tcp
				remote := udpPort
				if isTCP {
					remote = tcpPort
				}
				g := &workloadGuest{s: s, replies: make(chan []byte, 16), port: uint16(40000 + i), remote: remote, tcp: isTCP, seq: 1000, udpGate: udpGate}
				guests = append(guests, g)
				sink.replies[g.port] = g.replies
			}
			processor := NewSocketPacketProcessor(sink, 4).(*SocketPacketProcessor)
			if err := processor.Start(); err != nil {
				t.Fatal(err)
			}
			s.SetPacketProcessor(processor)
			if err := s.Start(); err != nil {
				processor.Stop()
				t.Fatal(err)
			}
			t.Cleanup(func() { s.Stop(); processor.Stop() })
			baseline, rssBefore := storageMemory()
			var before runtime.MemStats
			runtime.ReadMemStats(&before)
			payload := bytes.Repeat([]byte{0x5a}, 1024)
			for _, g := range guests {
				if g.tcp {
					if err := g.handshake(); err != nil {
						t.Fatal(err)
					}
				}
				if err := g.exchange(payload); err != nil {
					t.Fatal(err)
				}
			}
			// Flow caps refuse new peers while all admitted peers stay usable.
			for _, isTCP := range []bool{true, false} {
				remote := udpPort
				if isTCP {
					remote = tcpPort
				}
				probe := &workloadGuest{s: s, replies: make(chan []byte, 1), port: 60000, remote: remote, tcp: isTCP, seq: 1}
				if err := probe.send(2, payload); !errors.Is(err, ErrFlowLimit) {
					t.Fatalf("flow cap TCP=%v: %v", isTCP, err)
				}
			}
			for round := 0; round < 4; round++ {
				var workers sync.WaitGroup
				failures := make(chan error, len(guests))
				for _, g := range guests {
					workers.Add(1)
					go func(g *workloadGuest) {
						defer workers.Done()
						for i := 0; i < 16; i++ {
							if err := g.exchange(payload); err != nil {
								failures <- err
								return
							}
						}
					}(g)
				}
				workers.Wait()
				close(failures)
				for err := range failures {
					t.Fatal(err)
				}
				used, peak, limit, _ := s.buffers().snapshot()
				if used > limit || peak > limit {
					t.Fatal("budget exceeded")
				}
				heap, rss := storageMemory()
				t.Logf("round=%d clients=%d heap=%d rss=%q live=%d peak=%d limit=%d", round, len(guests), heap, rss, used, peak, limit)
			}
			// Exhaust otherwise-idle capacity, reject a synthesis, release it, then
			// prove established TCP and UDP sessions still carry payloads.
			// Queue workers may still be completing the last ACK; wait for stable live
			// reader storage rather than guessing a reservation amount.
			deadline := time.Now().Add(3 * time.Second)
			var release func()
			for time.Now().Before(deadline) {
				used, _, limit, _ := s.buffers().snapshot()
				release, _ = s.ReservePacketBuffer(int(limit-used) - 128)
				if release != nil {
					break
				}
				time.Sleep(time.Millisecond)
			}
			if release == nil {
				t.Fatal("could not reserve overload fixture")
			}
			if p := s.buffers().buildPacket(65535, false, func() []byte { return make([]byte, 65535) }); p != nil {
				core.ReleasePacket(p)
				t.Fatal("saturation not enforced")
			}
			release()
			for _, g := range guests {
				if err := g.exchange(payload); err != nil {
					t.Fatalf("post-overload recovery: %v", err)
				}
			}
			if err := s.Stop(); err != nil {
				t.Fatal(err)
			}
			processor.Stop()
			stopServers()
			assertBudget(t, s.buffers(), 0)
			if len(s.tcp.flowSnapshot()) != 0 || len(s.udp.flows) != 0 {
				t.Fatal("flows survived teardown")
			}
			for sample := 0; sample < 4; sample++ {
				if sample > 0 {
					time.Sleep(time.Second)
				}
				heap, rss := storageMemory()
				var after runtime.MemStats
				runtime.ReadMemStats(&after)
				t.Logf("idle=%ds heap_before=%d heap_now=%d rss_before=%q rss_now=%q natural_gc=%d stack_inuse=%d heap_inuse=%d reservations=0", sample, baseline, heap, rssBefore, rss, after.NumGC-before.NumGC, after.StackInuse, after.HeapInuse)
			}
		})
	}
}
