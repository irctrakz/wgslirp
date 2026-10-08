//go:build integration

package socket

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// Two full default-capacity batches use real host connections and production
// packet handling. Only the four-minute TIME-WAIT expiry clock is advanced.
func TestTCPDefaultCapacityChurnAndTimeWaitRecovery(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	cfg := DefaultConfig()
	cfg.Protocol = "ip4:tcp"
	cfg.TCPAckDelayMs = 0
	if cfg.MaxTCPFlows != 256 {
		t.Fatal("update the documented default sizing fixture")
	}
	s := NewSocketInterface(cfg)
	sink := &workloadSink{s, make(map[uint16]chan []byte)}
	guests := make([]*workloadGuest, 2*cfg.MaxTCPFlows)
	for i := range guests {
		g := &workloadGuest{s: s, replies: make(chan []byte, 16), port: uint16(40000 + i), remote: uint16(listener.Addr().(*net.TCPAddr).Port), tcp: true, seq: 100}
		guests[i] = g
		sink.replies[g.port] = g.replies
	}
	processor := NewSocketPacketProcessor(sink, 1).(*SocketPacketProcessor)
	if err := processor.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { processor.Stop() })
	s.SetPacketProcessor(processor)
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Stop() })
	for batch := 0; batch < 2; batch++ {
		for _, g := range guests[batch*cfg.MaxTCPFlows : (batch+1)*cfg.MaxTCPFlows] {
			func() {
				if err := g.handshake(); err != nil {
					t.Fatal(err)
				}
				_ = listener.SetDeadline(time.Now().Add(3 * time.Second))
				conn, err := listener.AcceptTCP()
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				payload := []byte("short response")
				if _, err := conn.Write(payload); err != nil {
					t.Fatal(err)
				}
				if err := conn.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				var got []byte
				fin := false
				for attempt := 0; attempt < 16 && !fin; attempt++ {
					p, err := g.receive()
					if err != nil {
						t.Fatal(err)
					}
					_, _, _, _, seq, _, flags, data := parseTCP(p)
					if flags&4 != 0 {
						t.Fatal("unexpected RST")
					}
					if seq == g.ack {
						got = append(got, data...)
						g.ack += uint32(len(data))
						if flags&1 != 0 {
							fin = true
							g.ack++
						}
					}
					if err := g.send(0x10, nil); err != nil {
						t.Fatal(err)
					}
				}
				if !fin || !bytes.Equal(got, payload) {
					t.Fatal("close lost response")
				}
				if err := g.send(0x11, nil); err != nil {
					t.Fatal(err)
				}
				var last [1]byte
				if n, err := conn.Read(last[:]); n != 0 || err != io.EOF {
					t.Fatalf("host descriptor not closed: %d %v", n, err)
				}
			}()
		}
		flows := s.tcp.flowSnapshot()
		if len(flows) != cfg.MaxTCPFlows {
			t.Fatalf("retained slots=%d", len(flows))
		}
		for _, f := range flows {
			f.stateMu.Lock()
			valid := f.state == tcpTimeWait && f.txBytes == 0 && f.pendingBytes == 0 && f.futureBytes == 0
			f.stateMu.Unlock()
			if !valid {
				t.Fatal("closed flow retained payload or wrong state")
			}
		}
		probe := &workloadGuest{s: s, port: 60000, remote: guests[0].remote, tcp: true, seq: 1}
		if err := probe.send(2, nil); !errors.Is(err, ErrFlowLimit) {
			t.Fatalf("TIME-WAIT capacity should refuse: %v", err)
		}
		for _, f := range flows {
			f.stateMu.Lock()
			s.tcp.closeTickLocked(f, f.timeWaitUntil.Add(-time.Nanosecond))
			if f.closed {
				f.stateMu.Unlock()
				t.Fatal("expired early")
			}
			s.tcp.closeTickLocked(f, f.timeWaitUntil)
			f.stateMu.Unlock()
		}
		if len(s.tcp.flowSnapshot()) != 0 {
			t.Fatal("expiry did not restore admission")
		}
	}
	s.Stop()
	processor.Stop()
	assertBudget(t, s.buffers(), 0)
	t.Logf("%d short TCP connections completed; each %d-flow TIME-WAIT batch refused overflow and recovered at simulated expiry", len(guests), cfg.MaxTCPFlows)
}
