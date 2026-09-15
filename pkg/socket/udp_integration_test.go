//go:build integration
// +build integration

package socket

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func parseIPv4UDP(pkt []byte) (src, dst net.IP, sport, dport uint16, payload []byte, ok bool) {
	if len(pkt) < 28 || pkt[0]>>4 != 4 {
		return nil, nil, 0, 0, nil, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl+8 {
		return nil, nil, 0, 0, nil, false
	}
	src = net.IP(pkt[12:16])
	dst = net.IP(pkt[16:20])
	off := ihl
	sport = binary.BigEndian.Uint16(pkt[off : off+2])
	dport = binary.BigEndian.Uint16(pkt[off+2 : off+4])
	payload = pkt[off+8:]
	return src, dst, sport, dport, payload, true
}

// TestUDPIntegration_Echo ensures UDP slirp bridge carries real traffic to a local UDP server.
func TestUDPIntegration_Echo(t *testing.T) {
	// Start local UDP echo server
	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Skipf("cannot listen locally: %v", err)
	}
	defer srv.Close()

	// Echo goroutine
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65535)
		for {
			_ = srv.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, addr, err := srv.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n > 0 {
				srv.WriteToUDP(buf[:n], addr)
			}
		}
	}()

	// Bridge and capture setup
	s := &SocketInterface{}
	cap := &localCapture{}
	s.processor = cap
	s.udp = newUDPBridge(s)
	defer s.udp.stop()

	// Guest/Server addressing
	var cliIP, srvIP [4]byte
	copy(cliIP[:], net.IPv4(10, 0, 0, 5).To4())
	copy(srvIP[:], srv.LocalAddr().(*net.UDPAddr).IP.To4())
	cliPort := uint16(53000)
	srvPort := uint16(srv.LocalAddr().(*net.UDPAddr).Port)

	// Build guest outbound IPv4+UDP packet
	payload := []byte("udp-hello")
	out := buildIPv4UDP(cliIP, srvIP, cliPort, srvPort, payload)
	if err := s.udp.HandleOutbound(out); err != nil {
		t.Fatalf("udp outbound: %v", err)
	}

	// Wait for response packet synthesized by bridge
	deadline := time.Now().Add(2 * time.Second)
	var got []byte
	for time.Now().Before(deadline) {
		for _, p := range cap.snapshot() {
			_, _, sp, dp, pl, ok := parseIPv4UDP(p)
			if ok && sp == srvPort && dp == cliPort && len(pl) > 0 {
				got = pl
				break
			}
		}
		if got != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if string(got) != string(payload) {
		t.Fatalf("udp echo mismatch: %q != %q", string(got), string(payload))
	}

	// Verify metrics
	dm := s.DetailedMetrics()
	if dm.UDP.Counters.ConnectionsCreated < 1 {
		t.Fatalf("expected UDP ConnectionsCreated >=1, got %d", dm.UDP.Counters.ConnectionsCreated)
	}
	if dm.UDP.Counters.PacketsSent < 1 || dm.UDP.Counters.PacketsReceived < 1 {
		t.Fatalf("expected UDP packets sent/received >=1, got %d/%d", dm.UDP.Counters.PacketsSent, dm.UDP.Counters.PacketsReceived)
	}
	if dm.UDP.ActiveFlows != 1 {
		t.Fatalf("expected 1 active UDP flow, got %d", dm.UDP.ActiveFlows)
	}

	<-done
}
