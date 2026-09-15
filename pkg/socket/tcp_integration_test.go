//go:build integration
// +build integration

package socket

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func parseTCP(pkt []byte) (src net.IP, dst net.IP, sport, dport uint16, seq, ack uint32, flags byte, payload []byte) {
	ihl := int(pkt[0]&0x0f) * 4
	src = net.IP(pkt[12:16])
	dst = net.IP(pkt[16:20])
	off := ihl
	sport = binary.BigEndian.Uint16(pkt[off : off+2])
	dport = binary.BigEndian.Uint16(pkt[off+2 : off+4])
	seq = binary.BigEndian.Uint32(pkt[off+4 : off+8])
	ack = binary.BigEndian.Uint32(pkt[off+8 : off+12])
	dataOff := int((pkt[off+12] >> 4) * 4)
	flags = pkt[off+13]
	payload = pkt[off+dataOff:]
	return
}

// Test a simple end-to-end TCP flow against a local echo server using the slirp bridge.
func TestTCPIntegration_Echo(t *testing.T) {
	// Start local echo server
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Skipf("cannot listen locally: %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.AcceptTCP()
		if err != nil {
			return
		}
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		if n > 0 {
			conn.Write(buf[:n])
		}
		conn.Close()
	}()

	// Prepare bridge and processor
	s := &SocketInterface{}
	proc := &captureProcessor{}
	s.processor = proc
	s.tcp = newTCPBridge(s)
	defer s.tcp.stop()

	// Construct client/server addressing
	var cliIP, srvIP [4]byte
	copy(cliIP[:], net.IPv4(10, 0, 0, 2).To4())
	port := uint16(40000)
	srv := ln.Addr().(*net.TCPAddr)
	copy(srvIP[:], srv.IP.To4())
	srvPort := uint16(srv.Port)

	// 1) Client SYN
	cseq := uint32(1000)
	syn := buildIPv4TCP(cliIP, srvIP, port, srvPort, cseq, 0, 0x02, nil)
	if err := s.tcp.HandleOutbound(syn); err != nil {
		t.Fatalf("syn outbound: %v", err)
	}

	// Expect SYN-ACK
	time.Sleep(50 * time.Millisecond)
	if len(proc.snapshot()) == 0 {
		t.Fatalf("no packets captured after SYN")
	}
	_, _, _, _, sseq, _, flags, _ := parseTCP(proc.snapshot()[0])
	if flags&0x12 != 0x12 { // SYN|ACK
		t.Fatalf("expected SYN|ACK, got flags=0x%02x", flags)
	}

	// 2) Client ACK to complete handshake
	ack := buildIPv4TCP(cliIP, srvIP, port, srvPort, cseq+1, sseq+1, 0x10, nil)
	if err := s.tcp.HandleOutbound(ack); err != nil {
		t.Fatalf("ack outbound: %v", err)
	}

	// 3) Client sends data
	payload := []byte("hello slirp")
	data := buildIPv4TCP(cliIP, srvIP, port, srvPort, cseq+1, sseq+1, 0x18, payload) // PSH|ACK
	if err := s.tcp.HandleOutbound(data); err != nil {
		t.Fatalf("data outbound: %v", err)
	}

	// Wait for echo response synthesized back
	deadline := time.Now().Add(2 * time.Second)
	var got []byte
	for time.Now().Before(deadline) {
		if len(proc.snapshot()) >= 2 { // SYN-ACK + ACK or data
			// Search for data segment from server
			for _, p := range proc.snapshot() {
				_, _, sp, dp, _, _, f, pl := parseTCP(p)
				if sp == srvPort && dp == port && (f&0x18) == 0x18 && len(pl) > 0 {
					got = pl
					break
				}
			}
			if got != nil {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo mismatch: %q != %q", string(got), string(payload))
	}

	// 4) Client FIN
	fin := buildIPv4TCP(cliIP, srvIP, port, srvPort, cseq+1+uint32(len(payload)), sseq+1+uint32(len(payload)), 0x11, nil) // FIN|ACK
	if err := s.tcp.HandleOutbound(fin); err != nil {
		t.Fatalf("fin outbound: %v", err)
	}

	// Allow server goroutine to exit
	<-done
	waitTCPClosed(t, s.tcp)

	// Verify metrics: one TCP connection created and closed, packets both ways
	dm := s.DetailedMetrics()
	if dm.TCP.Counters.ConnectionsCreated < 1 {
		t.Fatalf("expected TCP ConnectionsCreated >=1, got %d", dm.TCP.Counters.ConnectionsCreated)
	}
	if dm.TCP.Counters.ConnectionsClosed < 1 {
		t.Fatalf("expected TCP ConnectionsClosed >=1, got %d", dm.TCP.Counters.ConnectionsClosed)
	}
	if dm.TCP.Counters.PacketsSent < 1 || dm.TCP.Counters.PacketsReceived < 1 {
		t.Fatalf("expected TCP packets sent/received >=1, got %d/%d", dm.TCP.Counters.PacketsSent, dm.TCP.Counters.PacketsReceived)
	}
	if dm.TCP.ActiveFlows != 0 {
		t.Fatalf("expected no active TCP flows, got %d", dm.TCP.ActiveFlows)
	}
}

// Verify out-of-order reassembly by sending the second segment first.
func TestTCPIntegration_OutOfOrder(t *testing.T) {
	// Start local echo server that captures bytes received
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Skipf("cannot listen locally: %v", err)
	}
	defer ln.Close()

	recvCh := make(chan []byte, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.AcceptTCP()
		if err != nil {
			return
		}
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		var total []byte
		for {
			buf := make([]byte, 4096)
			n, err := conn.Read(buf)
			if n > 0 {
				total = append(total, buf[:n]...)
				// extend deadline to allow subsequent pieces
				_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
				continue
			}
			if err != nil {
				break
			}
		}
		if len(total) > 0 {
			recvCh <- total
			conn.Write(total) // echo
		}
		conn.Close()
	}()

	s := &SocketInterface{}
	cap := &captureProcessor{}
	s.processor = cap
	s.tcp = newTCPBridge(s)
	defer s.tcp.stop()

	// Addressing
	var cliIP, srvIP [4]byte
	copy(cliIP[:], net.IPv4(10, 0, 0, 4).To4())
	srv := ln.Addr().(*net.TCPAddr)
	copy(srvIP[:], srv.IP.To4())
	cliPort := uint16(42000)
	srvPort := uint16(srv.Port)

	// Handshake
	cseq := uint32(3000)
	syn := buildIPv4TCP(cliIP, srvIP, cliPort, srvPort, cseq, 0, 0x02, nil)
	if err := s.tcp.HandleOutbound(syn); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	if len(cap.snapshot()) == 0 {
		t.Fatal("no syn-ack")
	}
	_, _, _, _, sseq, _, _, _ := parseTCP(cap.snapshot()[len(cap.snapshot())-1])
	ack := buildIPv4TCP(cliIP, srvIP, cliPort, srvPort, cseq+1, sseq+1, 0x10, nil)
	if err := s.tcp.HandleOutbound(ack); err != nil {
		t.Fatal(err)
	}

	// Prepare two parts, send second first (out-of-order)
	part1 := []byte("ABC")
	part2 := []byte("DEF")
	// Send second segment first with higher seq
	seg2 := buildIPv4TCP(cliIP, srvIP, cliPort, srvPort, cseq+1+uint32(len(part1)), sseq+1, 0x18, part2)
	if err := s.tcp.HandleOutbound(seg2); err != nil {
		t.Fatal(err)
	}

	// Small wait; server should not receive yet due to buffering
	select {
	case b := <-recvCh:
		t.Fatalf("server received prematurely: %q", string(b))
	case <-time.After(50 * time.Millisecond):
		// expected timeout
	}

	// Now send the first segment
	seg1 := buildIPv4TCP(cliIP, srvIP, cliPort, srvPort, cseq+1, sseq+1, 0x18, part1)
	if err := s.tcp.HandleOutbound(seg1); err != nil {
		t.Fatal(err)
	}

	// Server should receive concatenated data in order (may arrive in pieces but accumulated)
	var got []byte
	select {
	case got = <-recvCh:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout waiting for server data")
	}
	if string(got) != "ABCDEF" {
		t.Fatalf("reassembly wrong, got %q", string(got))
	}

	// Ensure a response flows back
	deadline := time.Now().Add(1 * time.Second)
	var echoed []byte
	for time.Now().Before(deadline) {
		for _, p := range cap.snapshot() {
			_, _, sp, dp, _, _, f, pl := parseTCP(p)
			if sp == srvPort && dp == cliPort && (f&0x18) == 0x18 && len(pl) > 0 {
				echoed = pl
			}
		}
		if len(echoed) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if string(echoed) != "ABCDEF" {
		t.Fatalf("echoed payload mismatch: %q", string(echoed))
	}

	<-done
}
