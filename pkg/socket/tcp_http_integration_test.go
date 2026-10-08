//go:build integration
// +build integration

package socket

import (
	"net"
	"testing"
	"time"
)

// Simple HTTP over the TCP slirp bridge: start a local TCP server that replies
// with a fixed HTTP response, then synthesize a GET from the guest and verify
// we receive an HTTP response payload back.
func TestTCPIntegration_HTTP(t *testing.T) {
	// Start local TCP HTTP-like server
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
		// Read request (best-effort)
		buf := make([]byte, 2048)
		_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		_, _ = conn.Read(buf)
		// Write minimal HTTP response
		resp := "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nHELLO"
		_, _ = conn.Write([]byte(resp))
		conn.Close()
	}()

	// Setup bridge and capture
	s := &SocketInterface{}
	cap := &captureProcessor{}
	s.processor = cap
	s.tcp = newTCPBridge(s)
	defer s.tcp.stop()

	// Guest/Server addressing
	var cliIP, srvIP [4]byte
	copy(cliIP[:], net.IPv4(10, 0, 0, 3).To4())
	srv := ln.Addr().(*net.TCPAddr)
	copy(srvIP[:], srv.IP.To4())
	cliPort := uint16(41000)
	srvPort := uint16(srv.Port)

	// Handshake
	cseq := uint32(2000)
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

	// Send HTTP GET
	req := []byte("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
	data := buildIPv4TCP(cliIP, srvIP, cliPort, srvPort, cseq+1, sseq+1, 0x18, req)
	if err := s.tcp.HandleOutbound(data); err != nil {
		t.Fatal(err)
	}

	// Wait and accumulate server->client payloads
	deadline := time.Now().Add(2 * time.Second)
	var resp []byte
	for time.Now().Before(deadline) {
		for i := range cap.snapshot() {
			_, _, sp, dp, _, _, f, pl := parseTCP(cap.snapshot()[i])
			if sp == srvPort && dp == cliPort && (f&0x18) == 0x18 && len(pl) > 0 {
				resp = append(resp, pl...)
			}
		}
		if len(resp) >= 16 && string(resp[:8]) == "HTTP/1.1" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(resp) == 0 || string(resp[:8]) != "HTTP/1.1" {
		t.Fatalf("did not receive HTTP response, got %q", string(resp))
	}

	<-done
	finishTCPIntegrationClose(t, s.tcp, cap, cliIP, srvIP, cliPort, srvPort, cseq+1+uint32(len(req)), false)

	// Verify metrics: one connection created and closed, traffic both ways
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
}
