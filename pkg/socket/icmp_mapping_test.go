package socket

import (
	"net"
	"testing"
	"time"
)

// Test that TCP dial failure maps to ICMP host unreachable to the client.
func TestICMPMapping_TCPDialFailure(t *testing.T) {
	// Find an unused local port by listening and closing
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Skipf("cannot allocate port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	s := &SocketInterface{}
	cap := &captureProcessor{}
	s.processor = cap
	s.tcp = newTCPBridge(s)
	defer s.tcp.stop()

	var cli, dst [4]byte
	copy(cli[:], net.IPv4(10, 0, 0, 9).To4())
	copy(dst[:], net.IPv4(127, 0, 0, 1).To4())

	// Send SYN to closed port; expect ICMP unreachable back
	syn := buildIPv4TCP(cli, dst, 50000, uint16(port), 100, 0, 0x02, nil)
	_ = s.tcp.HandleOutbound(syn)

	// Wait for ICMP
	deadline := time.Now().Add(500 * time.Millisecond)
	var got []byte
	for time.Now().Before(deadline) {
		if len(cap.snapshot()) > 0 {
			got = cap.snapshot()[len(cap.snapshot())-1]
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(got) < 28 || got[9] != 1 || got[20] != 3 || got[21] != 1 {
		t.Fatalf("expected ICMP dest unreachable code 1, got len=%d proto=%d type=%d code=%d", len(got), got[9], got[20], got[21])
	}
}

// Test that UDP dial failure maps to ICMP port unreachable to the client.
func TestICMPMapping_UDPDialFailure(t *testing.T) {
	s := &SocketInterface{}
	cap := &localCapture{}
	s.processor = cap
	s.udp = newUDPBridge(s)
	defer s.udp.stop()

	var cli, badDst [4]byte
	copy(cli[:], net.IPv4(10, 0, 0, 10).To4())
	// 0.0.0.0 as remote is invalid for DialUDP and should fail
	copy(badDst[:], net.IPv4(0, 0, 0, 0).To4())

	pkt := buildIPv4UDP(cli, badDst, 53001, 9, []byte("x"))
	_ = s.udp.HandleOutbound(pkt)

	// Wait for ICMP
	deadline := time.Now().Add(500 * time.Millisecond)
	var got []byte
	for time.Now().Before(deadline) {
		if len(cap.snapshot()) > 0 {
			got = cap.snapshot()[len(cap.snapshot())-1]
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(got) < 28 || got[9] != 1 || got[20] != 3 {
		t.Fatalf("expected ICMP dest unreachable, got len=%d proto=%d type=%d code=%d", len(got), got[9], got[20], got[21])
	}
}
