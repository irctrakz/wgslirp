//go:build integration && linux
// +build integration,linux

package socket

import (
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/irctrakz/wgslirp/pkg/core"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type packetChannelCapture struct {
	once sync.Once
	ch   chan []byte
}

func (c *packetChannelCapture) ProcessPacket(p core.Packet) error {
	data := append([]byte(nil), p.Data()...)
	c.once.Do(func() { c.ch <- data })
	return nil
}

func TestICMPDatagramIntegration_EchoLoopback(t *testing.T) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_ICMP)
	if err != nil {
		t.Skipf("ICMP datagram socket unavailable; check ping_group_range: %v", err)
	}

	s := &SocketInterface{
		config:           Config{IPAddress: "10.0.0.5", MTU: 1500},
		dgramFd:          fd,
		dgramEchoPending: make(map[string][]pendingDgramEcho),
		running:          true,
		stopCh:           make(chan struct{}),
	}
	capture := &packetChannelCapture{ch: make(chan []byte, 1)}
	s.processor = capture

	if err := syscall.Bind(fd, &syscall.SockaddrInet4{}); err != nil {
		syscall.Close(fd)
		t.Skipf("cannot bind ICMP datagram socket: %v", err)
	}
	s.wg.Add(1)
	go s.dgramListenLoop()
	defer s.Stop()

	payload := []byte("wgslirp-dgram-echo")
	requestBody, err := (&icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{ID: 0x1234, Seq: 7, Data: payload},
	}).Marshal(nil)
	if err != nil {
		t.Fatalf("marshal echo request: %v", err)
	}

	request := buildIPv4ICMP(net.IPv4(10, 0, 0, 5).To4(), net.IPv4(127, 0, 0, 1).To4(), requestBody)
	if err := s.WritePacket(core.NewPacket(request)); err != nil {
		t.Fatalf("write echo request: %v", err)
	}

	var reply []byte
	select {
	case reply = <-capture.ch:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for datagram ICMP echo reply")
	}

	if !net.IP(reply[12:16]).Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("reply source = %v, want 127.0.0.1", net.IP(reply[12:16]))
	}
	if !net.IP(reply[16:20]).Equal(net.IPv4(10, 0, 0, 5)) {
		t.Fatalf("reply destination = %v, want 10.0.0.5", net.IP(reply[16:20]))
	}

	got, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), reply[20:])
	if err != nil {
		t.Fatalf("parse echo reply: %v", err)
	}
	if got.Type != ipv4.ICMPTypeEchoReply {
		t.Fatalf("reply type = %v, want %v", got.Type, ipv4.ICMPTypeEchoReply)
	}
	echo, ok := got.Body.(*icmp.Echo)
	if !ok {
		t.Fatalf("reply body = %T, want *icmp.Echo", got.Body)
	}
	if echo.ID != 0x1234 || echo.Seq != 7 || string(echo.Data) != string(payload) {
		t.Fatalf("reply echo = id %#x seq %d data %q", echo.ID, echo.Seq, echo.Data)
	}
}
