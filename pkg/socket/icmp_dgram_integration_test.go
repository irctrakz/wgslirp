//go:build integration && linux
// +build integration,linux

package socket

import (
	"context"
	"net"
	"os"
	"sync"
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
	defer core.ReleasePacket(p)
	data := append([]byte(nil), p.Data()...)
	c.once.Do(func() { c.ch <- data })
	return nil
}

func TestICMPDatagramIntegration_EchoLoopback(t *testing.T) {
	testICMPDatagramEcho(t, false)
}

func TestICMPDatagramIntegration_TCPUDPEcho(t *testing.T) {
	testICMPDatagramEcho(t, true)
}

func testICMPDatagramEcho(t *testing.T, echoOnly bool) {
	required := os.Getenv("WGSLIRP_REQUIRE_ICMP_DGRAM") == "1"
	if raw, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0"); err == nil {
		raw.Close()
		if required {
			t.Fatal("test must run without raw socket privileges")
		}
		if !echoOnly {
			t.Skip("run with all capabilities dropped to exercise startup fallback")
		}
	}
	cfg := Config{IPAddress: "10.0.0.5", MTU: 1500, Protocol: "ip4:icmp"}
	if echoOnly {
		cfg.Protocol = "ip4:tcp"
		cfg.ICMPEcho = true
	}
	s := NewSocketInterface(cfg)
	capture := &packetChannelCapture{ch: make(chan []byte, 1)}
	s.SetPacketProcessor(capture)
	if err := s.Start(); err != nil {
		if required {
			t.Fatal(err)
		}
		t.Skipf("ICMP datagram socket unavailable; check ping_group_range: %v", err)
	}
	t.Cleanup(func() { _ = s.Stop() })
	if s.conn != nil || s.dgram == nil {
		t.Fatal("startup did not select ping socket")
	}

	payload := []byte("wgslirp-dgram-echo")
	requestBody, err := (&icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{ID: 0x1234, Seq: 7, Data: payload},
	}).Marshal(nil)
	if err != nil {
		t.Fatalf("marshal echo request: %v", err)
	}

	request := buildIPv4ICMP(net.IPv4(10, 0, 0, 5).To4(), net.IPv4(127, 0, 0, 1).To4(), requestBody)
	packet := core.NewCopiedPacket(request)
	defer core.ReleasePacket(packet)
	if err := s.WritePacket(packet); err != nil {
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
	if calculateChecksum(reply[:20]) != 0 || calculateChecksum(reply[20:]) != 0 {
		t.Fatal("invalid reply checksum")
	}
	// Writes, metrics snapshots and repeated stop requests share the production
	// lifecycle. Stop must unblock the ping reader and drain every reservation.
	var workers sync.WaitGroup
	gate := make(chan struct{})
	for i := 0; i < 4; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-gate
			for j := 0; j < 16; j++ {
				_ = s.WritePacket(packet)
				_ = s.DetailedMetrics()
			}
		}()
	}
	close(gate)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.StopContext(ctx); err != nil {
		t.Fatal(err)
	}
	workers.Wait()
	if err := s.StopContext(ctx); err != nil {
		t.Fatal(err)
	}
	assertBudget(t, s.buffers(), 0)
	t.Log("ICMP_DGRAM_VERIFIED: startup fallback, guest identity, checksums, concurrent stop, zero reservations")

}
