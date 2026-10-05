package socket

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/irctrakz/wgslirp/pkg/core"
	"github.com/irctrakz/wgslirp/pkg/logging"
	"github.com/sirupsen/logrus"
)

func TestAcceptedOversizedPackets(t *testing.T) {
	logger := logging.WithFields(nil).Logger
	output, level := logger.Out, logger.Level
	defer func() { logger.SetOutput(output); logger.SetLevel(level) }()
	var logs bytes.Buffer
	logger.SetOutput(&logs)
	logger.SetLevel(logrus.WarnLevel)
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	s := NewSocketInterface(Config{Protocol: "ip4:tcp", MTU: 1200, MaxUDPFlows: 1, IPv4Reassembly: true})
	s.SetPacketProcessor(&captureProcessor{})
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	packet := func(size int, source uint16) []byte {
		return buildIPv4UDP([4]byte{10, 0, 0, 2}, [4]byte{127, 0, 0, 1}, source, uint16(listener.LocalAddr().(*net.UDPAddr).Port), bytes.Repeat([]byte{0x5a}, size))
	}
	checkDelivery := func(payload int) {
		t.Helper()
		listener.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 2048)
		n, _, err := listener.ReadFromUDP(buf)
		if err != nil || !bytes.Equal(buf[:n], bytes.Repeat([]byte{0x5a}, payload)) {
			t.Fatalf("UDP delivery: size=%d err=%v", n, err)
		}
	}
	if err := s.WritePacket(core.NewPacket(packet(1200, 40000))); err != nil {
		t.Fatal(err)
	}
	checkDelivery(1200)
	// Input padding exceeds MTU, but the declared IP packet fits exactly.
	if err := s.WritePacket(core.NewPacket(append(packet(1172, 40000), make([]byte, 28)...))); err != nil {
		t.Fatal(err)
	}
	checkDelivery(1172)
	if err := s.WritePacket(core.NewPacket(packet(1200, 40001))); !errors.Is(err, ErrFlowLimit) {
		t.Fatal(err)
	}
	bad := packet(1200, 40000)
	bad[10] ^= 1
	if err := s.WritePacket(core.NewPacket(bad)); !errors.Is(err, ErrInvalidChecksum) {
		t.Fatal(err)
	}
	if got := s.DetailedMetrics().PacketSize["accepted_oversized"]; got != 1 {
		t.Fatalf("accepted count=%d", got)
	}
	// Count accepted original fragments, not the larger reassembled datagram.
	whole := packet(1600, 40000)
	for _, p := range [][]byte{fragmentFixture(17, 42, 0, true, whole[20:1228]), fragmentFixture(17, 42, 1208, false, whole[1228:])} {
		if err := s.WritePacket(core.NewPacket(p)); err != nil {
			t.Fatal(err)
		}
	}
	checkDelivery(1600)
	if got := s.DetailedMetrics().PacketSize["accepted_oversized"]; got != 2 {
		t.Fatalf("fragment count=%d", got)
	}
	if strings.Contains(logs.String(), "MTU") {
		t.Fatalf("accepted packet warned: %s", logs.String())
	}
	logger.SetLevel(logrus.DebugLevel)
	if err := s.WritePacket(core.NewPacket(packet(1200, 40000))); err != nil {
		t.Fatal(err)
	}
	checkDelivery(1200)
	if !strings.Contains(logs.String(), "Guest packet accepted above configured MTU") {
		t.Fatal("optional debug missing")
	}
}

func TestLocalSizeRejectionReason(t *testing.T) {
	s := NewSocketInterface(Config{MTU: 1200})
	cause := &net.OpError{Op: "write", Net: "udp", Err: fmt.Errorf("host: %w", syscall.EMSGSIZE)}
	err := s.outboundPacketError("UDP", 1228, cause)
	if !errors.Is(err, syscall.EMSGSIZE) || !strings.Contains(err.Error(), "guest_frame_bytes=1228") || !strings.Contains(err.Error(), "reduce datagram size or check host path MTU") {
		t.Fatal(err)
	}
	other := s.outboundPacketError("UDP", 1228, net.ErrClosed)
	if !errors.Is(other, net.ErrClosed) || strings.Contains(other.Error(), "MTU") {
		t.Fatal(other)
	}
	m := s.DetailedMetrics()
	if m.PacketSize["accepted_oversized"] != 0 || m.PacketSize["local_size_rejected"] != 1 || m.Total.Errors != 2 {
		t.Fatal(m)
	}
}
