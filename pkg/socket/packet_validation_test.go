package socket

import (
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/irctrakz/wgslirp/pkg/core"
	"net"
	"testing"
	"time"
)

func TestPacketBoundariesBeforeForwarding(t *testing.T) {
	s := NewSocketInterface(Config{Protocol: "ip4:udp", MTU: 1500})
	s.SetPacketProcessor(&captureProcessor{})
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	udp := buildIPv4UDP([4]byte{10, 0, 0, 2}, [4]byte{127, 0, 0, 1}, 40000, 9, []byte("payload"))
	tcp := buildIPv4TCP([4]byte{10, 0, 0, 2}, [4]byte{127, 0, 0, 1}, 40000, 9, 1, 0, 2, nil)
	tests := []struct {
		name string
		base []byte
		edit func([]byte) []byte
		want error
	}{
		{"short", udp, func(p []byte) []byte { return p[:19] }, ErrMalformedPacket},
		{"version", udp, func(p []byte) []byte { p[0] = 0x65; return p }, ErrMalformedPacket},
		{"small IHL", udp, func(p []byte) []byte { p[0] = 0x44; return p }, ErrMalformedPacket},
		{"IHL exceeds total", udp, func(p []byte) []byte { p[0] = 0x4f; return p }, ErrMalformedPacket},
		{"truncated IP", udp, func(p []byte) []byte { return p[:len(p)-1] }, ErrMalformedPacket},
		{"short total", udp, func(p []byte) []byte { binary.BigEndian.PutUint16(p[2:4], 19); return p }, ErrMalformedPacket},
		{"first fragment", udp, func(p []byte) []byte { p[6] = 0x20; return p }, ErrUnsupportedFragment},
		{"later fragment", udp, func(p []byte) []byte { p[7] = 1; return p }, ErrUnsupportedFragment},
		{"reserved flag", udp, func(p []byte) []byte { p[6] = 0x80; return p }, ErrMalformedPacket},
		{"short UDP", udp, func(p []byte) []byte { binary.BigEndian.PutUint16(p[24:26], 7); return p }, ErrMalformedPacket},
		{"long UDP", udp, func(p []byte) []byte { binary.BigEndian.PutUint16(p[24:26], 65535); return p }, ErrMalformedPacket},
		{"missing UDP", udp, func(p []byte) []byte { binary.BigEndian.PutUint16(p[2:4], 24); return p }, ErrMalformedPacket},
		{"short TCP offset", tcp, func(p []byte) []byte { p[32] = 0x40; return p }, ErrMalformedPacket},
		{"long TCP offset", tcp, func(p []byte) []byte { p[32] = 0xf0; return p }, ErrMalformedPacket},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.edit(append([]byte(nil), tc.base...))
			// Test the public boundary and direct bridge entry points.
			if err := s.WritePacket(core.NewPacket(p)); !errors.Is(err, tc.want) {
				t.Fatalf("socket: %v", err)
			}
			var err error
			if tc.base[9] == 17 {
				err = s.udp.HandleOutbound(p)
			} else {
				err = s.tcp.HandleOutbound(p)
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("bridge: %v", err)
			}
		})
	}
	if s.DetailedMetrics().UDP.ActiveFlows != 0 || s.DetailedMetrics().TCP.ActiveFlows != 0 {
		t.Fatal("malformed input created flows")
	}
	if err := s.tcp.HandleOutbound(udp); !errors.Is(err, ErrMalformedPacket) {
		t.Fatalf("wrong protocol: %v", err)
	}
	if err := s.icmp.HandleOutbound(udp); !errors.Is(err, ErrMalformedPacket) {
		t.Fatalf("wrong ICMP protocol: %v", err)
	}
}

func TestUDPForwardingIgnoresIPPadding(t *testing.T) {
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	s := NewSocketInterface(Config{Protocol: "ip4:udp", MTU: 1500})
	s.SetPacketProcessor(&captureProcessor{})
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	payload := []byte("only this payload")
	pkt := buildIPv4UDP([4]byte{10, 0, 0, 2}, [4]byte{127, 0, 0, 1}, 40000, uint16(listener.LocalAddr().(*net.UDPAddr).Port), payload)
	pkt = append(pkt, []byte("padding must not be forwarded")...)
	if err := s.WritePacket(core.NewPacket(pkt)); err != nil {
		t.Fatal(err)
	}
	_ = listener.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 128)
	n, _, err := listener.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("forwarded %q", buf[:n])
	}
}

func FuzzTransportBoundaries(f *testing.F) {
	f.Add([]byte{})
	f.Add(buildIPv4UDP([4]byte{10, 0, 0, 2}, [4]byte{127, 0, 0, 1}, 40000, 9, []byte("payload")))
	f.Add(buildIPv4TCP([4]byte{10, 0, 0, 2}, [4]byte{127, 0, 0, 1}, 40000, 9, 1, 0, 2, nil))
	f.Fuzz(func(t *testing.T, p []byte) {
		for _, protocol := range []byte{1, 6, 17} {
			datagram, ihl, err := parseTransport(p, protocol)
			if err != nil {
				continue
			}
			if ihl < 20 || ihl > len(datagram) || len(datagram) > len(p) || len(datagram) != int(binary.BigEndian.Uint16(p[2:4])) {
				t.Fatal("invalid accepted bounds")
			}
		}
	})
}
