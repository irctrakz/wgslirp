package socket

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/irctrakz/wgslirp/pkg/core"
	"io"
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
			repairTestChecksums(p)
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

// repairTestChecksums deliberately preserves malformed lengths/offsets so a
// boundary fixture reaches its intended rejection after checksum validation.
func repairTestChecksums(p []byte) {
	if len(p) < 20 {
		return
	}
	ihl, total := int(p[0]&15)*4, int(binary.BigEndian.Uint16(p[2:4]))
	if ihl < 20 || ihl > len(p) {
		return
	}
	p[10], p[11] = 0, 0
	binary.BigEndian.PutUint16(p[10:12], calculateChecksum(p[:ihl]))
	if total < ihl || total > len(p) {
		return
	}
	body := p[ihl:total]
	var src, dst [4]byte
	copy(src[:], p[12:16])
	copy(dst[:], p[16:20])
	switch p[9] {
	case 6:
		if len(body) < 20 {
			return
		}
		body[16], body[17] = 0, 0
		binary.BigEndian.PutUint16(body[16:18], tcpChecksum(body, src, dst))
	case 17:
		if len(body) < 8 {
			return
		}
		body[6], body[7] = 0, 0
		sum := udpChecksum(body, src, dst)
		if sum == 0 {
			sum = 0xffff
		}
		binary.BigEndian.PutUint16(body[6:8], sum)
	case 1:
		if len(body) < 8 {
			return
		}
		body[2], body[3] = 0, 0
		binary.BigEndian.PutUint16(body[2:4], calculateChecksum(body))
	}
}

func packetWithIPOptions(p, options []byte) []byte {
	out := append([]byte(nil), p[:20]...)
	out = append(out, options...)
	out = append(out, p[20:]...)
	out[0] = 0x40 | byte((20+len(options))/4)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	repairTestChecksums(out)
	return out
}

func validationPackets() [][]byte {
	src, dst := [4]byte{10, 0, 0, 2}, [4]byte{127, 0, 0, 1}
	icmp := buildIPv4UDP(src, dst, 40000, 9, []byte("odd"))
	icmp[9] = 1
	copy(icmp[20:28], []byte{8, 0, 0, 0, 0, 1, 0, 1})
	repairTestChecksums(icmp)
	return [][]byte{icmp, buildIPv4TCPOpts(src, dst, 40000, 9, 1, 0, 2, []byte("odd"), []byte{2, 4, 5, 180}), buildIPv4UDP(src, dst, 40000, 9, []byte("odd"))}
}

func TestChecksumAndIPPolicyBeforeSideEffects(t *testing.T) {
	s := NewSocketInterface(Config{Protocol: "ip4:udp", MTU: 1500})
	c := &captureProcessor{}
	s.SetPacketProcessor(c)
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	for _, base := range validationPackets() {
		for _, tc := range []struct {
			name string
			edit func([]byte) []byte
			want error
		}{
			{"IP checksum", func(p []byte) []byte { p[8] ^= 1; return p }, ErrInvalidChecksum},
			{"transport checksum", func(p []byte) []byte { p[len(p)-1] ^= 1; return p }, ErrInvalidChecksum},
			{"source pseudoheader", func(p []byte) []byte {
				// ICMP has no pseudoheader: change its body instead.
				if p[9] == 1 {
					p[24] ^= 1
				} else {
					p[12] ^= 1
				}
				p[10], p[11] = 0, 0
				binary.BigEndian.PutUint16(p[10:12], calculateChecksum(p[:20]))
				return p
			}, ErrInvalidChecksum},
			{"padding options", func(p []byte) []byte { return packetWithIPOptions(p, []byte{0, 0, 0, 0}) }, ErrUnsupportedIPOptions},
			{"source route", func(p []byte) []byte { return packetWithIPOptions(p, []byte{131, 3, 4, 0}) }, ErrUnsupportedIPOptions},
			{"malformed option", func(p []byte) []byte { return packetWithIPOptions(p, []byte{7, 255, 0, 0}) }, ErrUnsupportedIPOptions},
			{"first fragment", func(p []byte) []byte { p[6] = 0x20; repairTestChecksums(p); return p }, ErrUnsupportedFragment},
			{"later fragment", func(p []byte) []byte { p[7] = 1; repairTestChecksums(p); return p }, ErrUnsupportedFragment},
		} {
			t.Run(fmt.Sprintf("%d/%s", base[9], tc.name), func(t *testing.T) {
				p := tc.edit(append([]byte(nil), base...))
				before := append([]byte(nil), p...)
				if err := s.WritePacket(core.NewPacket(p)); !errors.Is(err, tc.want) {
					t.Fatalf("socket: %v", err)
				}
				var err error
				switch base[9] {
				case 1:
					err = s.icmp.HandleOutbound(p)
				case 6:
					err = s.tcp.HandleOutbound(p)
				case 17:
					err = s.udp.HandleOutbound(p)
				}
				if !errors.Is(err, tc.want) {
					t.Fatalf("direct bridge: %v", err)
				}
				if !bytes.Equal(p, before) {
					t.Fatal("input mutated")
				}
			})
		}
	}
	if s.DetailedMetrics().TCP.ActiveFlows != 0 || s.DetailedMetrics().UDP.ActiveFlows != 0 || len(c.snapshot()) != 0 {
		t.Fatal("rejected packets caused network response or flow creation")
	}
	assertBudget(t, s.buffers(), 0)
}

func TestTransportChecksumAcceptance(t *testing.T) {
	for _, p := range validationPackets() {
		original := append([]byte(nil), p...)
		p[6] = 0x40 // DF alone is supported
		repairTestChecksums(p)
		original = append([]byte(nil), p...)
		p = append(p, 1, 2, 3) // padding is outside both checksums
		if _, _, err := parseTransport(p, p[9]); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(p[:len(original)], original) {
			t.Fatal("input mutated")
		}
	}
	udp := validationPackets()[2]
	udp[26], udp[27] = 0, 0 // IPv4 UDP checksum omission is valid
	udp[len(udp)-1] ^= 1
	if _, _, err := parseTransport(udp, 17); err != nil {
		t.Fatal(err)
	}
	tcp := validationPackets()[1]
	tcp[36], tcp[37] = 0, 0
	if _, _, err := parseTransport(tcp, 6); !errors.Is(err, ErrInvalidChecksum) || !errors.Is(err, ErrMalformedPacket) {
		t.Fatalf("TCP checksum skipped: %v", err)
	}
	// A computed zero UDP checksum is transmitted as all ones.
	udp = buildIPv4UDP([4]byte{}, [4]byte{}, 0, 0, []byte{0xff, 0xda})
	if binary.BigEndian.Uint16(udp[26:28]) != 0xffff {
		t.Fatal("computed zero was encoded as checksum omission")
	}
	if _, _, err := parseTransport(udp, 17); err != nil {
		t.Fatalf("all-ones UDP checksum: %v", err)
	}
}

func TestTCPWrapReassemblyRefusalAndInOrderRecovery(t *testing.T) {
	b, f, c := concurrentFlow(t)
	conn, peer := tcpBudgetPair(t)
	f.conn = conn
	f.clientNxt = ^uint32(0) - 3
	next := f.clientNxt
	for _, seq := range []uint32{^uint32(0) - 1, 1} {
		closeOutbound(t, b, f, seq, 1000, 0x18, []byte("xyz"))
		if f.clientNxt != next || f.futureBytes != 0 || len(f.ooo) != 0 {
			t.Fatal("unsupported future bytes retained or acknowledged")
		}
		assertBudget(t, b.buffers, 0)
		packets := c.snapshot()
		if binary.BigEndian.Uint32(packets[len(packets)-1][28:32]) != next {
			t.Fatal("advanced cumulative ACK")
		}
	}
	// A pre-wrap queued segment becomes obsolete when an in-order segment
	// crosses zero. It must be released rather than block later reassembly.
	closeOutbound(t, b, f, next+1, 1000, 0x18, []byte("bc"))
	assertBudget(t, b.buffers, uint64(bufferCharge(2)))
	closeOutbound(t, b, f, next, 1000, 0x18, []byte("abcdef"))
	if f.clientNxt != 2 || len(f.ooo) != 0 {
		t.Fatal("in-order wrap did not drain obsolete queue")
	}
	closeOutbound(t, b, f, 4, 1000, 0x18, []byte("ij"))
	closeOutbound(t, b, f, 2, 1000, 0x18, []byte("gh"))
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	got := make([]byte, 10)
	if _, err := io.ReadFull(peer, got); err != nil || string(got) != "abcdefghij" {
		t.Fatalf("delivered %q: %v", got, err)
	}
	// A delayed ACK temporarily reserves its synthesized packet. Observe state
	// and accounting under the same lock as that worker, not mid-delivery.
	f.stateMu.Lock()
	defer f.stateMu.Unlock()
	if f.clientNxt != 6 {
		t.Fatal("wrong final ACK")
	}
	assertBudget(t, b.buffers, 0)
}

func FuzzTransportBoundaries(f *testing.F) {
	f.Add([]byte{})
	for _, p := range validationPackets() {
		f.Add(p)
		f.Add(packetWithIPOptions(p, []byte{1, 1, 0, 0}))
		fragment := append([]byte(nil), p...)
		fragment[6] = 0x20
		repairTestChecksums(fragment)
		f.Add(fragment)
	}
	f.Fuzz(func(t *testing.T, p []byte) {
		// Raw bytes exercise corruption. Repaired copies also reach deeper length
		// and policy checks instead of virtually always failing the IP checksum.
		fixed := append([]byte(nil), p...)
		repairTestChecksums(fixed)
		for _, candidate := range [][]byte{p, fixed} {
			before := append([]byte(nil), candidate...)
			for _, protocol := range []byte{1, 6, 17} {
				datagram, ihl, err := parseTransport(candidate, protocol)
				if !bytes.Equal(candidate, before) {
					t.Fatal("parser mutated input")
				}
				if err != nil {
					continue
				}
				if ihl != 20 || len(datagram) > len(candidate) || len(datagram) != int(binary.BigEndian.Uint16(candidate[2:4])) || binary.BigEndian.Uint16(datagram[6:8])&0xbfff != 0 || calculateChecksum(datagram[:ihl]) != 0 {
					t.Fatal("invalid accepted IP boundary")
				}
				body := datagram[ihl:]
				var src, dst [4]byte
				copy(src[:], datagram[12:16])
				copy(dst[:], datagram[16:20])
				switch protocol {
				case 1:
					if len(body) < 8 || calculateChecksum(body) != 0 {
						t.Fatal("invalid ICMP")
					}
				case 6:
					if len(body) < 20 || int(body[12]>>4)*4 < 20 || int(body[12]>>4)*4 > len(body) || tcpChecksum(body, src, dst) != 0 {
						t.Fatal("invalid TCP")
					}
				case 17:
					if len(body) < 8 || int(binary.BigEndian.Uint16(body[4:6])) != len(body) || (binary.BigEndian.Uint16(body[6:8]) != 0 && udpChecksum(body, src, dst) != 0) {
						t.Fatal("invalid UDP")
					}
				}
			}
		}
	})
}
