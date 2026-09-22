//go:build integration

package wireguard

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/irctrakz/wgslirp/pkg/core"
	"github.com/irctrakz/wgslirp/pkg/socket"
)

type encryptedGuestSink chan []byte

func (s encryptedGuestSink) WritePacket(p core.Packet) error {
	data := append([]byte(nil), core.BorrowPacketData(p)...)
	select {
	case s <- data:
		return nil
	default:
		return fmt.Errorf("guest queue full")
	}
}

func encryptedKey(t *testing.T) (string, string) {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(k.Bytes()), base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())
}

// Independent small guest packet encoder; no kernel TUN, raw sockets or root.
func encryptedPacket(proto byte, port uint16, seq, ack uint32, flags byte, data []byte) []byte {
	h := 8
	if proto == 6 {
		h = 20
	}
	p := make([]byte, 20+h+len(data))
	p[0], p[8], p[9] = 0x45, 64, proto
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	copy(p[12:16], []byte{10, 0, 0, 2})
	copy(p[16:20], []byte{127, 0, 0, 1})
	binary.BigEndian.PutUint16(p[20:22], 40000)
	binary.BigEndian.PutUint16(p[22:24], port)
	if proto == 6 {
		binary.BigEndian.PutUint32(p[24:28], seq)
		binary.BigEndian.PutUint32(p[28:32], ack)
		p[32], p[33] = 0x50, flags
		binary.BigEndian.PutUint16(p[34:36], 4096)
	} else {
		binary.BigEndian.PutUint16(p[24:26], uint16(h+len(data)))
	}
	copy(p[20+h:], data)
	binary.BigEndian.PutUint16(p[10:12], encryptedChecksum(p[:20]))
	pseudo := append([]byte(nil), p[12:20]...)
	pseudo = append(pseudo, 0, proto, byte((h+len(data))>>8), byte(h+len(data)))
	pseudo = append(pseudo, p[20:]...)
	checksum := encryptedChecksum(pseudo)
	if proto == 17 && checksum == 0 {
		checksum = 0xffff
	}
	off := 36
	if proto == 17 {
		off = 26
	}
	binary.BigEndian.PutUint16(p[off:off+2], checksum)
	return p
}

func encryptedChecksum(p []byte) uint16 {
	var sum uint32
	for len(p) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(p[:2]))
		p = p[2:]
	}
	if len(p) == 1 {
		sum += uint32(p[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func encryptedTestLink(t *testing.T, endpoint func(int) string) (*socket.SocketInterface, *WGTun, encryptedGuestSink) {
	t.Helper()
	serverPrivate, serverPublic := encryptedKey(t)
	guestPrivate, guestPublic := encryptedKey(t)
	cfg := socket.DefaultConfig()
	cfg.Protocol = "ip4:tcp"
	cfg.MTU = 1380
	cfg.TCPAckDelayMs = 0
	s := socket.NewSocketInterface(cfg)
	serverTun, err := NewWGTunWithConfig("encrypted-server", 1380, s, DefaultTunConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { serverTun.Close() })
	s.SetPacketProcessor(NewWGPacketProcessor(serverTun))
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Stop() })
	server, err := StartDevice(DeviceConfig{Options: &DeviceOptions{}, PrivateKey: serverPrivate, MTU: 1380,
		Peers: []PeerConfig{{PublicKey: guestPublic, AllowedIPs: []string{"10.0.0.2/32"}}}}, serverTun)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	state, err := server.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	port := 0
	for _, line := range strings.Split(state, "\n") {
		if value, ok := strings.CutPrefix(line, "listen_port="); ok {
			port, err = strconv.Atoi(value)
		}
	}
	if err != nil || port <= 0 {
		t.Fatal("device did not bind a UDP port")
	}
	responses := make(encryptedGuestSink, 32)
	guestTun, err := NewWGTunWithConfig("encrypted-guest", 1380, responses, DefaultTunConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { guestTun.Close() })
	guest, err := StartDevice(DeviceConfig{Options: &DeviceOptions{}, PrivateKey: guestPrivate, MTU: 1380,
		Peers: []PeerConfig{{PublicKey: serverPublic, AllowedIPs: []string{"0.0.0.0/0"}, Endpoint: endpoint(port)}}}, guestTun)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { guest.Close() })
	return s, guestTun, responses
}

func TestEncryptedWireGuardTCPUDP(t *testing.T) {
	_, guestTun, responses := encryptedTestLink(t, func(port int) string { return fmt.Sprintf("127.0.0.1:%d", port) })
	send := func(p []byte) {
		t.Helper()
		if err := guestTun.InjectToPeer(p); err != nil {
			t.Fatal(err)
		}
	}
	receive := func(proto byte) []byte {
		t.Helper()
		deadline := time.NewTimer(5 * time.Second)
		defer deadline.Stop()
		for {
			select {
			case p := <-responses:
				if len(p) >= 28 && p[9] == proto {
					return p
				}
			case <-deadline.C:
				t.Fatal("encrypted reply deadline")
				return nil
			}
		}
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udp.Close() })
	_ = udp.SetDeadline(time.Now().Add(5 * time.Second))
	udpPort := uint16(udp.LocalAddr().(*net.UDPAddr).Port)
	payload := []byte("encrypted UDP round trip")
	send(encryptedPacket(17, udpPort, 0, 0, 0, payload))
	buf := make([]byte, 1024)
	n, addr, err := udp.ReadFromUDP(buf)
	if err != nil || !bytes.Equal(buf[:n], payload) {
		t.Fatalf("host UDP receive: %v", err)
	}
	if _, err := udp.WriteToUDP(buf[:n], addr); err != nil {
		t.Fatal(err)
	}
	if p := receive(17); !bytes.Equal(p[28:], payload) {
		t.Fatal("guest UDP mismatch")
	}

	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	_ = listener.SetDeadline(time.Now().Add(5 * time.Second))
	tcpPort := uint16(listener.Addr().(*net.TCPAddr).Port)
	send(encryptedPacket(6, tcpPort, 100, 0, 2, nil))
	conn, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	syn := receive(6)
	if len(syn) < 40 || syn[33]&0x12 != 0x12 {
		t.Fatal("missing SYN ACK")
	}
	ack := binary.BigEndian.Uint32(syn[24:28]) + 1
	payload = []byte("encrypted TCP round trip")
	send(encryptedPacket(6, tcpPort, 101, ack, 0x18, payload))
	if _, err := io.ReadFull(conn, buf[:len(payload)]); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:len(payload)], payload) {
		t.Fatal("host TCP mismatch")
	}
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	var got []byte
	for attempts := 0; attempts < 16 && len(got) < len(payload); attempts++ {
		p := receive(6)
		if len(p) < 40 || p[33]&4 != 0 {
			t.Fatal("invalid TCP response")
		}
		h := 20 + int(p[32]>>4)*4
		if h > len(p) {
			t.Fatal("invalid TCP header")
		}
		if binary.BigEndian.Uint32(p[24:28]) == ack {
			got = append(got, p[h:]...)
			ack += uint32(len(p) - h)
		}
		send(encryptedPacket(6, tcpPort, 101+uint32(len(payload)), ack, 0x10, nil))
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("guest TCP mismatch")
	}
	// Exercise encrypted guest reset and join all production workers on cleanup.
	send(encryptedPacket(6, tcpPort, 101+uint32(len(payload)), ack, 0x14, nil))
}
