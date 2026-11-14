//go:build integration

package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/irctrakz/wgslirp/internal/packetwire"
	"github.com/irctrakz/wgslirp/pkg/core"
	wg "github.com/irctrakz/wgslirp/pkg/wireguard"
)

type releaseReplies chan []byte

func (r releaseReplies) WritePacket(packet core.Packet) error {
	select {
	case r <- core.CopyPacketData(packet):
		return nil
	default:
		return fmt.Errorf("release reply queue full")
	}
}

// Drive the exact executable to be packaged, from hello through encrypted
// traffic across a live peer addition and removal to a clean stop.
func TestEncryptedHelperRelease(t *testing.T) {
	if os.Getenv("WGSLIRP_HELPER_TEST_BINARY") == "" {
		t.Skip("set WGSLIRP_HELPER_TEST_BINARY to the already-built helper")
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public := base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())

	p := launchHelper(t, false)
	p.handshake(t)
	cfg := fixtureConfig(0)
	cfg["mappings"].([]object)[0]["host_port"] = listener.Addr().(*net.TCPAddr).Port
	started := p.roundTrip(t, 2, "start", cfg, 1, "")
	port, ok := started["listen_port"].(float64)
	if !ok || port < 1 || started["server_public_key"] != fixturePublic {
		t.Fatalf("invalid readiness: %v", started)
	}
	p.roundTrip(t, 3, "peer_add", object{"expected_revision": 1,
		"peer": object{"public_key": public, "address": "10.77.0.2"}}, 2, "")

	replies := make(releaseReplies, 64)
	guest, err := wg.NewWGTunWithConfig("release-guest", 1380, replies, wg.DefaultTunConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer guest.Close()
	device, err := wg.StartDeviceWithLogOutput(wg.DeviceConfig{
		PrivateKey: base64.StdEncoding.EncodeToString(key.Bytes()), MTU: 1380,
		Peers: []wg.PeerConfig{{PublicKey: fixturePublic, AllowedIPs: []string{"10.77.0.1/32"},
			Endpoint: fmt.Sprintf("127.0.0.1:%d", int(port))}},
	}, guest, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()

	src, dst := [4]byte{10, 77, 0, 2}, [4]byte{10, 77, 0, 1}
	send := func(seq, ack uint32, flags byte, payload []byte) {
		t.Helper()
		wire := make([]byte, 40+len(payload))
		if !packetwire.IPv4Header(wire, src, dst, 6, 0, 64, 0, 0) ||
			!packetwire.TCP(wire[20:], src, dst, 42000, 8096, seq, ack, flags, 65535, payload, nil) {
			t.Fatal("unable to encode TCP test packet")
		}
		if err := guest.InjectToPeer(wire); err != nil {
			t.Fatal(err)
		}
	}
	receive := func() []byte {
		t.Helper()
		select {
		case reply := <-replies:
			if len(reply) < 40 || reply[9] != 6 || !bytes.Equal(reply[12:16], dst[:]) ||
				!bytes.Equal(reply[16:20], src[:]) || binary.BigEndian.Uint16(reply[20:22]) != 8096 ||
				binary.BigEndian.Uint16(reply[22:24]) != 42000 {
				t.Fatalf("reply did not preserve the virtual TCP endpoints: %x", reply)
			}
			return reply
		case <-time.After(5 * time.Second):
			t.Fatal("missing encrypted helper reply")
			return nil
		}
	}
	send(100, 0, 0x02, nil)
	syn := receive()
	if syn[33]&0x12 != 0x12 {
		t.Fatalf("expected SYN-ACK, got flags %#x", syn[33])
	}
	if err := listener.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	host, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	if err := host.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := []byte("encrypted helper release")
	ack := binary.BigEndian.Uint32(syn[24:28]) + 1
	send(101, ack, 0x18, payload)
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(host, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("mapped host received %q (%v)", got, err)
	}
	if _, err := host.Write(payload); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	var echoed []byte
	for len(echoed) < len(payload) && time.Now().Before(deadline) {
		reply := receive()
		header := 20 + int(reply[32]>>4)*4
		if header < 40 || header > len(reply) {
			t.Fatalf("invalid reply header: %x", reply)
		}
		if seq := binary.BigEndian.Uint32(reply[24:28]); header < len(reply) && seq == ack+uint32(len(echoed)) {
			echoed = append(echoed, reply[header:]...)
			send(101+uint32(len(payload)), ack+uint32(len(echoed)), 0x10, nil)
		}
	}
	if !bytes.Equal(echoed, payload) {
		t.Fatalf("encrypted return payload %q", echoed)
	}
	p.roundTrip(t, 4, "peer_remove", object{"expected_revision": 2, "public_key": public}, 3, "")
	if n, err := host.Read(got); n != 0 || err != io.EOF {
		t.Fatalf("revocation left the mapped connection open: %d, %v", n, err)
	}
	p.roundTrip(t, 5, "stop", object{}, 3, "")
	p.wait(t, 0)
	p.expectEOF(t)
	assertUDPReleased(t, int(port))
}
