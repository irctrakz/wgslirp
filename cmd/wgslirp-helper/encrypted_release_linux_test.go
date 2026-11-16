//go:build integration

package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/irctrakz/wgslirp/internal/packetwire"
	"github.com/irctrakz/wgslirp/pkg/core"
	"github.com/irctrakz/wgslirp/pkg/socket"
	wg "github.com/irctrakz/wgslirp/pkg/wireguard"
)

type releaseReplies chan []byte

type releaseDenials struct {
	pending string
	seen    chan struct{}
}

func (d *releaseDenials) Write(record []byte) (int, error) {
	d.pending += string(record)
	for {
		line, rest, complete := strings.Cut(d.pending, "\n")
		if !complete {
			break
		}
		d.pending = rest
		if (strings.Contains(line, "Failed to write packets to TUN device: ") &&
			strings.HasSuffix(line, socket.ErrDestinationDenied.Error())) ||
			strings.HasSuffix(line, "Repeated TUN packet failures: reason=destination_denied suppressed=1") {
			select {
			case d.seen <- struct{}{}:
			default:
			}
		}
	}
	return len(record), nil
}

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
	binaryPath := os.Getenv("WGSLIRP_HELPER_TEST_BINARY")
	if binaryPath == "" {
		t.Skip("set WGSLIRP_HELPER_TEST_BINARY to the already-built helper")
	}
	binaryHash := releaseBinaryHash(t, binaryPath)
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

	denials := &releaseDenials{seen: make(chan struct{}, 2)}
	p := launchHelperWithStderr(t, false, denials)
	negotiated := p.handshake(t)
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
		Peers: []wg.PeerConfig{{PublicKey: fixturePublic, AllowedIPs: []string{"10.77.0.1/32", "127.0.0.1/32"},
			Endpoint: fmt.Sprintf("127.0.0.1:%d", int(port))}},
	}, guest, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()

	src, dst := [4]byte{10, 77, 0, 2}, [4]byte{10, 77, 0, 1}
	send := func(tun *wg.WGTun, target [4]byte, targetPort uint16, seq, ack uint32, flags byte, payload []byte) {
		t.Helper()
		wire := make([]byte, 40+len(payload))
		if !packetwire.IPv4Header(wire, src, target, 6, 0, 64, 0, 0) ||
			!packetwire.TCP(wire[20:], src, target, 42000, targetPort, seq, ack, flags, 65535, payload, nil) {
			t.Fatal("unable to encode TCP test packet")
		}
		if err := tun.InjectToPeer(wire); err != nil {
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
	// Use the mapped IP with an unmapped port, so an IP-only policy would
	// wrongly authorize the packet. This must be the first logged denial.
	send(guest, dst, 8097, 100, 0, 0x02, nil)
	select {
	case <-denials.seen:
	case <-time.After(5 * time.Second):
		t.Fatal("encrypted traffic did not reach the unmapped port denial")
	}
	// Also attempt direct access to the real listener. A second denial in
	// the same logging window is coalesced and emitted during shutdown.
	send(guest, [4]byte{127, 0, 0, 1}, uint16(listener.Addr().(*net.TCPAddr).Port), 100, 0, 0x02, nil)

	send(guest, dst, 8096, 100, 0, 0x02, nil)
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
	send(guest, dst, 8096, 101, ack, 0x18, payload)
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
			send(guest, dst, 8096, 101+uint32(len(payload)), ack+uint32(len(echoed)), 0x10, nil)
		}
	}
	if !bytes.Equal(echoed, payload) {
		t.Fatalf("encrypted return payload %q", echoed)
	}
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	probe := func(revoked bool) {
		t.Helper()
		fresh, err := wg.NewWGTunWithConfig("fresh-guest", 1380, make(releaseReplies, 16), wg.DefaultTunConfig())
		if err != nil {
			t.Fatal(err)
		}
		defer fresh.Close()
		freshDevice, err := wg.StartDeviceWithLogOutput(wg.DeviceConfig{
			PrivateKey: base64.StdEncoding.EncodeToString(key.Bytes()), MTU: 1380,
			Peers: []wg.PeerConfig{{PublicKey: fixturePublic, AllowedIPs: []string{"10.77.0.1/32"},
				Endpoint: relay.LocalAddr().String()}},
		}, fresh, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		defer freshDevice.Close()
		send(fresh, dst, 8096, 200, 0, 0x02, nil)
		probeReleaseHandshake(t, relay, int(port), revoked)
	}
	probe(false)
	p.roundTrip(t, 4, "peer_remove", object{"expected_revision": 2, "public_key": public}, 3, "")
	if n, err := host.Read(got); n != 0 || err != io.EOF {
		t.Fatalf("revocation left the mapped connection open: %d, %v", n, err)
	}
	probe(true)

	p.roundTrip(t, 5, "stop", object{}, 3, "")
	p.wait(t, 0)
	p.expectEOF(t)
	select {
	case <-denials.seen:
	default:
		t.Fatal("missing second destination denial for direct host access")
	}
	assertUDPReleased(t, int(port))
	if evidence := os.Getenv("WGSLIRP_HELPER_ACCEPTANCE"); evidence != "" {
		if releaseBinaryHash(t, binaryPath) != binaryHash {
			t.Fatal("release helper changed during acceptance")
		}
		info, err := buildinfo.ReadFile(binaryPath)
		if err != nil {
			t.Fatal(err)
		}
		settings := map[string]string{}
		for _, setting := range info.Settings {
			settings[setting.Key] = setting.Value
		}
		if settings["vcs.revision"] == "" || settings["vcs.modified"] != "false" {
			t.Fatal("release helper requires clean VCS build information")
		}
		record, err := json.MarshalIndent(object{
			"source_commit": settings["vcs.revision"], "binary_sha256": binaryHash,
			"binary_version": negotiated["binary_version"], "protocol_versions": []any{negotiated["version"]},
			"capabilities": negotiated["capabilities"], "platform": fmt.Sprint(negotiated["os"], "/", negotiated["arch"]),
		}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(evidence, append(record, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func releaseBinaryHash(t *testing.T, path string) string {
	t.Helper()
	binary, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", sha256.Sum256(binary))
}

func probeReleaseHandshake(t *testing.T, relay *net.UDPConn, port int, revoked bool) {
	t.Helper()
	if err := relay.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 2048)
	n, _, err := relay.ReadFromUDP(packet)
	if err != nil || n != 148 || binary.LittleEndian.Uint32(packet) != 1 {
		t.Fatalf("expected fresh WireGuard handshake initiation, got %d bytes (%v)", n, err)
	}
	server, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	// Send the real initiation to the helper and wait for the server's
	// reply on loopback. An accepted key would receive a handshake reply.
	if _, err := server.Write(packet[:n]); err != nil {
		t.Fatal(err)
	}
	wait := 3 * time.Second
	if revoked {
		wait = time.Second
	}
	if err := server.SetReadDeadline(time.Now().Add(wait)); err != nil {
		t.Fatal(err)
	}
	n, err = server.Read(packet)
	if !revoked {
		if err != nil || n != 92 || binary.LittleEndian.Uint32(packet) != 2 {
			t.Fatalf("active handshake did not receive a response: %d bytes (%v)", n, err)
		}
		return
	}
	if timeout, ok := err.(net.Error); n != 0 || !ok || !timeout.Timeout() {
		t.Fatalf("revoked handshake returned %d bytes (%v)", n, err)
	}
}
