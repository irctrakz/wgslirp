package application

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/irctrakz/wgslirp/internal/packetwire"
	"github.com/irctrakz/wgslirp/pkg/core"
	"github.com/irctrakz/wgslirp/pkg/socket"
	wg "github.com/irctrakz/wgslirp/pkg/wireguard"
)

type isolationReplies chan []byte

func (r isolationReplies) WritePacket(packet core.Packet) error {
	select {
	case r <- core.CopyPacketData(packet):
		return nil
	default:
		return fmt.Errorf("isolation test reply queue full")
	}
}

func TestRestrictedRuntimePeerIsolation(t *testing.T) {
	const marker = "WGSLIRP_TEST_PEER_ISOLATION"
	if os.Getenv(marker) != "1" {
		runRuntimeSubprocess(t, "TestRestrictedRuntimePeerIsolation", marker+"=1")
		return
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	host := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(listener.Addr().(*net.TCPAddr).Port))
	service := netip.MustParseAddrPort("10.77.0.1:8096")
	policy, err := socket.NewDestinationPolicy([]socket.TCPMapping{{Guest: service, Host: host}})
	if err != nil {
		t.Fatal(err)
	}

	cfg := testConfig()
	cfg.Socket.Destinations = policy
	// Keep loopback dials on the fast path so each positive probe is an
	// ordering barrier for packets sent before it by that peer.
	cfg.Socket.Transport.FastDialMs = 500
	addresses := []netip.Addr{netip.MustParseAddr("10.77.0.2"), netip.MustParseAddr("10.77.0.3")}
	var privateKeys []string
	for _, address := range addresses {
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		privateKeys = append(privateKeys, base64.StdEncoding.EncodeToString(key.Bytes()))
		cfg.Device.Peers = append(cfg.Device.Peers, wg.PeerConfig{
			PublicKey:  base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()),
			AllowedIPs: []string{netip.PrefixFrom(address, 32).String()},
		})
	}
	runtime, err := Start(context.Background(), cfg, Observers{})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	status, err := runtime.Status()
	if err != nil || status.ListenPort == nil || status.ServerPublicKey == nil || len(status.Peers) != 2 {
		t.Fatalf("restricted runtime status: %+v (%v)", status, err)
	}
	endpoint := netip.AddrPortFrom(host.Addr(), *status.ListenPort)
	var tuns []*wg.WGTun
	var replies []isolationReplies
	for _, key := range privateKeys {
		reply := make(isolationReplies, 16)
		tun, err := wg.NewWGTunWithConfig("isolation-client", cfg.Device.MTU, reply, wg.DefaultTunConfig())
		if err != nil {
			t.Fatal(err)
		}
		defer tun.Close()
		device, err := wg.StartDevice(wg.DeviceConfig{
			PrivateKey: key, MTU: cfg.Device.MTU,
			Peers: []wg.PeerConfig{{PublicKey: *status.ServerPublicKey,
				AllowedIPs: []string{"10.77.0.0/24"}, Endpoint: endpoint.String()}},
		}, tun)
		if err != nil {
			t.Fatal(err)
		}
		defer device.Close()
		tuns, replies = append(tuns, tun), append(replies, reply)
	}

	send := func(peer int, source netip.Addr, destination netip.AddrPort, port uint16, seq, ack uint32, flags byte, payload []byte) {
		t.Helper()
		p := make([]byte, 40+len(payload))
		src, dst := source.As4(), destination.Addr().As4()
		if !packetwire.IPv4Header(p, src, dst, 6, 0, 64, 0, 0) ||
			!packetwire.TCP(p[20:], src, dst, port, destination.Port(), seq, ack, flags, 65535, payload, nil) {
			t.Fatal("could not encode encrypted test packet")
		}
		if err := tuns[peer].InjectToPeer(p); err != nil {
			t.Fatal(err)
		}
	}
	roundTrip := func(peer int, port uint16) {
		t.Helper()
		send(peer, addresses[peer], service, port, 100, 0, 2, nil)
		wait := time.NewTimer(3 * time.Second)
		defer wait.Stop()
		var synACK []byte
		for synACK == nil {
			select {
			case p := <-replies[peer]:
				if len(p) < 40 {
					t.Fatalf("short peer %d reply: %x", peer, p)
				}
				replyPort := binary.BigEndian.Uint16(p[22:24])
				if binary.BigEndian.Uint16(p[20:22]) == 42002 || replyPort == 42003 {
					t.Fatalf("peer %d received an unauthorized packet: %x", peer, p)
				}
				if replyPort == port {
					synACK = p
				}
			case <-wait.C:
				t.Fatal("missing mapped SYN-ACK")
			}
		}
		if len(synACK) < 40 || synACK[33]&0x12 != 0x12 ||
			!bytes.Equal(synACK[12:16], service.Addr().AsSlice()) ||
			!bytes.Equal(synACK[16:20], addresses[peer].AsSlice()) ||
			binary.BigEndian.Uint16(synACK[22:24]) != port {
			t.Fatalf("unexpected peer %d reply: %x", peer, synACK)
		}
		if err := listener.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		conn, err := listener.AcceptTCP()
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		payload := []byte{byte(peer), byte(port)}
		send(peer, addresses[peer], service, port, 101, binary.BigEndian.Uint32(synACK[24:28])+1, 0x18, payload)
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("mapped host received %x from peer %d (%v)", got, peer, err)
		}
	}

	// Establish both WireGuard sessions before trying peer-to-peer traffic.
	roundTrip(1, 42001)
	// Target the second peer, then try its source address against the service.
	send(0, addresses[0], netip.AddrPortFrom(addresses[1], service.Port()), 42002, 200, 0, 2, nil)
	send(0, addresses[1], service, 42003, 300, 0, 2, nil)
	roundTrip(0, 42004)
	roundTrip(1, 42005)

	// Any unauthorized SYN-ACK or forwarded SYN carries one of these ports.
	quiet := time.NewTimer(200 * time.Millisecond)
	defer quiet.Stop()
	for {
		select {
		case p := <-replies[1]:
			if len(p) >= 40 && (binary.BigEndian.Uint16(p[20:22]) == 42002 ||
				binary.BigEndian.Uint16(p[22:24]) == 42003) {
				t.Fatalf("second peer received an unauthorized packet: %x", p)
			}
		case <-quiet.C:
			if got := runtime.socket.DetailedMetrics().TCP.Counters.ConnectionsCreated; got != 3 {
				t.Fatalf("host flow count = %d, want three mapped connections", got)
			}
			return
		}
	}
}
