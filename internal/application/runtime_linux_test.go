package application

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/irctrakz/wgslirp/internal/packetwire"
	"github.com/irctrakz/wgslirp/pkg/core"
	"github.com/irctrakz/wgslirp/pkg/socket"
	wg "github.com/irctrakz/wgslirp/pkg/wireguard"
)

type captureSYNACK struct {
	core.PacketProcessor
	sequence chan uint32
}

type waitingPeerDevice struct {
	wg.DeviceHandle
	wg.PeerDevice
	receiveDone <-chan error
}

func (d waitingPeerDevice) RemovePeer(key [32]byte) error {
	// Model WireGuard joining its receive worker before returning.
	select {
	case err := <-d.receiveDone:
		if err == nil {
			return fmt.Errorf("host write completed without interruption")
		}
	case <-time.After(3 * time.Second):
		return fmt.Errorf("peer removal waited for the stalled receive worker")
	}
	return d.PeerDevice.RemovePeer(key)
}

func (p captureSYNACK) ProcessPacket(packet core.Packet) error {
	data := core.BorrowPacketData(packet)
	if len(data) >= 40 && data[33]&0x12 == 0x12 {
		select {
		case p.sequence <- binary.BigEndian.Uint32(data[24:28]):
		default:
		}
	}
	return p.PacketProcessor.ProcessPacket(packet)
}

func TestRuntimeStatusWhileHostWriteStalled(t *testing.T) {
	const marker = "WGSLIRP_RUNTIME_STALLED_WRITE_TEST"
	mode := os.Getenv(marker)
	if mode == "" {
		for _, mode := range []string{"status", "revoke"} {
			t.Run(mode, func(t *testing.T) {
				runRuntimeSubprocess(t, "TestRuntimeStatusWhileHostWriteStalled", marker+"="+mode)
			})
		}
		return
	}
	lc := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var sockErr error
		if err := raw.Control(func(fd uintptr) {
			sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4096)
		}); err != nil {
			return err
		}
		return sockErr
	}}
	ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	cfg := testConfig()
	cfg.Socket.Transport.SocketSendBuffer = 4096
	cfg.Socket.Transport.FastDialMs = 2000
	source, target := [4]byte{10, 0, 0, 2}, [4]byte{127, 0, 0, 1}
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	const peerKey = "3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08="
	if mode == "revoke" {
		guest := netip.MustParseAddrPort("10.77.0.1:8096")
		host := netip.AddrPortFrom(netip.AddrFrom4(target), port)
		cfg.Socket.Destinations, err = socket.NewDestinationPolicy([]socket.TCPMapping{{Guest: guest, Host: host}})
		if err != nil {
			t.Fatal(err)
		}
		cfg.Device.Peers = []wg.PeerConfig{{PublicKey: peerKey, AllowedIPs: []string{"10.0.0.2/32"}}}
		target, port = guest.Addr().As4(), guest.Port()
	}
	synACK := make(chan uint32, 1)
	r, err := Start(context.Background(), cfg, Observers{
		WrapProcessor: func(primary core.PacketProcessor) core.PacketProcessor {
			return captureSYNACK{PacketProcessor: primary, sequence: synACK}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	makePacket := func(seq, ack uint32, flags byte, payload []byte) core.Packet {
		t.Helper()
		data := make([]byte, 40+len(payload))
		if !packetwire.IPv4Header(data, source, target, 6, 0, 64, 0, 0) ||
			!packetwire.TCP(data[20:], source, target, 42000, port, seq, ack, flags, 65535, payload, nil) {
			t.Fatal("could not encode guest packet")
		}
		return core.NewBorrowedPacket(data)
	}
	if err := r.socket.WritePacket(makePacket(1, 0, 2, nil)); err != nil {
		t.Fatal(err)
	}
	var serverSeq uint32
	select {
	case serverSeq = <-synACK:
	case <-time.After(3 * time.Second):
		t.Fatal("missing SYN-ACK")
	}
	if err := ln.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	unreadHost, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer unreadHost.Close()
	payload := make([]byte, 1200)
	for seq := uint32(2); seq < 256*uint32(len(payload)); seq += uint32(len(payload)) {
		packet := makePacket(seq, serverSeq+1, 0x18, payload)
		write := make(chan error, 1)
		go func() { write <- r.socket.WritePacket(packet) }()
		select {
		case err := <-write:
			if err != nil {
				t.Fatal(err)
			}
			continue
		case <-time.After(150 * time.Millisecond):
		}
		if mode == "revoke" {
			r.device = waitingPeerDevice{
				DeviceHandle: r.device, PeerDevice: r.device.(wg.PeerDevice), receiveDone: write,
			}
			removed := make(chan error, 1)
			go func() { removed <- r.RemovePeer(peerKey) }()
			select {
			case err := <-removed:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("revocation waited for the stalled host write deadline")
			}
			if got := r.socket.DetailedMetrics().TCP.ActiveFlows; got != 0 {
				t.Fatalf("revocation retained %d active flows", got)
			}
			return
		}
		type result struct {
			status Status
			err    error
		}
		poll := make(chan result, 1)
		go func() {
			status, err := r.Status()
			poll <- result{status, err}
		}()
		select {
		case got := <-poll:
			if got.err != nil || got.status.Metrics == nil || got.status.Metrics.ActiveTCPFlows != 1 {
				t.Fatalf("status during stalled write: %+v (%v)", got.status, got.err)
			}
		case <-time.After(time.Second):
			t.Fatal("runtime status blocked behind the host write")
		}
		select {
		case err := <-write:
			t.Fatalf("host write was no longer stalled: %v", err)
		default:
		}
		return
	}
	t.Fatal("unread host never stalled a write")
}

type discardPackets struct{}

func (discardPackets) WritePacket(core.Packet) error { return nil }

func TestCloseCancelsWireGuardHostDial(t *testing.T) {
	const marker = "WGSLIRP_RUNTIME_PENDING_DIAL_TEST"
	mode := os.Getenv(marker)
	if mode == "" {
		for _, mode := range []string{"unrestricted", "restricted", "restricted-async"} {
			t.Run(mode, func(t *testing.T) {
				runRuntimeSubprocess(t, "TestCloseCancelsWireGuardHostDial", marker+"="+mode)
			})
		}
		return
	}
	// Linux backlog zero admits one connection. Keep it queued so the next
	// SYN to this listener stays pending without using an external address.
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Listen(fd, 0); err != nil {
		t.Fatal(err)
	}
	addr, err := syscall.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	port := addr.(*syscall.SockaddrInet4).Port
	queued, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer queued.Close()

	keys := func() (private, public string) {
		t.Helper()
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(key.Bytes()), base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
	}
	serverPrivate, serverPublic := keys()
	clientPrivate, clientPublic := keys()
	cfg := testConfig()
	cfg.Device.PrivateKey = serverPrivate
	cfg.Device.Peers = []wg.PeerConfig{{PublicKey: clientPublic, AllowedIPs: []string{"10.0.0.2/32"}}}
	cfg.Socket.Transport.FastDialMs = 8000
	target := netip.MustParseAddrPort(net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if mode != "unrestricted" {
		host := target
		target = netip.MustParseAddrPort("10.77.0.1:8096")
		cfg.Socket.Destinations, err = socket.NewDestinationPolicy([]socket.TCPMapping{{Guest: target, Host: host}})
		if err != nil {
			t.Fatal(err)
		}
	}
	if mode == "restricted-async" {
		cfg.Socket.Transport.FastDialMs = 1
	}
	r, err := Start(context.Background(), cfg, Observers{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	status, err := r.Status()
	if err != nil {
		t.Fatal(err)
	}
	if status.ListenPort == nil || *status.ListenPort == 0 {
		t.Fatal("missing server UDP port")
	}
	serverPort := strconv.Itoa(int(*status.ListenPort))
	clientTun, err := wg.NewWGTunWithConfig("shutdown-client", cfg.Device.MTU, discardPackets{}, wg.DefaultTunConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer clientTun.Close()
	client, err := wg.StartDevice(wg.DeviceConfig{
		PrivateKey: clientPrivate, MTU: cfg.Device.MTU,
		Peers: []wg.PeerConfig{{PublicKey: serverPublic, AllowedIPs: []string{netip.PrefixFrom(target.Addr(), 32).String()},
			Endpoint: net.JoinHostPort("127.0.0.1", serverPort)}},
	}, clientTun)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var syn [40]byte
	source, destination := [4]byte{10, 0, 0, 2}, target.Addr().As4()
	if mode != "unrestricted" {
		fragment := make([]byte, 28)
		if !packetwire.IPv4Header(fragment, source, destination, 6, 0, 64, 42, 0x2000) {
			t.Fatal("could not encode partial TCP fragment")
		}
		binary.BigEndian.PutUint16(fragment[22:24], target.Port())
		if err := clientTun.InjectToPeer(fragment); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(3 * time.Second)
		for r.socket.DetailedMetrics().IPv4Fragments["live"] != 1 {
			if time.Now().After(deadline) {
				t.Fatal("peer fragment never reserved reassembly space")
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	if !packetwire.IPv4Header(syn[:], source, destination, 6, 0, 64, 0, 0) ||
		!packetwire.TCP(syn[20:], source, destination, 42000, target.Port(), 1, 0, 2, 65535, nil, nil) {
		t.Fatal("could not encode SYN")
	}
	if err := clientTun.InjectToPeer(syn[:]); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(4 * time.Second)
	for r.socket.DetailedMetrics().TCPExt["dial_reserved"] != 1 {
		if time.Now().After(deadline) {
			t.Fatal("WireGuard SYN did not reach a pending host dial")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if mode == "restricted-async" {
		for r.socket.DetailedMetrics().TCPExt["dial_inflight"] != 1 {
			if time.Now().After(deadline) {
				t.Fatal("mapped dial never reached asynchronous completion")
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	status, err = r.Status()
	if err != nil || len(status.Peers) != 1 {
		t.Fatalf("live peer status: %+v (%v)", status, err)
	}
	peer := status.Peers[0]
	if peer.PublicKey != clientPublic || peer.Address != "10.0.0.2" ||
		peer.Endpoint == nil || peer.LastHandshakeUnixSec == nil ||
		peer.RXBytes == nil || *peer.RXBytes == "0" || peer.TXBytes == nil || *peer.TXBytes == "0" {
		t.Fatalf("missing telemetry after encrypted guest traffic: %+v", peer)
	}
	done := make(chan error, 1)
	go func() {
		if mode != "unrestricted" {
			done <- r.RemovePeer(clientPublic)
		} else {
			done <- r.Close()
		}
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown or revocation waited on the host dial instead of cancelling it")
	}
	if got := r.socket.DetailedMetrics().TCPExt["dial_reserved"]; got != 0 {
		t.Fatalf("shutdown left %d pending dial reservations", got)
	}
	if mode != "unrestricted" {
		metrics := r.socket.DetailedMetrics()
		if metrics.TCP.ActiveFlows != 0 || metrics.IPv4Fragments["live"] != 0 ||
			metrics.TCPExt["dial_inflight"] != 0 || metrics.TCPExt["socket_buffer_bytes"] != 0 {
			t.Fatal("revocation returned before peer reservations were released")
		}
	}
}
