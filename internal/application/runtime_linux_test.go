package application

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/irctrakz/wgslirp/internal/packetwire"
	"github.com/irctrakz/wgslirp/pkg/core"
	wg "github.com/irctrakz/wgslirp/pkg/wireguard"
)

type discardPackets struct{}

func (discardPackets) WritePacket(core.Packet) error { return nil }

func TestCloseCancelsWireGuardHostDial(t *testing.T) {
	const marker = "WGSLIRP_RUNTIME_PENDING_DIAL_TEST"
	if os.Getenv(marker) != "1" {
		runRuntimeSubprocess(t, "TestCloseCancelsWireGuardHostDial", marker+"=1")
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
	r, err := Start(context.Background(), cfg, Observers{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	state, err := r.device.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	var serverPort string
	for _, line := range strings.Split(state, "\n") {
		if value, ok := strings.CutPrefix(line, "listen_port="); ok {
			serverPort = value
			break
		}
	}
	if serverPort == "" || serverPort == "0" {
		t.Fatal("missing server UDP port")
	}
	clientTun, err := wg.NewWGTunWithConfig("shutdown-client", cfg.Device.MTU, discardPackets{}, wg.DefaultTunConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer clientTun.Close()
	client, err := wg.StartDevice(wg.DeviceConfig{
		PrivateKey: clientPrivate, MTU: cfg.Device.MTU,
		Peers: []wg.PeerConfig{{PublicKey: serverPublic, AllowedIPs: []string{"127.0.0.1/32"},
			Endpoint: net.JoinHostPort("127.0.0.1", serverPort)}},
	}, clientTun)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var syn [40]byte
	source, target := [4]byte{10, 0, 0, 2}, [4]byte{127, 0, 0, 1}
	if !packetwire.IPv4Header(syn[:], source, target, 6, 0, 64, 0, 0) ||
		!packetwire.TCP(syn[20:], source, target, 42000, uint16(port), 1, 0, 2, 65535, nil, nil) {
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
	done := make(chan error, 1)
	go func() { done <- r.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("runtime close waited on the host dial instead of cancelling it")
	}
	if got := r.socket.DetailedMetrics().TCPExt["dial_reserved"]; got != 0 {
		t.Fatalf("shutdown left %d pending dial reservations", got)
	}
}
