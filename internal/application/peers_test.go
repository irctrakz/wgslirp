package application

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/irctrakz/wgslirp/internal/packetwire"
	"github.com/irctrakz/wgslirp/pkg/core"
	"github.com/irctrakz/wgslirp/pkg/socket"
	wg "github.com/irctrakz/wgslirp/pkg/wireguard"
)

type peerUpdateDevice struct {
	state    string
	next     string
	closed   bool
	calls    int
	onRemove func() error
}

func (d *peerUpdateDevice) IpcGet() (string, error)    { return d.state, nil }
func (d *peerUpdateDevice) RebindListenPort(int) error { return nil }
func (d *peerUpdateDevice) Close() error {
	d.closed = true
	return nil
}
func (d *peerUpdateDevice) AddPeer([32]byte, netip.Addr) error {
	d.calls++
	d.state = d.next
	return errors.New("injected UAPI failure")
}
func (d *peerUpdateDevice) RemovePeer([32]byte) error {
	d.calls++
	d.state = d.next
	if d.onRemove != nil {
		return d.onRemove()
	}
	return errors.New("injected UAPI failure")
}

func TestPeerRemovalReconcilesDeviceAfterFailure(t *testing.T) {
	const key = "3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08="
	base := "private_key=" + privateHex + "\nlisten_port=51820\n"
	peer := "public_key=" + peerHex + "\n"
	before := base + peer + "allowed_ip=10.77.0.2/32\n"
	address := netip.MustParseAddr("10.77.0.2")
	guest := netip.MustParseAddrPort("10.77.0.1:8096")
	policy, err := socket.NewDestinationPolicy([]socket.TCPMapping{{
		Guest: guest, Host: netip.MustParseAddrPort("127.0.0.1:8096"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		state string
		want  error
	}{
		{"prior intact", before, ErrPeerUpdate},
		{"desired applied", base, nil},
		{"partial update", base + peer, ErrRuntimeStateUncertain},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.Socket.Destinations = policy
			cfg.Device.Peers = []wg.PeerConfig{{PublicKey: key, AllowedIPs: []string{"10.77.0.2/32"}}}
			s := socket.NewSocketInterface(cfg.Socket)
			s.EnablePeerAdmission()
			s.AdmitPeerSource(address.As4())
			tun, err := wg.NewWGTunWithConfig("peer-removal", cfg.Device.MTU, s, cfg.Tun)
			if err != nil {
				t.Fatal(err)
			}
			defer tun.Close()
			s.SetPacketProcessor(wg.NewWGPacketProcessor(tun))
			if err := s.Start(); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			device := &peerUpdateDevice{state: before, next: tc.state}
			r := &Runtime{ctx: ctx, cancel: cancel, socket: s, tun: tun, device: device, peers: newRestrictedPeers(cfg)}
			defer r.Close()

			fragment := make([]byte, 28)
			if !packetwire.IPv4Header(fragment, address.As4(), guest.Addr().As4(), 6, 0, 64, 1, 0x2000) {
				t.Fatal("could not encode peer fragment")
			}
			fragment[22], fragment[23] = byte(guest.Port()>>8), byte(guest.Port())
			write := func() error { return s.WritePacket(core.NewBorrowedPacket(fragment)) }
			if err := write(); err != nil {
				t.Fatal(err)
			}
			device.onRemove = func() error {
				if err := write(); !errors.Is(err, socket.ErrPeerInactive) {
					t.Errorf("admission during removal: %v", err)
				}
				return errors.New("injected UAPI failure")
			}
			if err := r.RemovePeer(key); !errors.Is(err, tc.want) || device.calls != 1 {
				t.Fatalf("remove = %v, want %v, calls = %d", err, tc.want, device.calls)
			}
			if got := s.DetailedMetrics().IPv4Fragments["live"]; got != 0 {
				t.Fatalf("removal retained %d fragment assemblies", got)
			}
			switch tc.want {
			case ErrPeerUpdate:
				if err := write(); err != nil || r.peers.active[key] != address || device.closed {
					t.Fatalf("verified prior policy did not reopen admission: %v", err)
				}
			case ErrRuntimeStateUncertain:
				if !device.closed || ctx.Err() == nil {
					t.Fatal("uncertain removal did not close the runtime")
				}
				if _, err := r.Status(); !errors.Is(err, ErrRuntimeStateUncertain) {
					t.Fatalf("status after uncertain removal: %v", err)
				}
			default:
				if err := write(); !errors.Is(err, socket.ErrPeerInactive) || r.peers.active[key].IsValid() || device.closed {
					t.Fatalf("verified removal left the peer active: %v", err)
				}
			}
		})
	}
}

func TestPeerUpdateReconcilesDeviceAfterFailure(t *testing.T) {
	const key = "3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08="
	base := "private_key=" + privateHex + "\nlisten_port=51820\n"
	address := netip.MustParseAddr("10.77.0.2")
	policy, err := socket.NewDestinationPolicy([]socket.TCPMapping{{
		Guest: netip.MustParseAddrPort("10.77.0.1:8096"),
		Host:  netip.MustParseAddrPort("127.0.0.1:8096"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		state string
		want  error
	}{
		{"prior intact", base, ErrPeerUpdate},
		{"desired applied", base + "public_key=" + peerHex + "\nallowed_ip=10.77.0.2/32\n", nil},
		{"partial update", base + "public_key=" + peerHex + "\n", ErrRuntimeStateUncertain},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.Socket.Destinations = policy
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			device := &peerUpdateDevice{state: base, next: tc.state}
			s := socket.NewSocketInterface(cfg.Socket)
			s.EnablePeerAdmission()
			r := &Runtime{ctx: ctx, cancel: cancel, socket: s, device: device, peers: newRestrictedPeers(cfg)}
			if err := r.AddPeer(key, netip.MustParseAddr("10.77.0.1")); !errors.Is(err, ErrInvalidPeer) || device.calls != 0 {
				t.Fatalf("reserved address was not rejected before update: %v", err)
			}
			if err := r.AddPeer(key, address); !errors.Is(err, tc.want) {
				t.Fatalf("update error = %v, want %v", err, tc.want)
			}
			_, active := r.peers.active[key]
			if active != (tc.want == nil) || device.closed != errors.Is(tc.want, ErrRuntimeStateUncertain) {
				t.Fatalf("unexpected reconciliation: active=%t closed=%t", active, device.closed)
			}
		})
	}
}
