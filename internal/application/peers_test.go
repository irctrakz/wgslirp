package application

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/irctrakz/wgslirp/pkg/socket"
)

type peerUpdateDevice struct {
	state  string
	next   string
	closed bool
	calls  int
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
func (*peerUpdateDevice) RemovePeer([32]byte) error { return errors.New("unexpected removal") }

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
