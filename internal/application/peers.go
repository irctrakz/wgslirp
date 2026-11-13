package application

import (
	"errors"
	"net/netip"

	"github.com/irctrakz/wgslirp/pkg/socket"
	wg "github.com/irctrakz/wgslirp/pkg/wireguard"
)

var (
	ErrInvalidPeer   = errors.New("invalid_config")
	ErrPeerConflict  = errors.New("peer_conflict")
	ErrPeerLimit     = errors.New("peer_limit")
	ErrPeerNotFound  = errors.New("peer_not_found")
	ErrPeerUpdate    = errors.New("peer_update_failed")
	ErrPeersDisabled = errors.New("live peers require restricted forwarding")
)

type restrictedPeers struct {
	active       map[string]netip.Addr
	assigned     map[netip.Addr]struct{}
	destinations *socket.DestinationPolicy
}

func newRestrictedPeers(cfg Config) *restrictedPeers {
	p := &restrictedPeers{
		active:       make(map[string]netip.Addr, len(cfg.Device.Peers)),
		assigned:     make(map[netip.Addr]struct{}, len(cfg.Device.Peers)),
		destinations: cfg.Socket.Destinations,
	}
	for _, peer := range cfg.Device.Peers {
		address := netip.MustParsePrefix(peer.AllowedIPs[0]).Addr()
		p.active[peer.PublicKey] = address
		p.assigned[address] = struct{}{}
	}
	return p
}

// AddPeer verifies applied WireGuard state before opening source admission.
// The protocol controller supplies revision checks around this operation.
func (r *Runtime) AddPeer(publicKey string, address netip.Addr) error {
	r.peerMu.Lock()
	defer r.peerMu.Unlock()
	device, before, err := r.peerUpdateStart()
	if err != nil {
		return err
	}
	key, ok := restrictedKey(publicKey)
	if !ok || publicKey == *before.ServerPublicKey || !validGuestIPv4(address) || r.peers.destinations.Reserves(address) {
		return ErrInvalidPeer
	}
	if _, assigned := r.peers.assigned[address]; assigned || r.peers.active[publicKey].IsValid() {
		return ErrPeerConflict
	}
	if len(r.peers.active) >= 128 || len(r.peers.assigned) >= 1024 {
		return ErrPeerLimit
	}
	updateErr := device.AddPeer(key, address)
	if err := r.verifyPeerUpdate(before, publicKey, address, false, updateErr); err != nil {
		return err
	}
	r.peers.active[publicKey] = address
	r.peers.assigned[address] = struct{}{}
	r.socket.AdmitPeerSource(address.As4())
	return nil
}

// RemovePeer closes admission, verifies removal and joins forwarding cleanup.
// Bytes already delivered to the host or peer cannot be retracted.
func (r *Runtime) RemovePeer(publicKey string) error {
	r.peerMu.Lock()
	defer r.peerMu.Unlock()
	device, before, err := r.peerUpdateStart()
	if err != nil {
		return err
	}
	key, ok := restrictedKey(publicKey)
	if !ok {
		return ErrInvalidPeer
	}
	address, exists := r.peers.active[publicKey]
	if !exists {
		return ErrPeerNotFound
	}
	source := address.As4()
	r.socket.QuiescePeerSource(source)
	updateErr := device.RemovePeer(key)
	err = r.verifyPeerUpdate(before, publicKey, address, true, updateErr)
	if errors.Is(err, ErrRuntimeStateUncertain) {
		return err
	}
	r.socket.RetirePeerSource(source)
	r.tun.DiscardPeerPackets(source)
	if err != nil {
		// Restore admission after verifying the prior WireGuard policy.
		// Quiescing may already have cancelled or closed host work.
		r.socket.AdmitPeerSource(source)
		return err
	}
	delete(r.peers.active, publicKey)
	return nil
}

func (r *Runtime) peerUpdateStart() (wg.PeerDevice, Status, error) {
	if r.peers == nil {
		return nil, Status{}, ErrPeersDisabled
	}
	device, ok := r.device.(wg.PeerDevice)
	if !ok {
		return nil, Status{}, ErrPeersDisabled
	}
	before, err := r.status()
	if err != nil || !matchesPeers(before, r.peers.active, "", netip.Addr{}, false) {
		return nil, Status{}, r.failPeerUpdate()
	}
	return device, before, nil
}

func (r *Runtime) verifyPeerUpdate(before Status, key string, address netip.Addr, remove bool, updateErr error) error {
	after, err := r.status()
	if err == nil && *before.ListenPort == *after.ListenPort && *before.ServerPublicKey == *after.ServerPublicKey {
		if matchesPeers(after, r.peers.active, key, address, remove) {
			return nil
		}
		if updateErr != nil && matchesPeers(after, r.peers.active, "", netip.Addr{}, false) {
			return ErrPeerUpdate
		}
	}
	return r.failPeerUpdate()
}

func matchesPeers(status Status, active map[string]netip.Addr, key string, address netip.Addr, remove bool) bool {
	count := len(active)
	if remove {
		count--
	} else if key != "" {
		count++
	}
	if len(status.Peers) != count {
		return false
	}
	for _, peer := range status.Peers {
		expected := active[peer.PublicKey]
		if peer.PublicKey == key {
			if remove {
				return false
			}
			expected = address
		}
		if !expected.IsValid() || expected.String() != peer.Address {
			return false
		}
	}
	return true
}

func (r *Runtime) failPeerUpdate() error {
	if r.stateUncertain != nil {
		r.stateUncertain()
	}
	_ = r.close()
	return ErrRuntimeStateUncertain
}
