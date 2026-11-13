package application

import (
	"crypto/ecdh"
	"encoding/base64"
	"fmt"
	"net/netip"
)

func (c Config) validateRestricted() error {
	if c.Capture.Path != "" {
		return fmt.Errorf("restricted forwarding disables packet capture")
	}
	if options := c.Device.Options; options != nil && (options.OverlayRouting || options.DisableIPv6) {
		return fmt.Errorf("restricted forwarding disables overlay routing and sysctl changes")
	}
	if c.Device.MTU > 9000 || len(c.Device.Peers) > 128 {
		return fmt.Errorf("restricted forwarding requires MTU at most 9000 and at most 128 peers")
	}
	private, ok := restrictedKey(c.Device.PrivateKey)
	if !ok {
		return fmt.Errorf("invalid restricted server key")
	}
	key, err := ecdh.X25519().NewPrivateKey(private[:])
	clear(private[:])
	if err != nil {
		return fmt.Errorf("invalid restricted server key")
	}
	keys := map[[32]byte]bool{[32]byte(key.PublicKey().Bytes()): true}
	addresses := make(map[netip.Addr]bool, len(c.Device.Peers))
	for i, peer := range c.Device.Peers {
		public, ok := restrictedKey(peer.PublicKey)
		if !ok || keys[public] {
			return fmt.Errorf("peer %d requires a valid and distinct public key", i)
		}
		if peer.Endpoint != "" || peer.PersistentKeepaliveSec != 0 || len(peer.AllowedIPs) != 1 {
			return fmt.Errorf("peer %d must be passive with one IPv4 /32", i)
		}
		prefix, err := netip.ParsePrefix(peer.AllowedIPs[0])
		if err != nil || prefix.Bits() != 32 || !validGuestIPv4(prefix.Addr()) || prefix.String() != peer.AllowedIPs[0] {
			return fmt.Errorf("peer %d requires a canonical unicast IPv4 /32", i)
		}
		address := prefix.Addr()
		if addresses[address] || c.Socket.Destinations.Reserves(address) {
			return fmt.Errorf("peer %d address conflicts with another peer or virtual service", i)
		}
		keys[public] = true
		addresses[address] = true
	}
	return nil
}

func restrictedKey(encoded string) ([32]byte, bool) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	defer clear(raw)
	if err != nil || len(raw) != 32 || base64.StdEncoding.EncodeToString(raw) != encoded {
		return [32]byte{}, false
	}
	key := [32]byte(raw)
	return key, key != [32]byte{}
}

func validGuestIPv4(address netip.Addr) bool {
	if !address.Is4() {
		return false
	}
	first := address.As4()[0]
	return first != 0 && first != 127 && first < 224
}
