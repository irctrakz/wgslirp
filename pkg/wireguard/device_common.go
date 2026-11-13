package wireguard

import "net/netip"

// PeerDevice is the optional live peer capability of a device handle.
type PeerDevice interface {
	AddPeer(publicKey [32]byte, address netip.Addr) error
	RemovePeer(publicKey [32]byte) error
}

// DeviceHandle is a minimal lifecycle for the WG device.
type DeviceHandle interface {
	Close() error
	// IpcGet returns the current device state in UAPI text form.
	IpcGet() (string, error)
	// RebindListenPort updates the device's UDP listen port (0 = random).
	RebindListenPort(port int) error
}
