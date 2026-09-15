package wireguard

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// PeerConfig holds a single WireGuard peer configuration.
type PeerConfig struct {
	PublicKey              string   // base64
	AllowedIPs             []string // CIDRs
	Endpoint               string   // host:port
	PersistentKeepaliveSec int      // optional
}

// DeviceConfig holds the WireGuard device configuration for WG-only mode.
type DeviceConfig struct {
	ListenPort int
	PrivateKey string // base64
	MTU        int    // plaintext MTU for wg tun
	Peers      []PeerConfig
}

// LoadFromEnv builds a DeviceConfig from environment variables.
//
// Required:
//
//	WG_PRIVATE_KEY  (base64)
//
// Optional:
//
//	WG_LISTEN_PORT (default 51820)
//	WG_MTU (default 1380)
//	WG_PEERS (comma-separated peer indices, e.g., "0,1")
//
// For each index i in WG_PEERS, read:
//
//	WG_PEER_i_PUBLIC_KEY
//	WG_PEER_i_ALLOWED_IPS (comma-separated CIDRs)
//	WG_PEER_i_ENDPOINT (host:port)
//	WG_PEER_i_KEEPALIVE (seconds, optional)
func (c *DeviceConfig) LoadFromEnv() error {
	pk := strings.TrimSpace(os.Getenv("WG_PRIVATE_KEY"))
	if pk == "" {
		return fmt.Errorf("WG_PRIVATE_KEY is required")
	}
	c.PrivateKey = pk
	lp := 51820
	if v := os.Getenv("WG_LISTEN_PORT"); v != "" {
		x, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("WG_LISTEN_PORT must be an integer")
		}
		lp = x
	}
	c.ListenPort = lp
	mtu := 1380
	if v := os.Getenv("WG_MTU"); v != "" {
		x, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("WG_MTU must be an integer")
		}
		mtu = x
	}
	c.MTU = mtu

	var peers []PeerConfig
	idxs := strings.TrimSpace(os.Getenv("WG_PEERS"))
	if idxs != "" {
		for _, s := range strings.Split(idxs, ",") {
			i := strings.TrimSpace(s)
			if i == "" {
				continue
			}
			p := PeerConfig{}
			p.PublicKey = strings.TrimSpace(os.Getenv("WG_PEER_" + i + "_PUBLIC_KEY"))
			allowed := strings.TrimSpace(os.Getenv("WG_PEER_" + i + "_ALLOWED_IPS"))
			if allowed != "" {
				p.AllowedIPs = splitCSV(allowed)
			}
			p.Endpoint = strings.TrimSpace(os.Getenv("WG_PEER_" + i + "_ENDPOINT"))
			if ka := strings.TrimSpace(os.Getenv("WG_PEER_" + i + "_KEEPALIVE")); ka != "" {
				x, err := strconv.Atoi(ka)
				if err != nil {
					return fmt.Errorf("WG_PEER_%s_KEEPALIVE must be an integer", i)
				}
				p.PersistentKeepaliveSec = x
			}
			if p.PublicKey == "" {
				return fmt.Errorf("WG_PEER_%s_PUBLIC_KEY is required", i)
			}
			peers = append(peers, p)
		}
	}
	c.Peers = peers
	return c.Validate()
}

// Validate checks the complete device configuration before any device is opened.
// Errors deliberately omit key values.
func (c DeviceConfig) Validate() error {
	key, err := base64.StdEncoding.DecodeString(c.PrivateKey)
	if err != nil || len(key) != 32 {
		return fmt.Errorf("WG_PRIVATE_KEY must encode 32 bytes in base64")
	}
	if c.ListenPort < 0 || c.ListenPort > 65535 {
		return fmt.Errorf("WG_LISTEN_PORT must be between 0 and 65535")
	}
	if c.MTU < 576 || c.MTU > 65535 {
		return fmt.Errorf("WG_MTU must be between 576 and 65535")
	}
	for i, p := range c.Peers {
		raw, err := base64.StdEncoding.DecodeString(p.PublicKey)
		if err != nil || len(raw) != 32 {
			raw, err = hex.DecodeString(p.PublicKey)
		}
		if err != nil || len(raw) != 32 {
			return fmt.Errorf("peer %d public key must encode 32 bytes", i)
		}
		if p.PersistentKeepaliveSec < 0 || p.PersistentKeepaliveSec > 65535 {
			return fmt.Errorf("peer %d keepalive must be between 0 and 65535", i)
		}
		for _, cidr := range p.AllowedIPs {
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				return fmt.Errorf("peer %d has an invalid allowed IP prefix", i)
			}
		}
		if p.Endpoint != "" {
			host, port, err := net.SplitHostPort(p.Endpoint)
			n, numberErr := strconv.Atoi(port)
			if err != nil || host == "" || numberErr != nil || n < 1 || n > 65535 {
				return fmt.Errorf("peer %d endpoint must be host:port with a valid port", i)
			}
		}
	}
	return nil
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
