package application

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/irctrakz/wgslirp/pkg/socket"
	wg "github.com/irctrakz/wgslirp/pkg/wireguard"
)

func TestRestrictedConfiguration(t *testing.T) {
	policy, err := socket.NewDestinationPolicy([]socket.TCPMapping{{
		Guest: netip.MustParseAddrPort("10.77.0.1:8096"),
		Host:  netip.MustParseAddrPort("127.0.0.1:8097"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		edit func(*Config)
	}{
		{name: "valid"},
		{name: "overlay", edit: func(c *Config) { c.Device.Options = &wg.DeviceOptions{OverlayRouting: true} }},
		{name: "capture", edit: func(c *Config) { c.Capture.Path = "capture.pcap" }},
		{name: "echo", edit: func(c *Config) { c.Socket.ICMPEcho = true }},
		{name: "non-TCP", edit: func(c *Config) { c.Socket.Protocol = "ip4:udp" }},
		{name: "unlimited TCP", edit: func(c *Config) { c.Socket.MaxTCPFlows = 0 }},
		{name: "zero policy", edit: func(c *Config) { c.Socket.Destinations = &socket.DestinationPolicy{} }},
		{name: "service address", edit: func(c *Config) { c.Device.Peers[0].AllowedIPs = []string{"10.77.0.1/32"} }},
		{name: "overlap", edit: func(c *Config) { c.Device.Peers[0].AllowedIPs = []string{"10.77.0.0/24"} }},
		{name: "loopback", edit: func(c *Config) { c.Device.Peers[0].AllowedIPs = []string{"127.0.0.1/32"} }},
		{name: "active peer", edit: func(c *Config) { c.Device.Peers[0].Endpoint = "localhost:51820" }},
		{name: "server public key", edit: func(c *Config) { c.Device.Peers[0].PublicKey = publicBase64 }},
		{name: "hex key", edit: func(c *Config) { c.Device.Peers[0].PublicKey = peerHex }},
		{name: "duplicate peer key", edit: func(c *Config) {
			c.Device.Peers = append(c.Device.Peers, wg.PeerConfig{
				PublicKey: c.Device.Peers[0].PublicKey, AllowedIPs: []string{"10.77.0.3/32"},
			})
		}},
		{name: "duplicate source address", edit: func(c *Config) {
			c.Device.Peers = append(c.Device.Peers, wg.PeerConfig{
				PublicKey: "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=", AllowedIPs: []string{"10.77.0.2/32"},
			})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.Socket.Destinations = policy
			cfg.Device.Peers = []wg.PeerConfig{{
				PublicKey: "3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=", AllowedIPs: []string{"10.77.0.2/32"},
			}}
			if test.edit != nil {
				test.edit(&cfg)
			}
			err := cfg.Validate()
			if (err == nil) != (test.edit == nil) {
				t.Fatalf("validation: %v", err)
			}
			if err != nil && (strings.Contains(err.Error(), cfg.Device.PrivateKey) || strings.Contains(err.Error(), privateHex)) {
				t.Fatal("validation exposed private key")
			}
		})
	}
}
