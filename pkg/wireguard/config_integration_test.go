//go:build integration

package wireguard

import (
	"bytes"
	"encoding/base64"
	"net"
	"testing"
)

func TestDeviceUsesConfiguredRoutingAfterEnvironmentChanges(t *testing.T) {
	values := map[string]string{
		"WG_PRIVATE_KEY": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)),
		"WG_LISTEN_PORT": "0", "WG_DISABLE_IPV6": "false", "WG_DEBUG": "true",
		"WG_OVERLAY_ROUTING": "true", "WG_OVERLAY_EXCLUDE_CIDRS": "10.42.0.0/24", "WG_PEERS": "0",
		"WG_PEER_0_PUBLIC_KEY":  base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)),
		"WG_PEER_0_ALLOWED_IPS": "10.41.0.0/24",
	}
	cfg, err := DeviceConfigFromEnv(func(k string) (string, bool) { v, ok := values[k]; return v, ok })
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("WG_OVERLAY_ROUTING", "false")
	t.Setenv("WG_OVERLAY_EXCLUDE_CIDRS", "10.99.0.0/24")
	t.Setenv("WG_DEBUG", "false")
	// No sysctl writes: the explicit startup configuration disables that behavior.
	tun, err := NewWGTunWithConfig("config-test", cfg.MTU, nil, TunConfig{QueueCapacity: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	dev, err := StartDevice(cfg, tun)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	cfg.Options.OverlayExcludeCIDRs[0] = "10.98.0.0/24"
	cfg.Peers[0].AllowedIPs[0] = "10.97.0.0/24"
	if !tun.dstInPeerCIDR(net.ParseIP("10.41.0.1")) || !tun.dstInExclude(net.ParseIP("10.42.0.1")) ||
		tun.dstInPeerCIDR(net.ParseIP("10.97.0.1")) || tun.dstInExclude(net.ParseIP("10.98.0.1")) || tun.dstInExclude(net.ParseIP("10.99.0.1")) {
		t.Fatal("device routing followed environment or caller mutation")
	}
}
