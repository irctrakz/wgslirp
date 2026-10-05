package wireguard

import (
	"encoding/base64"
	"reflect"
	"strings"
	"testing"
)

func TestPeerDiscoveryAndExplicitSelection(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	for _, tc := range []struct {
		name      string
		selection *string
		want      []string
	}{
		{"discover sparse numeric order", nil, []string{"10.77.0.3/32", "10.77.0.2/32"}},
		{"explicit order", stringPointer("10,2"), []string{"10.77.0.2/32", "10.77.0.3/32"}},
		{"explicit subset", stringPointer("10"), []string{"10.77.0.2/32"}},
		{"explicit empty", stringPointer(""), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := map[string]string{"WG_PRIVATE_KEY": key,
				"WG_PEER_10_PUBLIC_KEY": key, "WG_PEER_10_ALLOWED_IPS": "10.77.0.2/32",
				"WG_PEER_2_PUBLIC_KEY": key, "WG_PEER_2_ALLOWED_IPS": "10.77.0.3/32",
				"WG_PEER_2_KEEPALIVE": "25", "WG_PEER_2_ENDPOINT": "example.com:51820"}
			if tc.selection != nil {
				values["WG_PEERS"] = *tc.selection
			}
			before := make(map[string]string)
			for k, v := range values {
				before[k] = v
			}
			cfg, err := DeviceConfigFromEnvironment(values)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, peer := range cfg.Peers {
				got = append(got, peer.AllowedIPs[0])
				if peer.AllowedIPs[0] == "10.77.0.3/32" && (peer.PersistentKeepaliveSec != 25 || peer.Endpoint != "example.com:51820") {
					t.Fatal("discovered peer options lost")
				}
			}
			if !reflect.DeepEqual(got, tc.want) || !reflect.DeepEqual(values, before) {
				t.Fatalf("peers=%v want=%v; input must remain unchanged", got, tc.want)
			}
		})
	}
	// Names are not required to be numeric in the legacy explicit-selector API.
	cfg, err := DeviceConfigFromEnvironment(map[string]string{"WG_PRIVATE_KEY": key,
		"WG_PEERS": "client", "WG_PEER_client_PUBLIC_KEY": key, "WG_PEER_other_TYPO": "ignored"})
	if err != nil || len(cfg.Peers) != 1 {
		t.Fatalf("explicit compatibility: %v", err)
	}
	cfg, err = DeviceConfigFromEnvironment(map[string]string{"WG_PRIVATE_KEY": key})
	if err != nil || len(cfg.Peers) != 0 {
		t.Fatalf("no peers: %v", err)
	}
}

func stringPointer(value string) *string { return &value }

func TestPeerDiscoveryRejectsIncompleteAndInvalidPeers(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	for _, tc := range []struct{ name, value string }{
		{"WG_PEER_7_ALLOWED_IPS", "10.77.0.2/32"},
		{"WG_PEER_7_ENDPOINT", "example.com:51820"},
		{"WG_PEER_7_KEEPALIVE", "25"},
		{"WG_PEER_7_PUBLIC_KEY", "secret-invalid-value"},
		{"WG_PEER_01_PUBLIC_KEY", key},
		{"WG_PEER_-1_PUBLIC_KEY", key},
		{"WG_PEER_client_PUBLIC_KEY", key},
		{"WG_PEER_999999999999999999999999_PUBLIC_KEY", key},
		{"WG_PEER_0_PUBLICKEY", key},
		{"WG_PEER_0", key},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DeviceConfigFromEnvironment(map[string]string{"WG_PRIVATE_KEY": key, tc.name: tc.value})
			if err == nil {
				t.Fatal("accepted invalid peer configuration")
			}
			if strings.Contains(err.Error(), key) || strings.Contains(err.Error(), "secret-invalid-value") {
				t.Fatal("key value leaked")
			}
		})
	}
	for _, tc := range []struct{ name, value string }{
		{"WG_PEER_0_ALLOWED_IPS", "not-a-prefix"},
		{"WG_PEER_0_ENDPOINT", "bad-endpoint"},
		{"WG_PEER_0_KEEPALIVE", "-1"},
	} {
		if _, err := DeviceConfigFromEnvironment(map[string]string{"WG_PRIVATE_KEY": key,
			"WG_PEER_0_PUBLIC_KEY": key, tc.name: tc.value}); err == nil {
			t.Fatalf("accepted invalid %s", tc.name)
		}
	}
}
