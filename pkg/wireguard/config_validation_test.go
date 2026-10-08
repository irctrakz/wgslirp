package wireguard

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestDeviceConfigValidation(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	for _, tc := range []struct{ name, value string }{
		{"WG_LISTEN_PORT", "bad"}, {"WG_LISTEN_PORT", "65536"},
		{"WG_MTU", "0"}, {"WG_MTU", "575"}, {"WG_MTU", "bad"},
		{"WG_PRIVATE_KEY", "secret-invalid-value"},
	} {
		t.Run(tc.name+tc.value, func(t *testing.T) {
			t.Setenv("WG_PRIVATE_KEY", key)
			t.Setenv("WG_PEERS", "")
			t.Setenv(tc.name, tc.value)
			var c DeviceConfig
			err := c.LoadFromEnv()
			if err == nil {
				t.Fatal("accepted invalid configuration")
			}
			if strings.Contains(err.Error(), "secret-invalid-value") {
				t.Fatal("secret leaked")
			}
		})
	}
	t.Setenv("WG_PRIVATE_KEY", key)
	t.Setenv("WG_PEERS", "0")
	t.Setenv("WG_PEER_0_PUBLIC_KEY", "")
	var c DeviceConfig
	if c.LoadFromEnv() == nil {
		t.Fatal("silently skipped incomplete peer")
	}
}
