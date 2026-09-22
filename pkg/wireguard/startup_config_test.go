package wireguard

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDeviceEnvironmentSnapshot(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	values := map[string]string{"WG_PRIVATE_KEY": key, "WG_LISTEN_PORT": "0", "WG_MTU": "1400", "WG_PEERS": "0",
		"WG_PEER_0_PUBLIC_KEY": key, "WG_PEER_0_ALLOWED_IPS": "10.1.0.0/16", "WG_PEER_0_ENDPOINT": "localhost:1234", "WG_PEER_0_KEEPALIVE": "25",
		"DEBUG": "true", "WG_DEBUG": "yes", "WG_DISABLE_IPV6": "off", "WG_OVERLAY_ROUTING": "1", "WG_OVERLAY_EXCLUDE_CIDRS": "10.2.0.0/16"}
	lookup := func(k string) (string, bool) { v, ok := values[k]; return v, ok }
	cfg, err := DeviceConfigFromEnv(lookup)
	if err != nil {
		t.Fatal(err)
	}
	want := DeviceOptions{true, true, true, []string{"10.2.0.0/16"}, false}
	options := cfg.deviceOptions()
	cfg.Options.OverlayExcludeCIDRs[0] = "10.3.0.0/16"
	for k := range values {
		t.Setenv(k, "invalid")
	}
	if !reflect.DeepEqual(options, want) || cfg.ListenPort != 0 || cfg.MTU != 1400 || len(cfg.Peers) != 1 || cfg.Peers[0].Endpoint != "localhost:1234" || cfg.Peers[0].PersistentKeepaliveSec != 25 || cfg.Peers[0].AllowedIPs[0] != "10.1.0.0/16" {
		t.Fatal("device configuration not effective/copied")
	}
	for k, v := range map[string]string{"DEBUG": "maybe", "WG_DEBUG": "", "WG_DISABLE_IPV6": "invalid", "WG_OVERLAY_ROUTING": "2", "WG_OVERLAY_EXCLUDE_CIDRS": "bad", "WG_MTU": "", "WG_LISTEN_PORT": "65536", "WG_PEER_0_KEEPALIVE": "-1"} {
		old := values[k]
		values[k] = v
		if _, err := DeviceConfigFromEnv(lookup); err == nil {
			t.Errorf("accepted invalid %s", k)
		}
		values[k] = old
	}
	previous := cfg
	if err := cfg.LoadFromEnv(); err == nil || !reflect.DeepEqual(cfg, previous) {
		t.Fatal("failed load mutated configuration")
	}
	if DefaultDeviceOptions().DisableIPv6 {
		t.Fatal("default configuration must leave IPv6 sysctls unchanged")
	}
}

func TestIPv6SysctlOptIn(t *testing.T) {
	for _, value := range []string{"unset", "false", "0", "off", "no", "true", "1", "on", "yes"} {
		t.Run(value, func(t *testing.T) {
			options, err := DeviceOptionsFromEnv(func(key string) (string, bool) {
				return value, key == "WG_DISABLE_IPV6" && value != "unset"
			})
			want := value == "true" || value == "1" || value == "on" || value == "yes"
			if err != nil || options.DisableIPv6 != want {
				t.Fatalf("IPv6 opt-in %q: options=%+v err=%v", value, options, err)
			}
		})
	}
	// Both omitted library options and explicit zero options leave sysctls alone.
	if (DeviceConfig{}).deviceOptions().DisableIPv6 || (DeviceConfig{Options: &DeviceOptions{}}).deviceOptions().DisableIPv6 {
		t.Fatal("library default unexpectedly enables sysctl writes")
	}
	if !(DeviceConfig{Options: &DeviceOptions{DisableIPv6: true}}).deviceOptions().DisableIPv6 {
		t.Fatal("explicit library opt-in was lost")
	}
}

func TestTunConfigSnapshot(t *testing.T) {
	t.Setenv("WG_TUN_QUEUE_CAP", "3")
	cfg, err := TunConfigFromEnv(os.LookupEnv)
	if err != nil {
		t.Fatal(err)
	}
	tun, err := NewWGTunWithConfig("test", 1380, nil, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	legacy := NewWGTun("test", 1380, nil)
	defer legacy.Close()
	t.Setenv("WG_TUN_QUEUE_CAP", "4")
	cfg.QueueCapacity = 9
	if cap(tun.outCh) != 3 || cap(legacy.outCh) != 3 {
		t.Fatal("queue snapshot changed")
	}
	for _, n := range []int{0, -1, 65537} {
		if tun, err := NewWGTunWithConfig("test", 1380, nil, TunConfig{n}); err == nil || tun != nil {
			t.Fatal("allocated invalid queue")
		}
	}
	t.Setenv("WG_TUN_QUEUE_CAP", "bad")
	if _, err := TunConfigFromEnv(os.LookupEnv); err == nil {
		t.Fatal("invalid queue accepted")
	}
	legacyBad := NewWGTun("test", 1380, nil)
	defer legacyBad.Close()
	if cap(legacyBad.outCh) != 1024 {
		t.Fatal("legacy invalid fallback")
	}
}

func TestCaptureCannotFollowEnvironmentOrReopen(t *testing.T) {
	_ = ClosePCAP()
	pcapConfig = nil
	pcapFailed = false
	t.Cleanup(func() { _ = ClosePCAP(); pcapConfig = nil; pcapFailed = false })
	path := filepath.Join(t.TempDir(), "first.pcap")
	other := filepath.Join(t.TempDir(), "second.pcap")
	t.Setenv("WG_PCAP", path)
	t.Setenv("WG_PCAP_MAX_BYTES", "44")
	cfg, err := CaptureConfigFromEnv(os.LookupEnv)
	if err != nil {
		t.Fatal(err)
	}
	if err := ConfigurePCAP(cfg); err != nil {
		t.Fatal(err)
	}
	if err := ConfigurePCAP(cfg); err != nil {
		t.Fatal("same config not idempotent")
	}
	t.Setenv("WG_PCAP", other)
	t.Setenv("WG_PCAP_MAX_BYTES", "9999")
	pcapWriteIPv4([]byte{0x45, 0, 0, 0})
	pcapWriteIPv4([]byte{0x45})
	info, err := os.Stat(path)
	if err != nil || info.Size() != 44 {
		t.Fatal("capture ignored snapshot/limit")
	}
	if _, err := os.Stat(other); !os.IsNotExist(err) {
		t.Fatal("environment redirected capture")
	}
	if err := ConfigurePCAP(cfg); err == nil {
		t.Fatal("reopened completed capture")
	}
	if err := ConfigurePCAP(CaptureConfig{other, 44}); err == nil {
		t.Fatal("changed live capture policy")
	}
	for _, v := range []string{"", "0", "23", "invalid", "9223372036854775808"} {
		t.Setenv("WG_PCAP_MAX_BYTES", v)
		if _, err := CaptureConfigFromEnv(os.LookupEnv); err == nil {
			t.Errorf("accepted limit %q", v)
		}
	}
}
