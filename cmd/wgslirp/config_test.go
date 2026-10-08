package main

import (
	"encoding/base64"
	"encoding/json"
	"golang.org/x/net/dns/dnsmessage"
	"strings"
	"testing"
	"time"
)

func TestApplicationConfigurationSnapshotAndSummary(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	entries := []string{"WG_PRIVATE_KEY=" + key, "WG_LISTEN_PORT=12345", "WG_MTU=1420", "WG_PEER_0_PUBLIC_KEY=" + key,
		"WG_PEER_0_ENDPOINT=private.example:1234", "WG_PEER_0_ALLOWED_IPS=10.3.0.0/16", "WG_DEBUG=true", "DEBUG=true", "WG_DISABLE_IPV6=false",
		"WG_OVERLAY_ROUTING=true", "WG_OVERLAY_EXCLUDE_CIDRS=10.4.0.0/16", "WG_TUN_QUEUE_CAP=7", "WG_PCAP=/private/capture", "WG_PCAP_MAX_BYTES=44",
		"POOLING=true", "HEALTHCHECK=true", "HEALTH_HTTP_URL=https://user:password@private.example/path?token=secret",
		"HEALTH_DNS_NAME=health.example", "HEALTH_DNS_IP=127.0.0.2", "METRICS_LOG=true", "METRICS_INTERVAL=7s", "METRICS_FORMAT=json", "PRINT_CONFIG=yes",
		"PROCESSOR_WORKERS=8", "PROCESSOR_QUEUE_CAP=2048"}
	lookup := snapshotEnvironment(entries)
	for i := range entries {
		entries[i] = "changed"
	}
	cfg, err := loadApplicationConfig(lookup)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Socket.MTU != 1420 || cfg.Tun.QueueCapacity != 7 || !cfg.Pool.Enabled || !cfg.Health.Enabled ||
		cfg.Health.DNSName != "health.example" || cfg.Health.DNSIP != "127.0.0.2" || cfg.MetricsInterval != 7*time.Second || cfg.MetricsFormat != "json" ||
		!cfg.Metrics || !cfg.PrintConfig || cfg.Capture.Path != "/private/capture" || cfg.Capture.MaxBytes != 44 || len(cfg.Warnings) != 2 {
		t.Fatalf("configuration: %+v", cfg.Health)
	}
	summary := cfg.effectiveSummary()
	if strings.Contains(summary, `"Wrap"`) || strings.Contains(summary, `"GateLog"`) {
		t.Fatal("summary retained retired configuration")
	}
	if !json.Valid([]byte(summary)) {
		t.Fatal("invalid summary JSON")
	}
	for _, secret := range []string{key, "private.example", "password", "secret", "/private/capture", "health.example", "10.3.", "10.4."} {
		if strings.Contains(summary, secret) {
			t.Fatalf("summary leaked %q", secret)
		}
	}
	for _, field := range []string{`"QueueCapacity":7`, `"ListenPort":12345`, `"PeerCount":1`, `"MetricsFormat":"json"`, `"CaptureMaxBytes":44`} {
		if !strings.Contains(summary, field) {
			t.Errorf("missing effective value %s", field)
		}
	}
	// The configured health name is used in both the emitted query and validation.
	var query dnsmessage.Message
	if err := query.Unpack(buildDNSQuery(13, cfg.Health.DNSName)); err != nil {
		t.Fatal(err)
	}
	if query.Questions[0].Name.String() != "health.example." {
		t.Fatal("health query ignored configured name")
	}
	query.Response = true
	query.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: query.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}, Body: &dnsmessage.AResource{A: [4]byte{1, 2, 3, 4}}}}
	body, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	server, client := [4]byte{127, 0, 0, 2}, [4]byte{10, 0, 0, 2}
	reply := buildIPv4UDP(server, client, 53, 40053, body)
	if !validDNSHealthReplyForName(reply, server, client, 13, cfg.Health.DNSName) || validDNSHealthReply(reply, server, client, 13) {
		t.Fatal("health reply name mismatch")
	}
}

func TestApplicationDefaultsAndInvalidSettings(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	defaults, err := loadApplicationConfig(snapshotEnvironment([]string{"WG_PRIVATE_KEY=" + key}))
	if err != nil {
		t.Fatal(err)
	}
	if defaults.Device.ListenPort != 51820 || defaults.Device.MTU != 1380 || defaults.Device.Options.DisableIPv6 || defaults.Tun.QueueCapacity != 1024 ||
		!defaults.Pool.Enabled || defaults.Health.Enabled || defaults.Metrics || defaults.PrintConfig || defaults.MetricsInterval != 30*time.Second || defaults.MetricsFormat != "text" ||
		defaults.Health.DNSName != "example.com" || defaults.Health.DNSIP != "1.1.1.1" || defaults.Health.HTTPURL != "https://httpbin.org/ip" || defaults.Capture.MaxBytes != 64*1024*1024 {
		t.Fatal("unexpected defaults")
	}
	for k, v := range map[string]string{"METRICS_LOG": "maybe", "HEALTHCHECK": "", "PRINT_CONFIG": "2", "METRICS_INTERVAL": "0s", "METRICS_FORMAT": "xml",
		"HEALTH_HTTP_URL": "file:///tmp/example", "HEALTH_DNS_IP": "::1", "HEALTH_DNS_NAME": "", "WG_TUN_QUEUE_CAP": "65537", "POOLING": "bad", "POOL_WRAP": "bad", "WG_PCAP_MAX_BYTES": "23"} {
		t.Run(k, func(t *testing.T) {
			_, err := loadApplicationConfig(snapshotEnvironment([]string{"WG_PRIVATE_KEY=" + key, k + "=" + v}))
			if err == nil || !strings.Contains(err.Error(), k) {
				t.Fatalf("invalid setting %s: %v", k, err)
			}
		})
	}
	for _, tc := range []struct {
		entries []string
		want    bool
	}{{[]string{"METRICS_INTERVAL=2s"}, true}, {[]string{"METRICS_INTERVAL=2s", "METRICS_LOG=false"}, false}, {[]string{"METRICS_LOG=true"}, true}} {
		c, err := loadApplicationConfig(snapshotEnvironment(append(tc.entries, "WG_PRIVATE_KEY="+key)))
		if err != nil || c.Metrics != tc.want {
			t.Fatal("metrics precedence", err)
		}
	}
}

func TestApplicationRejectsRetiredSettings(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	for _, name := range []string{"POOL_WRAP", "TCP_GATE_LOG"} {
		for _, value := range []string{"", "false", "off", "true"} {
			_, err := loadApplicationConfig(snapshotEnvironment([]string{"WG_PRIVATE_KEY=" + key, name + "=" + value}))
			if err == nil || !strings.Contains(err.Error(), name) || !strings.Contains(err.Error(), "remove this setting") {
				t.Fatal("missing startup migration error", name, err)
			}
		}
	}
}

func TestEffectiveZeroDefaults(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	c, err := loadApplicationConfig(snapshotEnvironment([]string{"WG_PRIVATE_KEY=" + key,
		"MAX_PENDING_TCP_DIALS=0", "SOCKET_BUFFER_CAP_BYTES=0", "TCP_PEND_CAP_BYTES=0", "TCP_RETRANSMIT_CAP_BYTES=0",
		"TCP_FLOW_LIFETIME_SEC=0", "UDP_FLOW_LIFETIME_SEC=0", "TCP_REASSEMBLY_CAP_BYTES=0", "MAX_TCP_FLOWS=0", "TCP_ACK_DELAY_MS=0"}))
	if err != nil {
		t.Fatal(err)
	}
	s := c.Socket
	if s.MaxPendingTCPDials != 64 || s.SocketBufferCapBytes != 67108864 || s.TCPPendingCapBytes != 65536 || s.TCPRetransmitCapBytes != 1048576 ||
		s.TCPFlowLifetimeSec != 120 || s.UDPFlowLifetimeSec != 60 || s.TCPReassemblyCapBytes != 131072 || s.MaxTCPFlows != 0 || s.TCPAckDelayMs != 0 {
		t.Fatalf("effective defaults incorrect: %+v", s)
	}
}
