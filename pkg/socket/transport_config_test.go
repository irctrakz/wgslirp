package socket

import (
	"math"
	"os"
	"testing"
	"time"
)

func TestTransportEnvironmentAndSnapshot(t *testing.T) {
	values := map[string]string{
		"TCP_ACK_IDLE_GATE_MS": "23", "TCP_ACK_IDLE_MIN_INFLIGHT": "1234", "TCP_ACK_IDLE_FAIL_SEC": "19",
		"TCP_ACK_TRACE": "yes", "TCP_MSS_CLAMP": "1000", "TCP_PACE_US": "13", "TCP_ERROR_SIGNAL": "rst",
		"TCP_LOG_HANDSHAKE": "on", "TCP_FAST_DIAL_MS": "17", "TCP_CC": "new-reno",
		"TCP_INIT_CWND_MSS": "2", "TCP_SOCK_RCVBUF": "4096", "TCP_SOCK_SNDBUF": "8192", "TCP_WS_OUT": "3",
		"TCP_ENABLE_SACK": "true", "COPY_TOS": "1", "IP_TTL": "42",
	}
	for key, value := range values {
		t.Setenv(key, value)
	}
	base := DefaultConfig()
	base.Protocol = "ip4:tcp"
	cfg, err := ConfigFromEnv(base, os.LookupEnv)
	if err != nil {
		t.Fatal(err)
	}
	want := TransportConfig{23, 1234, 19, true, 1000, 13, "rst", true, 17, "newreno", 2, 4096, 8192, 3, true, true, 42}
	if *cfg.Transport != want {
		t.Fatalf("parsed %+v; want %+v", *cfg.Transport, want)
	}
	if *base.Transport != DefaultTransportConfig() {
		t.Fatal("parser changed caller template")
	}
	s := NewSocketInterface(cfg)
	// Neither caller edits nor changes before Start may alter an existing object.
	*cfg.Transport = DefaultTransportConfig()
	for key := range values {
		t.Setenv(key, "invalid")
	}
	s.SetPacketProcessor(&captureProcessor{})
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	b := s.tcp
	if b.tuning != want || s.ttlOverride != 42 || !s.tosCopy ||
		b.ackIdleGate != 23*time.Millisecond || b.ackIdleMinInflight != 1234 || b.ackIdleFail != 19*time.Second ||
		!b.ackTrace || b.mssClamp.Load() != 1000 || b.paceUS.Load() != 13 || b.errorSignal != "rst" ||
		!b.logHandshake {
		t.Fatal("runtime ignored transport snapshot")
	}
}

func TestInvalidTransportFailsBeforeStartup(t *testing.T) {
	for key, value := range map[string]string{
		"TCP_ACK_IDLE_GATE_MS": "9223372036854775807", "TCP_ACK_IDLE_FAIL_SEC": "9223372036854775807",
		"TCP_PACE_US": "9223372036854775807", "TCP_FAST_DIAL_MS": "9223372036854775807",
		"TCP_ACK_IDLE_MIN_INFLIGHT": "-1", "TCP_MSS_CLAMP": "65536", "TCP_INIT_CWND_MSS": "-1",
		"TCP_SOCK_RCVBUF": "2147483648", "TCP_SOCK_SNDBUF": "-1", "TCP_WS_OUT": "15", "IP_TTL": "0",
		"TCP_ACK_TRACE": "maybe", "TCP_LOG_HANDSHAKE": "", "TCP_ENABLE_SACK": "2", "COPY_TOS": "unknown",
		"TCP_ERROR_SIGNAL": "invalid", "TCP_GATE_LOG": "verbose", "TCP_CC": "cubic",
	} {
		t.Run(key, func(t *testing.T) {
			cfg, err := ConfigFromEnv(DefaultConfig(), func(name string) (string, bool) { return value, name == key })
			if err == nil {
				t.Fatalf("accepted %s=%s", key, value)
			}
			// Use a direct typed invalid value to verify constructor validation precedes resources.
			cfg.Transport.TTL = 256
			s := NewSocketInterface(cfg)
			s.SetPacketProcessor(&captureProcessor{})
			if s.Start() == nil {
				s.Stop()
				t.Fatal("started invalid configuration")
			}
			if s.conn != nil || s.tcp != nil || s.udp != nil {
				t.Fatal("created resources before validation")
			}
		})
	}
}

func TestTransportDefaultsAndBoundaries(t *testing.T) {
	if (Config{}).transportConfig() != DefaultTransportConfig() {
		t.Fatal("nil tuning lost defaults")
	}
	cfg, err := ConfigFromEnv(DefaultConfig(), func(key string) (string, bool) {
		switch key {
		case "TCP_ACK_IDLE_GATE_MS", "TCP_ACK_IDLE_FAIL_SEC", "TCP_FAST_DIAL_MS", "TCP_WS_OUT":
			return "0", true
		case "TCP_CC":
			return "off", true
		}
		return "", false
	})
	if err != nil {
		t.Fatal(err)
	}
	b := newTCPBridge(NewSocketInterface(cfg))
	defer b.stop()
	if b.ackIdleGate != 0 || b.ackIdleFail != 0 || b.tuning.WindowScale != 0 || b.tuning.CongestionControl != "off" {
		t.Fatal("zero/off overrides ignored")
	}
	for _, tc := range []struct{ override, want int }{{0, 10000}, {1, 1000}, {2, 2000}, {10, 10000}, {math.MaxInt32, 10000}} {
		if got := newNewReno(1000, tc.override).Cwnd(); got != tc.want {
			t.Fatalf("override %d: got %d want %d", tc.override, got, tc.want)
		}
	}
}
