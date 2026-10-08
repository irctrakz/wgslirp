package socket

import (
	"fmt"
	"math"
	"time"
)

// TransportConfig controls TCP behavior and synthesized IP headers. It contains
// only values; constructors snapshot it so callers can safely reuse a template.
type TransportConfig struct {
	AckIdleGateMs      int // zero disables gating
	AckIdleMinInflight int // zero uses one MSS
	AckIdleFailSec     int // zero disables ACK-idle failure
	AckTrace           bool
	MSSClamp           int // zero leaves the peer/MTU limit unchanged
	PaceUS             int
	ErrorSignal        string // icmp, rst, none
	LogHandshake       bool
	// Deprecated: retained for configuration compatibility; send-gate logging has no active caller.
	GateLog             string // accepted values: info, debug, off
	FastDialMs          int    // zero retains the historical one-millisecond minimum
	CongestionControl   string // newreno or off
	InitialCwndMSS      int    // zero uses RFC 6928; positive values only reduce the window
	SocketReceiveBuffer int    // zero uses the OS default
	SocketSendBuffer    int    // zero uses the OS default
	WindowScale         int    // 0..14
	EnableSACK          bool   // force SACK even when not offered by the peer (legacy option)
	CopyTOS             bool
	TTL                 int // 1..255
}

func DefaultTransportConfig() TransportConfig {
	return TransportConfig{AckIdleGateMs: 6000, AckIdleFailSec: 120,
		ErrorSignal: "icmp", GateLog: "info", FastDialMs: 5,
		CongestionControl: "newreno", WindowScale: 7, TTL: 64}
}

func (c Config) transportConfig() TransportConfig {
	if c.Transport == nil {
		return DefaultTransportConfig()
	}
	return *c.Transport
}

func (c TransportConfig) Validate() error {
	for _, s := range []struct {
		name  string
		value int
		max   uint64
	}{
		{"TCP_ACK_IDLE_GATE_MS", c.AckIdleGateMs, uint64(math.MaxInt64 / int64(time.Millisecond))},
		{"TCP_ACK_IDLE_MIN_INFLIGHT", c.AckIdleMinInflight, math.MaxInt32},
		{"TCP_ACK_IDLE_FAIL_SEC", c.AckIdleFailSec, uint64(math.MaxInt64 / int64(time.Second))},
		{"TCP_MSS_CLAMP", c.MSSClamp, 65535},
		{"TCP_PACE_US", c.PaceUS, uint64(math.MaxInt64 / int64(time.Microsecond))},
		{"TCP_FAST_DIAL_MS", c.FastDialMs, uint64(math.MaxInt64 / int64(time.Millisecond))},
		{"TCP_INIT_CWND_MSS", c.InitialCwndMSS, math.MaxInt32},
		{"TCP_SOCK_RCVBUF", c.SocketReceiveBuffer, math.MaxInt32},
		{"TCP_SOCK_SNDBUF", c.SocketSendBuffer, math.MaxInt32},
		{"TCP_WS_OUT", c.WindowScale, 14},
		{"IP_TTL", c.TTL, 255},
	} {
		if s.value < 0 || uint64(s.value) > s.max {
			return fmt.Errorf("%s must be between 0 and %d", s.name, s.max)
		}
	}
	if c.TTL == 0 {
		return fmt.Errorf("IP_TTL must be between 1 and 255")
	}
	switch c.ErrorSignal {
	case "icmp", "rst", "none":
	default:
		return fmt.Errorf("TCP_ERROR_SIGNAL must be icmp, rst or none")
	}
	switch c.GateLog {
	case "info", "debug", "off":
	default:
		return fmt.Errorf("TCP_GATE_LOG must be info, debug or off")
	}
	switch c.CongestionControl {
	case "newreno", "off":
	default:
		return fmt.Errorf("TCP_CC must be newreno or off")
	}
	return nil
}
