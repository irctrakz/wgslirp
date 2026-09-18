package socket

import (
	"fmt"
	"strconv"
	"strings"
)

// ConfigFromEnv overlays explicitly present environment values onto a copy of
// base, then validates the complete result. It never reads the process environment
// itself and leaves base unchanged, including on error. Empty values are errors.
func ConfigFromEnv(base Config, lookup func(string) (string, bool)) (Config, error) {
	cfg := base
	transport := base.transportConfig()
	cfg.Transport = &transport
	for _, setting := range []struct {
		name   string
		target *int
	}{
		{"TCP_ACK_IDLE_GATE_MS", &transport.AckIdleGateMs},
		{"TCP_ACK_IDLE_MIN_INFLIGHT", &transport.AckIdleMinInflight},
		{"TCP_ACK_IDLE_FAIL_SEC", &transport.AckIdleFailSec},
		{"TCP_MSS_CLAMP", &transport.MSSClamp},
		{"TCP_PACE_US", &transport.PaceUS},
		{"TCP_FAST_DIAL_MS", &transport.FastDialMs},
		{"TCP_INIT_CWND_MSS", &transport.InitialCwndMSS},
		{"TCP_SOCK_RCVBUF", &transport.SocketReceiveBuffer},
		{"TCP_SOCK_SNDBUF", &transport.SocketSendBuffer},
		{"TCP_WS_OUT", &transport.WindowScale},
		{"IP_TTL", &transport.TTL},
		{"TCP_ACK_DELAY_MS", &cfg.TCPAckDelayMs},
		{"TCP_FLOW_LIFETIME_SEC", &cfg.TCPFlowLifetimeSec},
		{"UDP_FLOW_LIFETIME_SEC", &cfg.UDPFlowLifetimeSec},
		{"TCP_REASSEMBLY_CAP_BYTES", &cfg.TCPReassemblyCapBytes},
		{"MAX_TCP_FLOWS", &cfg.MaxTCPFlows},
		{"MAX_UDP_FLOWS", &cfg.MaxUDPFlows},
		{"MAX_PENDING_TCP_DIALS", &cfg.MaxPendingTCPDials},
		{"SOCKET_BUFFER_CAP_BYTES", &cfg.SocketBufferCapBytes},
		{"TCP_PEND_CAP_BYTES", &cfg.TCPPendingCapBytes},
		{"TCP_RETRANSMIT_CAP_BYTES", &cfg.TCPRetransmitCapBytes},
	} {
		if value, present := lookup(setting.name); present {
			number, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil || number < 0 {
				return cfg, fmt.Errorf("%s must be a nonnegative integer", setting.name)
			}
			*setting.target = number
		}
	}
	for _, setting := range []struct {
		name   string
		target *bool
	}{
		{"TCP_ACK_TRACE", &transport.AckTrace}, {"TCP_LOG_HANDSHAKE", &transport.LogHandshake},
		{"TCP_ENABLE_SACK", &transport.EnableSACK}, {"COPY_TOS", &transport.CopyTOS},
	} {
		if value, present := lookup(setting.name); present {
			switch strings.ToLower(strings.TrimSpace(value)) {
			case "1", "true", "yes", "on":
				*setting.target = true
			case "0", "false", "no", "off":
				*setting.target = false
			default:
				return cfg, fmt.Errorf("%s must be a boolean (true/false, 1/0, yes/no or on/off)", setting.name)
			}
		}
	}
	for _, setting := range []struct {
		name   string
		target *string
	}{
		{"TCP_ERROR_SIGNAL", &transport.ErrorSignal}, {"TCP_GATE_LOG", &transport.GateLog},
		{"TCP_CC", &transport.CongestionControl},
	} {
		if value, present := lookup(setting.name); present {
			*setting.target = strings.ToLower(strings.TrimSpace(value))
		}
	}
	switch transport.GateLog {
	case "0", "false", "no":
		transport.GateLog = "off"
	case "1", "true", "yes":
		transport.GateLog = "info"
	}
	switch transport.CongestionControl {
	case "reno", "new-reno":
		transport.CongestionControl = "newreno"
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg.Effective(), nil
}
