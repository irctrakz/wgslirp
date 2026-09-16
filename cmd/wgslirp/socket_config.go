package main

import (
	"fmt"
	"github.com/irctrakz/wgslirp/pkg/socket"
	"strconv"
	"strings"
)

// socketConfig reads these resource controls once at the application boundary.
// Explicit environment values override defaults; zero caps retain unlimited
// active flows for compatibility. Other TCP tuning is migrated separately.
func socketConfig(mtu int, lookup func(string) (string, bool)) (socket.Config, error) {
	cfg := socket.DefaultConfig()
	cfg.MTU = mtu
	cfg.Protocol = "ip4:tcp"
	for _, setting := range []struct {
		name   string
		target *int
	}{
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
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}
