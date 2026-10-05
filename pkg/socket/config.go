package socket

import (
	"errors"
	"fmt"
	"math"
	"time"
)

// ErrFlowLimit indicates that an active-flow admission limit was reached.
var ErrFlowLimit = errors.New("flow limit reached")

// Validate checks resource controls before startup creates network resources.
func (c Config) Validate() error {
	for _, setting := range []struct {
		name  string
		value int
		unit  time.Duration
	}{
		{"TCPAckDelayMs", c.TCPAckDelayMs, time.Millisecond},
		{"TCPFlowLifetimeSec", c.TCPFlowLifetimeSec, time.Second},
		{"UDPFlowLifetimeSec", c.UDPFlowLifetimeSec, time.Second},
		{"TCPReassemblyCapBytes", c.TCPReassemblyCapBytes, 1},
		{"MaxTCPFlows", c.MaxTCPFlows, 1},
		{"MaxUDPFlows", c.MaxUDPFlows, 1},
		{"MaxPendingTCPDials", c.MaxPendingTCPDials, 1},
		{"SocketBufferCapBytes", c.SocketBufferCapBytes, 1},
		{"TCPPendingCapBytes", c.TCPPendingCapBytes, 1},
		{"TCPRetransmitCapBytes", c.TCPRetransmitCapBytes, 1},
		{"IPv4FragmentBufferCapBytes", c.IPv4FragmentBufferCapBytes, 1},
	} {
		if setting.value < 0 || uint64(setting.value) > uint64(math.MaxInt64/int64(setting.unit)) {
			return fmt.Errorf("%s must be nonnegative and fit its runtime representation", setting.name)
		}
	}
	if c.IPv4Reassembly && budgetDefault(c.IPv4FragmentBufferCapBytes, DefaultIPv4FragmentBufferCap) < ipv4FragmentCharge {
		return fmt.Errorf("IPv4FragmentBufferCapBytes must admit at least one bounded datagram (%d bytes)", ipv4FragmentCharge)
	}
	return c.transportConfig().Validate()
}

// Config contains configuration for the socket interface
type Config struct {
	// Transport is optional for source compatibility; nil uses transport defaults.
	// NewSocketInterface copies the pointed-to value.
	Transport *TransportConfig

	// IP address for the socket interface
	IPAddress string

	// MTU for the socket interface
	MTU int

	// Enable debug logging
	Debug bool

	// Protocol to use for the socket interface (ip4:icmp, ip4:tcp, ip4:udp)
	// Default is ip4:icmp
	Protocol string

	// TCPAckDelayMs controls delayed ACK scheduling (milliseconds); 0 is immediate.
	TCPAckDelayMs int

	// TCPFlowLifetimeSec controls idle TCP flow timeout (seconds).
	TCPFlowLifetimeSec int

	// UDPFlowLifetimeSec controls idle UDP flow timeout (seconds).
	UDPFlowLifetimeSec int

	// TCPReassemblyCapBytes caps buffered out-of-order bytes per TCP flow.
	TCPReassemblyCapBytes int

	// MaxTCPFlows limits active TCP flows (0 = unlimited).
	MaxTCPFlows int

	// MaxUDPFlows limits active UDP flows (0 = unlimited).
	MaxUDPFlows int

	// New safety budgets use finite defaults when zero (never unlimited).
	MaxPendingTCPDials    int
	SocketBufferCapBytes  int
	TCPPendingCapBytes    int
	TCPRetransmitCapBytes int

	// IPv4Reassembly is opt-in during feature acceptance. Zero storage cap uses
	// a finite default, shared with SocketBufferCapBytes rather than added to it.
	IPv4Reassembly             bool
	IPv4FragmentBufferCapBytes int
}

// Effective returns a detached configuration with documented zero-as-default
// values resolved. Explicit unlimited flow caps and immediate ACKs stay zero.
// Invalid negative values are preserved so Validate still rejects them.
func (c Config) Effective() Config {
	defaults := DefaultConfig()
	transport := c.transportConfig()
	c.Transport = &transport
	for _, setting := range []struct {
		value    *int
		fallback int
	}{
		{&c.TCPFlowLifetimeSec, defaults.TCPFlowLifetimeSec},
		{&c.UDPFlowLifetimeSec, defaults.UDPFlowLifetimeSec},
		{&c.TCPReassemblyCapBytes, defaults.TCPReassemblyCapBytes},
		{&c.MaxPendingTCPDials, defaults.MaxPendingTCPDials},
		{&c.SocketBufferCapBytes, defaults.SocketBufferCapBytes},
		{&c.TCPPendingCapBytes, defaults.TCPPendingCapBytes},
		{&c.TCPRetransmitCapBytes, defaults.TCPRetransmitCapBytes},
		{&c.IPv4FragmentBufferCapBytes, defaults.IPv4FragmentBufferCapBytes},
	} {
		if *setting.value == 0 {
			*setting.value = setting.fallback
		}
	}
	return c
}

// DefaultConfig returns the default configuration for the socket interface
func DefaultConfig() Config {
	transport := DefaultTransportConfig()
	return Config{
		Transport:                  &transport,
		IPAddress:                  "0.0.0.0",
		MTU:                        1500,
		Debug:                      false,
		Protocol:                   "ip4:icmp",
		TCPAckDelayMs:              10,
		TCPFlowLifetimeSec:         120,
		UDPFlowLifetimeSec:         60,
		TCPReassemblyCapBytes:      128 * 1024,
		MaxTCPFlows:                DefaultMaxTCPFlows,
		MaxUDPFlows:                DefaultMaxUDPFlows,
		MaxPendingTCPDials:         DefaultPendingTCPDials,
		SocketBufferCapBytes:       DefaultSocketBufferCap,
		TCPPendingCapBytes:         DefaultTCPPendingCap,
		TCPRetransmitCapBytes:      DefaultTCPRetransmitCap,
		IPv4FragmentBufferCapBytes: DefaultIPv4FragmentBufferCap,
	}
}
