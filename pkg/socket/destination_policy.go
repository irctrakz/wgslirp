package socket

import (
	"errors"
	"fmt"
	"net/netip"
)

// ErrDestinationDenied marks traffic outside the configured TCP allowlist.
var ErrDestinationDenied = errors.New("guest destination denied")

// TCPMapping maps a guest-visible TCP endpoint to a numeric host endpoint.
type TCPMapping struct {
	Guest netip.AddrPort
	Host  netip.AddrPort
}

// DestinationPolicy is an immutable TCP allowlist. A nil policy preserves
// unrestricted forwarding. A non-nil policy denies all unmapped destinations.
type DestinationPolicy struct {
	tcp map[netip.AddrPort]netip.AddrPort
}

func NewDestinationPolicy(mappings []TCPMapping) (*DestinationPolicy, error) {
	if len(mappings) == 0 || len(mappings) > 32 {
		return nil, fmt.Errorf("destination policy requires 1 to 32 mappings")
	}
	p := &DestinationPolicy{tcp: make(map[netip.AddrPort]netip.AddrPort, len(mappings))}
	for i, m := range mappings {
		if !validMappingEndpoint(m.Guest) || m.Guest.Addr().IsLoopback() || !validMappingEndpoint(m.Host) {
			return nil, fmt.Errorf("mapping %d requires valid IPv4 TCP endpoints with loopback only on the host", i)
		}
		if _, exists := p.tcp[m.Guest]; exists {
			return nil, fmt.Errorf("mapping %d duplicates a guest destination", i)
		}
		p.tcp[m.Guest] = m.Host
	}
	return p, nil
}

func validMappingEndpoint(endpoint netip.AddrPort) bool {
	if !endpoint.Addr().Is4() || endpoint.Port() == 0 {
		return false
	}
	first := endpoint.Addr().As4()[0]
	return first != 0 && first < 224
}

// Reserves reports whether the address belongs to a virtual service, across
// all of its ports. The application uses it when assigning WireGuard sources.
func (p *DestinationPolicy) Reserves(address netip.Addr) bool {
	for guest := range p.tcp {
		if guest.Addr() == address {
			return true
		}
	}
	return false
}
