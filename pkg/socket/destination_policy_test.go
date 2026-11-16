package socket

import (
	"net/netip"
	"testing"
)

func TestDestinationPolicyValidation(t *testing.T) {
	guest := netip.MustParseAddrPort("10.77.0.1:8096")
	host := netip.MustParseAddrPort("127.0.0.1:9000")
	valid := TCPMapping{Guest: guest, Host: host}
	tooMany := make([]TCPMapping, 33)
	for i := range tooMany {
		tooMany[i] = TCPMapping{
			Guest: netip.AddrPortFrom(guest.Addr(), uint16(8096+i)),
			Host:  host,
		}
	}
	for _, tc := range []struct {
		name     string
		mappings []TCPMapping
	}{
		{"empty", nil},
		{"too many", tooMany},
		{"duplicate", []TCPMapping{valid, valid}},
		{"duplicate with different host", []TCPMapping{valid, {Guest: guest, Host: netip.MustParseAddrPort("127.0.0.1:9001")}}},
		{"guest loopback", []TCPMapping{{Guest: host, Host: host}}},
		{"guest IPv6", []TCPMapping{{Guest: netip.MustParseAddrPort("[::1]:8096"), Host: host}}},
		{"guest zero port", []TCPMapping{{Guest: netip.AddrPortFrom(guest.Addr(), 0), Host: host}}},
		{"host zero network", []TCPMapping{{Guest: guest, Host: netip.MustParseAddrPort("0.1.2.3:8096")}}},
		{"host multicast", []TCPMapping{{Guest: guest, Host: netip.MustParseAddrPort("224.0.0.1:8096")}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewDestinationPolicy(tc.mappings); err == nil {
				t.Fatal("accepted invalid mappings")
			}
		})
	}
	input := []TCPMapping{valid, {Guest: netip.AddrPortFrom(guest.Addr(), 8097), Host: host}}
	policy, err := NewDestinationPolicy(input)
	if err != nil {
		t.Fatal(err)
	}
	input[0].Host = guest
	if !policy.Reserves(guest.Addr()) || policy.Reserves(host.Addr()) || policy.tcp[guest] != host {
		t.Fatal("policy did not retain its guest reservation and original mapping")
	}
}
