package packetwire

import (
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	ErrMalformedPacket      = errors.New("malformed packet")
	ErrUnsupportedIPOptions = errors.New("incoming IPv4 options are unsupported")
	ErrInvalidChecksum      = fmt.Errorf("%w: invalid checksum", ErrMalformedPacket)
	ErrUnsupportedFragment  = errors.New("incoming IPv4 fragments are unsupported")
)

// ParseIPv4 bounds all subsequent reads by the declared IP datagram length.
// The result borrows input storage and parsing never mutates it.
// Trailing link padding is ignored. Incoming fragments require reassembly,
// so this strict parser never treats them as whole datagrams.
func ParseIPv4(packet []byte) (datagram []byte, headerLen int, err error) {
	return parseIPv4(packet, false)
}

// ParseIPv4Header validates lengths, checksum and supported header semantics
// without requiring a complete datagram. Its result borrows input storage;
// callers must reassemble fragments before invoking ParseTransport.
func ParseIPv4Header(packet []byte) ([]byte, int, error) {
	return parseIPv4(packet, true)
}

func parseIPv4(packet []byte, allowFragments bool) (datagram []byte, headerLen int, err error) {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return nil, 0, fmt.Errorf("%w: IPv4 header", ErrMalformedPacket)
	}
	ihl := int(packet[0]&15) * 4
	total := int(binary.BigEndian.Uint16(packet[2:4]))
	if ihl < 20 || total < ihl || total > len(packet) {
		return nil, 0, fmt.Errorf("%w: IPv4 lengths", ErrMalformedPacket)
	}
	flags := binary.BigEndian.Uint16(packet[6:8])
	if flags&0x8000 != 0 {
		return nil, 0, fmt.Errorf("%w: reserved IPv4 flag", ErrMalformedPacket)
	}
	if !allowFragments && flags&0x3fff != 0 {
		return nil, 0, ErrUnsupportedFragment
	}
	if Checksum(packet[:ihl]) != 0 {
		return nil, 0, fmt.Errorf("%w: IPv4", ErrInvalidChecksum)
	}
	// Supported consumers cannot preserve option semantics (including source routing).
	// Reject even padding-only options instead of silently stripping them.
	if ihl != 20 {
		return nil, 0, ErrUnsupportedIPOptions
	}
	return packet[:total], ihl, nil
}

// ParseTransport validates a complete TCP, UDP or ICMP datagram. Returned bytes
// borrow input storage; callers must not mutate or retain them beyond its lifetime.
// DNS matching, TCP option interpretation and other protocol state remain external.
func ParseTransport(packet []byte, protocol byte) ([]byte, int, error) {
	datagram, ihl, err := ParseIPv4(packet)
	if err != nil {
		return nil, 0, err
	}
	if datagram[9] != protocol {
		return nil, 0, fmt.Errorf("%w: expected protocol %d", ErrMalformedPacket, protocol)
	}
	payload := datagram[ihl:]
	var src, dst [4]byte
	copy(src[:], datagram[12:16])
	copy(dst[:], datagram[16:20])
	switch protocol {
	case 6:
		if len(payload) < 20 {
			return nil, 0, fmt.Errorf("%w: TCP header", ErrMalformedPacket)
		}
		offset := int(payload[12]>>4) * 4
		if offset < 20 || offset > len(payload) {
			return nil, 0, fmt.Errorf("%w: TCP data offset", ErrMalformedPacket)
		}
		if TransportChecksum(payload, src, dst, 6) != 0 {
			return nil, 0, fmt.Errorf("%w: TCP", ErrInvalidChecksum)
		}
	case 17:
		if len(payload) < 8 || int(binary.BigEndian.Uint16(payload[4:6])) != len(payload) {
			return nil, 0, fmt.Errorf("%w: UDP length", ErrMalformedPacket)
		}
		// IPv4 UDP explicitly permits an omitted (zero) checksum.
		if binary.BigEndian.Uint16(payload[6:8]) != 0 && TransportChecksum(payload, src, dst, 17) != 0 {
			return nil, 0, fmt.Errorf("%w: UDP", ErrInvalidChecksum)
		}
	case 1:
		if len(payload) < 8 {
			return nil, 0, fmt.Errorf("%w: ICMP header", ErrMalformedPacket)
		}
		if Checksum(payload) != 0 {
			return nil, 0, fmt.Errorf("%w: ICMP", ErrInvalidChecksum)
		}
	default:
		return nil, 0, fmt.Errorf("%w: unsupported transport %d", ErrMalformedPacket, protocol)
	}
	return datagram, ihl, nil
}
