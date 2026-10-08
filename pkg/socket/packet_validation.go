package socket

import (
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	ErrMalformedPacket     = errors.New("malformed packet")
	ErrUnsupportedFragment = errors.New("incoming IPv4 fragments are unsupported")
)

// parseIPv4 bounds all subsequent reads by the declared IP datagram length.
// Trailing link padding is ignored. Incoming fragments require reassembly,
// which these bridges do not implement; never treat them as whole datagrams.
func parseIPv4(packet []byte) (datagram []byte, headerLen int, err error) {
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
	if flags&0x3fff != 0 {
		return nil, 0, ErrUnsupportedFragment
	}
	return packet[:total], ihl, nil
}

func parseTransport(packet []byte, protocol byte) ([]byte, int, error) {
	datagram, ihl, err := parseIPv4(packet)
	if err != nil {
		return nil, 0, err
	}
	if datagram[9] != protocol {
		return nil, 0, fmt.Errorf("%w: expected protocol %d", ErrMalformedPacket, protocol)
	}
	payload := datagram[ihl:]
	switch protocol {
	case 6:
		if len(payload) < 20 {
			return nil, 0, fmt.Errorf("%w: TCP header", ErrMalformedPacket)
		}
		offset := int(payload[12]>>4) * 4
		if offset < 20 || offset > len(payload) {
			return nil, 0, fmt.Errorf("%w: TCP data offset", ErrMalformedPacket)
		}
	case 17:
		if len(payload) < 8 || int(binary.BigEndian.Uint16(payload[4:6])) != len(payload) {
			return nil, 0, fmt.Errorf("%w: UDP length", ErrMalformedPacket)
		}
	case 1:
		if len(payload) < 8 {
			return nil, 0, fmt.Errorf("%w: ICMP header", ErrMalformedPacket)
		}
	}
	return datagram, ihl, nil
}
