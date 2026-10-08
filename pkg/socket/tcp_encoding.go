package socket

import "github.com/irctrakz/wgslirp/internal/packetwire"

// buildIPv4TCP builds an IPv4+TCP packet with given sequence/ack and flags.
func buildIPv4TCP(srcIP, dstIP [4]byte, srcPort, dstPort uint16, seq, ack uint32, flags byte, payload []byte) []byte {
	return buildIPv4TCPOptsWith(srcIP, dstIP, srcPort, dstPort, seq, ack, flags, payload, nil, 0x00, 64)
}

// buildIPv4TCPOpts allows specifying TCP options (zero-padded to a 4-byte multiple).
func buildIPv4TCPOpts(srcIP, dstIP [4]byte, srcPort, dstPort uint16, seq, ack uint32, flags byte, payload []byte, options []byte) []byte {
	return buildIPv4TCPOptsWith(srcIP, dstIP, srcPort, dstPort, seq, ack, flags, payload, options, 0x00, 64)
}

// buildIPv4TCPWithIP allows specifying IP TOS/TTL without options.
func buildIPv4TCPWithIP(srcIP, dstIP [4]byte, srcPort, dstPort uint16, seq, ack uint32, flags byte, payload []byte, tos byte, ttl byte) []byte {
	return buildIPv4TCPOptsWith(srcIP, dstIP, srcPort, dstPort, seq, ack, flags, payload, nil, tos, ttl)
}

// buildIPv4TCPOptsWith allows specifying both options and IP TOS/TTL.
func buildIPv4TCPOptsWith(srcIP, dstIP [4]byte, srcPort, dstPort uint16, seq, ack uint32, flags byte, payload, options []byte, tos, ttl byte) []byte {
	if len(options) > 40 || len(payload) > 65535-40-((len(options)+3)&^3) {
		return nil
	}
	pkt := bufMaybePool(40 + ((len(options) + 3) &^ 3) + len(payload))
	packetwire.IPv4Header(pkt, srcIP, dstIP, 6, tos, ttl, nextIPID(), 0)
	packetwire.TCP(pkt[20:], srcIP, dstIP, srcPort, dstPort, seq, ack, flags, 0xffff, payload, options)
	return pkt
}

func tcpChecksum(tcp []byte, srcIP, dstIP [4]byte) uint16 {
	return packetwire.TransportChecksum(tcp, srcIP, dstIP, 6)
}
