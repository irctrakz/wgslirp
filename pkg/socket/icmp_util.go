package socket

import "github.com/irctrakz/wgslirp/internal/packetwire"

// buildICMPUnreachable builds an IPv4 ICMP Destination Unreachable packet
// with the given code (e.g., 1=host unreachable, 3=port unreachable).
// It includes the original IP header and first 8 bytes of the payload per RFC.
func buildICMPUnreachable(srcIP, dstIP [4]byte, code byte, original []byte) []byte {
	// Prepare ICMP payload: original IP header + first 8 bytes of original payload
	if len(original) < 20 {
		return nil
	}
	ihl := int(original[0]&0x0f) * 4
	if ihl < 20 || len(original) < ihl {
		return nil
	}
	copyLen := ihl + 8
	if copyLen > len(original) {
		copyLen = len(original)
	}
	pkt := bufMaybePool(28 + copyLen)
	icmpBody := pkt[20:] // 8 byte ICMP header + original
	// ICMP header
	icmpBody[0] = 3    // Type: Destination Unreachable
	icmpBody[1] = code // Code
	// bytes 2-3: checksum (later)
	// bytes 4-7: unused
	copy(icmpBody[8:], original[:copyLen])
	// Checksum over entire ICMP message
	cs := calculateChecksum(icmpBody)
	icmpBody[2] = byte(cs >> 8)
	icmpBody[3] = byte(cs & 0xff)

	packetwire.IPv4Header(pkt, srcIP, dstIP, 1, 0, 64, 0, 0)

	return pkt
}
