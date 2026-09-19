// Package packetwire encodes wire bytes into caller-owned storage. It owns no
// buffers, pools, budgets, IDs, sockets or protocol state. Inputs must not overlap
// output storage. Encoders reject invalid sizes without modifying output.
package packetwire

import "encoding/binary"

func sum(data []byte, initial uint32) uint32 {
	for len(data) >= 2 {
		initial += uint32(binary.BigEndian.Uint16(data))
		data = data[2:]
	}
	if len(data) != 0 {
		initial += uint32(data[0]) << 8
	}
	return initial
}

func finish(value uint32) uint16 {
	for value>>16 != 0 {
		value = (value & 0xffff) + (value >> 16)
	}
	return ^uint16(value)
}

// Checksum returns the Internet checksum for an IPv4-sized byte slice (at most
// 65535 bytes), including an odd trailing byte.
func Checksum(data []byte) uint16 { return finish(sum(data, 0)) }

// TransportChecksum includes the IPv4 pseudoheader. Callers validate transport
// lengths before use; verification returns zero for a valid checksummed segment.
func TransportChecksum(data []byte, src, dst [4]byte, protocol byte) uint16 {
	value := sum(src[:], 0) + sum(dst[:], 0) + uint32(protocol) + uint32(uint16(len(data)))
	return finish(sum(data, value))
}

// IPv4Header writes a fixed 20-byte header and its checksum. Packet length is
// taken from out; bytes after the header are untouched. ID and fragment flags/
// offset belong to the caller (fragment offsets are already in eight-byte units).
func IPv4Header(out []byte, src, dst [4]byte, protocol, tos, ttl byte, id, fragment uint16) bool {
	if len(out) < 20 || len(out) > 65535 {
		return false
	}
	clear(out[:20])
	out[0], out[1], out[8], out[9] = 0x45, tos, ttl, protocol
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	binary.BigEndian.PutUint16(out[4:6], id)
	binary.BigEndian.PutUint16(out[6:8], fragment)
	copy(out[12:16], src[:])
	copy(out[16:20], dst[:])
	binary.BigEndian.PutUint16(out[10:12], Checksum(out[:20]))
	return true
}

// UDP writes a complete IPv4 UDP datagram (without the IP header). A computed
// zero checksum is encoded as 0xffff: zero on the wire means checksum omitted.
func UDP(out []byte, src, dst [4]byte, sport, dport uint16, payload []byte) bool {
	if len(payload) > 65507 || len(out) != 8+len(payload) {
		return false
	}
	clear(out[:8])
	binary.BigEndian.PutUint16(out[0:2], sport)
	binary.BigEndian.PutUint16(out[2:4], dport)
	binary.BigEndian.PutUint16(out[4:6], uint16(len(out)))
	copy(out[8:], payload)
	checksum := TransportChecksum(out, src, dst, 17)
	if checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(out[6:8], checksum)
	return true
}

// TCP writes a complete IPv4 TCP segment, padding options with zero bytes.
// The caller supplies flags, sequence numbers and window; protocol policy stays
// outside this package. Checksums, reserved bits and urgent pointer are reset.
func TCP(out []byte, src, dst [4]byte, sport, dport uint16, seq, ack uint32, flags byte, window uint16, payload, options []byte) bool {
	if len(options) > 40 {
		return false
	}
	header := 20 + ((len(options) + 3) &^ 3)
	if len(payload) > 65515-header || len(out) != header+len(payload) {
		return false
	}
	clear(out[:header])
	binary.BigEndian.PutUint16(out[0:2], sport)
	binary.BigEndian.PutUint16(out[2:4], dport)
	binary.BigEndian.PutUint32(out[4:8], seq)
	binary.BigEndian.PutUint32(out[8:12], ack)
	out[12], out[13] = byte(header/4)<<4, flags
	binary.BigEndian.PutUint16(out[14:16], window)
	copy(out[20:header], options)
	copy(out[header:], payload)
	binary.BigEndian.PutUint16(out[16:18], TransportChecksum(out, src, dst, 6))
	return true
}
