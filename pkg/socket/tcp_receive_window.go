package socket

import "github.com/irctrakz/wgslirp/pkg/core"

// receiveWindowBytes is a fixed span ahead of clientNxt, bounded by out-of-order
// storage and the negotiated wire representation. Retained future bytes occupy
// this span: subtracting them would retract its right edge and impede recovery.
func (b *tcpBridge) receiveWindowBytes(f *tcpFlow) int {
	return min(b.reasmCap>>f.wsOut, 65535) << f.wsOut
}

// buildTCPFlowLocked requires stateMu. All established-flow packet paths use
// this window, including data, retransmission and FIN; SYN windows are unscaled.
// Reserve before synthesis and compute checksums once with the final window.
func (b *tcpBridge) buildTCPFlowLocked(f *tcpFlow, seq uint32, flags byte, payload, options []byte, tos, ttl byte) core.Packet {
	if len(options) > 40 || len(payload) > 65535-40-((len(options)+3)&^3) {
		return nil
	}
	window := b.receiveWindowBytes(f)
	if flags&fSYN != 0 {
		window = min(window, 65535)
	} else {
		window >>= f.wsOut
	}
	size := 40 + ((len(options) + 3) &^ 3) + len(payload)
	return b.buffers.buildPacket(size, true, func() []byte {
		return buildIPv4TCPWindow(f.dstIP, f.srcIP, f.dstPort, f.srcPort, seq, f.clientNxt, flags, payload, options, tos, ttl, uint16(window))
	})
}
