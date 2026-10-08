package socket

import (
	"encoding/binary"
	"fmt"
	"sync/atomic"
	"time"
)

// handleTCPFlow takes stateMu after observing registry membership. It also
// handles the winner of a concurrent SYN insertion; caller owns work admission.
func (b *tcpBridge) handleTCPFlow(flow *tcpFlow, segment tcpSegment) error {
	pkt := segment.pkt
	tcpOff := segment.tcpOff
	srcIP := segment.srcIP
	dstIP := segment.dstIP
	srcPort := segment.srcPort
	dstPort := segment.dstPort
	seq := segment.seq
	ack := segment.ack
	flags := segment.flags
	payload := segment.payload

	if flow == nil {
		// No flow: send RST per RFC depending on ACK flag
		const fACK = 0x10
		const fRST = 0x04
		if (flags & fACK) != 0 {
			// RST with seq = ack
			rst := b.buildIPv4TCP(dstIP, srcIP, dstPort, srcPort, ack, 0, fRST, nil)
			if rst != nil {
				_ = b.sendToGuest(flow, rst)
			}
		} else {
			// RST|ACK with ack = seq + len
			segLen := uint32(len(payload))
			// SYN/FIN consume 1 sequence number
			if (flags & 0x02) != 0 { // SYN
				segLen++
			}
			if (flags & 0x01) != 0 { // FIN
				segLen++
			}
			rst := b.buildIPv4TCP(dstIP, srcIP, dstPort, srcPort, 0, seq+segLen, fRST|fACK, nil)
			if rst != nil {
				_ = b.sendToGuest(flow, rst)
			}
		}
		return nil
	}

	flow.stateMu.Lock()
	defer flow.stateMu.Unlock()
	if flow.closed {
		return fmt.Errorf("TCP flow closed")
	}
	flow.touch()

	switch flow.state {
	case tcpSynRcvd:
		if (flags&fACK) != 0 && ack == flow.serverISN+1 {
			flow.state = tcpEstablished
			// Seed advertised window from this ACK
			wnd := uint32(binary.BigEndian.Uint16(pkt[tcpOff+14 : tcpOff+16]))
			if flow.wsIn > 0 {
				wnd = wnd << flow.wsIn
			}
			flow.advWnd = wnd
			select {
			case flow.ackCh <- struct{}{}:
			default:
			}
		} else {
			return nil
		}
		// The handshake ACK may also carry data and/or FIN.
		fallthrough
	case tcpEstablished, tcpFinWait1, tcpFinWait2, tcpCloseWait, tcpClosing, tcpLastAck, tcpTimeWait:
		if flow.state == tcpTimeWait {
			if flags&fFIN != 0 && seq+uint32(len(payload))+1 == flow.clientNxt {
				b.enterTimeWaitLocked(flow, time.Now())
				b.sendCloseACKLocked(flow)
			}
			return nil
		}
		if flags&fACK != 0 && seqAfter(ack, flow.serverNxt) {
			b.sendCloseACKLocked(flow)
			return nil
		}
		if flags&fACK != 0 {
			b.processTCPACKLocked(flow, segment)
			if flow.closed {
				return nil
			}
		}

		return b.receiveTCPDataLocked(flow, segment)
	default:
		return nil
	}
}

// receiveTCPDataLocked requires flow.stateMu. It trims duplicate prefixes,
// reserves future/pending payload before retaining it, and consumes FIN only
// after all preceding bytes are accepted. Borrowed segment slices never escape.
func (b *tcpBridge) receiveTCPDataLocked(flow *tcpFlow, segment tcpSegment) error {
	seq, flags, payload := segment.seq, segment.flags, segment.payload
	// A consumed FIN closes only the guest->host direction. Continue
	// processing ACKs/windows above for the host's response and FIN.
	if flow.finReceived {
		if len(payload) > 0 || flags&fFIN != 0 {
			b.sendCloseACKLocked(flow)
		}
		return nil
	}
	finSeq := seq + uint32(len(payload))
	if seqBefore(seq, flow.clientNxt) {
		skip := uint32(flow.clientNxt - seq)
		if skip > uint32(len(payload)) {
			b.sendCloseACKLocked(flow)
			return nil
		}
		// Keep a new suffix/FIN when only its prefix was retransmitted.
		payload = payload[skip:]
		seq = flow.clientNxt
	}
	if seqAfter(seq, flow.clientNxt) {
		// Retain admitted data, but do not consume an out-of-order FIN.
		// The cumulative ACK asks the peer to retransmit the missing range.
		b.queueFuture(flow, seq, payload)
		b.sendCloseACKLocked(flow)
		return nil
	}
	if len(payload) > 0 {
		if flow.conn == nil {
			if !b.reservePending(flow, len(payload)) {
				atomic.AddUint64(&b.pendDrop, 1)
				b.bufferDrops.Add(1)
				b.sendCloseACKLocked(flow)
				return nil
			}
			pending := make([]byte, len(payload))
			copy(pending, payload)
			flow.pending = append(flow.pending, pending)
			flow.pendingBytes += len(payload)
			atomic.AddUint64(&b.pendEnq, 1)
		} else {
			n, err := writeTCP(flow.conn, payload)
			if err != nil {
				b.abortBufferedFlowLocked(flow)
				return fmt.Errorf("tcp: write: %w", err)
			}
			atomic.AddUint64(&b.metrics.BytesSent, uint64(n))
			atomic.AddUint64(&b.metrics.PacketsSent, 1)
		}
		flow.clientNxt += uint32(len(payload))
		if !flow.closeDeadline.IsZero() {
			b.beginCloseLocked(flow, time.Now())
		}
		// Data buffered beyond an in-order FIN is outside the stream.
		if flags&fFIN == 0 {
			if err := b.flushReassembly(flow); err != nil {
				b.abortBufferedFlowLocked(flow)
				return fmt.Errorf("tcp: write (reassembly): %w", err)
			}
		}
		b.scheduleAck(flow)
	}
	if flags&fFIN != 0 && finSeq == flow.clientNxt {
		return b.receiveFINLocked(flow, time.Now())
	}
	return nil
}
