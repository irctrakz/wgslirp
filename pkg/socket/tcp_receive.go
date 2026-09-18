package socket

import (
	"encoding/binary"
	"fmt"
	"github.com/irctrakz/wgslirp/pkg/logging"
	"sync/atomic"
	"time"
)

// handleTCPFlow takes stateMu after observing registry membership. It also
// handles the winner of a concurrent SYN insertion; caller owns work admission.
func (b *tcpBridge) handleTCPFlow(flow *tcpFlow, segment tcpSegment) error {
	pkt := segment.pkt
	tcpOff := segment.tcpOff
	dataOff := segment.dataOff
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
		// Handle ACK updates and possible FIN teardown
		if (flags & fACK) != 0 {
			// dupACK detection
			if ack == flow.sndUna && len(payload) == 0 {
				flow.dupAckCnt++
				atomic.AddUint64(&b.ackDup, 1)
			} else {
				flow.dupAckCnt = 0
			}
			if !seqAfter(ack, flow.serverNxt) && seqAfter(ack, flow.sndUna) {
				prevUna := flow.sndUna
				flow.sndUna = ack
				flow.lastAckTime = time.Now()
				if !flow.closeDeadline.IsZero() {
					b.beginCloseLocked(flow, flow.lastAckTime)
				}
				atomic.AddUint64(&b.ackAdv, 1)
				// drop acknowledged segments from txQueue and update RTT/RTO
				now := time.Now()
				flow.txMu.Lock()
				for len(flow.txQueue) > 0 {
					head := flow.txQueue[0]
					if !seqAfter(head.seq+uint32(len(head.data)), ack) {
						// RTT sample (Karn's algorithm: only if not retransmitted)
						if head.retries == 0 && !head.sentAt.IsZero() {
							sample := now.Sub(head.sentAt)
							if sample > 0 {
								if flow.srtt == 0 {
									// RFC 6298 init
									flow.srtt = sample
									flow.rttvar = sample / 2
								} else {
									// RFC 6298 update
									err := flow.srtt - sample
									if err < 0 {
										err = -err
									}
									flow.rttvar = (3*flow.rttvar + err) / 4
									flow.srtt = (7*flow.srtt + sample) / 8
								}
								// RTO = SRTT + 4*RTTVAR, with bounds
								rto := flow.srtt + 4*flow.rttvar
								if rto < 200*time.Millisecond {
									rto = 200 * time.Millisecond
								}
								if rto > 60*time.Second {
									rto = 60 * time.Second
								}
								flow.rto = rto
							}
						}
						flow.txQueue[0].data = nil
						flow.txQueue = flow.txQueue[1:]
						flow.txBytes -= len(head.data)
						b.buffers.release(bufferCharge(len(head.data)))
					} else {
						break
					}
				}
				flow.txMu.Unlock()
				// Notify CC of ACKed bytes
				if flow.ccEnabled && flow.cc != nil {
					diff := int(ack - prevUna)
					if diff > 0 {
						flow.cc.OnAck(diff)
					}
				}
				// trimmed: per-flow verbose ack debug removed
				// Notify sender waiters
				select {
				case flow.ackCh <- struct{}{}:
				default:
				}
			}
			// Track previous window to detect pure window updates that should wake senders.
			prevWnd := flow.advWnd
			wnd := uint32(binary.BigEndian.Uint16(pkt[tcpOff+14 : tcpOff+16]))
			if flow.wsIn > 0 {
				wnd = wnd << flow.wsIn
			}
			flow.advWnd = wnd
			// If the peer opened its window without advancing ACK, wake senders.
			if wnd > prevWnd {
				// Treat as progress for idle tracking to avoid false ACK-idle.
				flow.lastAckTime = time.Now()
				// Count as window-only update if ACK did not advance
				if ack <= flow.sndUna {
					atomic.AddUint64(&b.ackWndOnly, 1)
				}
				select {
				case flow.ackCh <- struct{}{}:
				default:
				}
			}
			if b.ackTrace {
				class := "adv"
				if ack == flow.sndUna && len(payload) == 0 {
					class = "dup"
				} else if ack <= flow.sndUna && wnd > prevWnd {
					class = "wnd"
				}
				logging.Infof("TCP ACK trace: flow=%s class=%s ack=%d sndUna=%d nxt=%d wnd=%d ws=%d txq=%d",
					flow.key, class, ack, flow.sndUna, flow.serverNxt, flow.advWnd, flow.wsIn, len(flow.txQueue))
			}
			// Parse SACK blocks if any and SACK permitted
			if flow.sackPermitted || b.tuning.EnableSACK {
				// Also prune acknowledged blocks on ACKs without options.
				parseSACKBlocks(flow, pkt[tcpOff+20:tcpOff+dataOff])
			}
			b.ackFINLocked(flow, ack, time.Now())
			if flow.closed {
				return nil
			}
			// Fast retransmit on 3 dupACKs
			if flow.dupAckCnt >= 3 {
				flow.dupAckCnt = 0
				// Enter SACK recovery and retransmit a hole if available
				flow.sackRecovery = true
				// Exclusive end of data outstanding when recovery begins.
				flow.recover = flow.serverNxt
			}
			// Partial ACK handling: in recovery, keep sending next hole
			if flow.sackRecovery {
				if !seqBefore(ack, flow.recover) {
					flow.sackRecovery = false
				} else {
					b.retransmitNextHole(flow)
				}
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
