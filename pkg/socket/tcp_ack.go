package socket

import (
	"encoding/binary"
	"github.com/irctrakz/wgslirp/pkg/logging"
	"sync/atomic"
	"time"
)

// processTCPACKLocked requires flow.stateMu. The caller rejects future ACKs
// before entry and checks closed on return: ACKing LAST-ACK can remove the flow.
// Keep queue release, RTT/CC updates, waiter notification, SACK and FIN handling
// in their original order before processing any payload on the same segment.
func (b *tcpBridge) processTCPACKLocked(flow *tcpFlow, segment tcpSegment) {
	pkt, tcpOff, dataOff := segment.pkt, segment.tcpOff, segment.dataOff
	ack, payload := segment.ack, segment.payload
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
		return
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

// scheduleAck schedules a delayed ACK for the given flow if one isn't already scheduled.
// Caller holds stateMu. All timer work is owned by the bridge.
func (b *tcpBridge) scheduleAck(f *tcpFlow) {
	if f.ackScheduled || f.closed {
		return
	}
	f.ackScheduled = true
	if !b.launch(func() {
		timer := time.NewTimer(b.ackDelay)
		defer timer.Stop()
		select {
		case <-f.rtoStop:
			return
		case <-b.stopCh:
			return
		case <-timer.C:
		}
		f.stateMu.Lock()
		defer f.stateMu.Unlock()
		f.ackScheduled = false
		if f.closed {
			return
		}
		ack := b.buildIPv4TCP(f.dstIP, f.srcIP, f.dstPort, f.srcPort, f.serverNxt, f.clientNxt, 0x10, nil)
		_ = b.sendToGuest(f, ack)
	}) {
		f.ackScheduled = false
	}
}
