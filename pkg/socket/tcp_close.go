package socket

import (
	"fmt"
	"github.com/irctrakz/wgslirp/pkg/logging"
	"sync/atomic"
	"time"
)

// Close recovery expires after two minutes without new data/ACK progress.
// Duplicate control traffic cannot keep a stalled flow or TIME-WAIT alive forever.
// The TIME-WAIT interval uses 2 * the RFC 9293 two-minute MSL. Both intervals
// remain subject to explicit reset/shutdown; normal idle expiry cannot cut them short.
const tcpCloseTimeout = 2 * time.Minute
const tcpTimeWaitDuration = 4 * time.Minute

// TCP sequence comparisons are modulo 2^32, for distances below 2^31.
func seqBefore(a, b uint32) bool { return int32(a-b) < 0 }
func seqAfter(a, b uint32) bool  { return seqBefore(b, a) }

func (b *tcpBridge) sendCloseACKLocked(f *tcpFlow) {
	var options [36]byte
	_ = b.sendToGuest(f, b.buildIPv4TCPOpts(f.dstIP, f.srcIP, f.dstPort, f.srcPort, f.serverNxt, f.clientNxt, 0x10, nil, f.receiveSACKLocked(&options)))
}

func (b *tcpBridge) beginCloseLocked(f *tcpFlow, now time.Time) {
	f.closeDeadline = now.Add(tcpCloseTimeout)
}

// startFINLocked is called only after the host reader has forwarded every byte
// preceding EOF. The sequence number is reserved exactly once, even on refusal.
func (b *tcpBridge) startFINLocked(f *tcpFlow, now time.Time) {
	if f.closed || f.finSent {
		return
	}
	b.beginCloseLocked(f, now)
	f.finSent = true
	f.finSeq = f.serverNxt
	f.serverNxt++
	f.finRTO = f.rto
	if f.finRTO < 200*time.Millisecond {
		f.finRTO = 200 * time.Millisecond
	}
	if f.finRTO > 2*time.Second {
		f.finRTO = 2 * time.Second
	}
	if f.finReceived {
		f.state = tcpLastAck
	} else {
		f.state = tcpFinWait1
	}
	b.emitFINLocked(f, now)
}

func (b *tcpBridge) emitFINLocked(f *tcpFlow, now time.Time) bool {
	f.finSentAt = now
	packet := b.buildIPv4TCP(f.dstIP, f.srcIP, f.dstPort, f.srcPort, f.finSeq, f.clientNxt, 0x11, nil)
	if packet == nil {
		return false
	}
	_ = b.sendToGuest(f, packet)
	return true
}

func (b *tcpBridge) closeHostWriteLocked(f *tcpFlow) error {
	if f.conn == nil || f.hostWriteClosed {
		return nil
	}
	if err := f.conn.CloseWrite(); err != nil {
		b.abortBufferedFlowLocked(f)
		return fmt.Errorf("tcp: close host write: %w", err)
	}
	f.hostWriteClosed = true
	return nil
}

// receiveFINLocked runs only after all preceding guest bytes were accepted.
// Pending bytes are flushed before CloseWrite if the dial is still in progress.
func (b *tcpBridge) receiveFINLocked(f *tcpFlow, now time.Time) error {
	if f.finReceived {
		b.sendCloseACKLocked(f)
		return nil
	}
	b.beginCloseLocked(f, now)
	f.finReceived = true
	f.clientNxt++
	// No guest bytes beyond FIN belong to this stream.
	b.buffers.release(f.futureBytes + len(f.ooo)*bufferEntryAllowance)
	f.futureBytes = 0
	f.ooo = nil
	if err := b.closeHostWriteLocked(f); err != nil {
		return err
	}
	switch f.state {
	case tcpEstablished:
		f.state = tcpCloseWait
	case tcpFinWait1:
		f.state = tcpClosing
	case tcpFinWait2:
		b.enterTimeWaitLocked(f, now)
	}
	b.sendCloseACKLocked(f)
	return nil
}

func (b *tcpBridge) ackFINLocked(f *tcpFlow, ack uint32, now time.Time) {
	if !f.finSent || ack != f.finSeq+1 {
		return
	}
	switch f.state {
	case tcpFinWait1:
		f.state = tcpFinWait2
	case tcpClosing:
		b.enterTimeWaitLocked(f, now)
	case tcpLastAck:
		b.removeFlowLocked(f)
	}
}

func (b *tcpBridge) enterTimeWaitLocked(f *tcpFlow, now time.Time) {
	f.state = tcpTimeWait
	f.timeWaitUntil = now.Add(tcpTimeWaitDuration)
	// A duplicate FIN refreshes TIME-WAIT, but cannot pin a slot indefinitely.
	cap := f.closeDeadline.Add(tcpTimeWaitDuration)
	if f.timeWaitUntil.After(cap) {
		f.timeWaitUntil = cap
	}
	if f.conn != nil {
		_ = f.conn.Close()
	}
}

// closeTickLocked shares the existing retransmission worker. Tests supply time
// explicitly, avoiding multi-minute sleeps or per-flow unowned timer goroutines.
func (b *tcpBridge) closeTickLocked(f *tcpFlow, now time.Time) bool {
	if f.closed || f.closeDeadline.IsZero() {
		return false
	}
	if f.state == tcpTimeWait {
		if !now.Before(f.timeWaitUntil) {
			b.removeFlowLocked(f)
		}
		return false
	}
	if !now.Before(f.closeDeadline) {
		// Expiration aborts rather than pretending unacknowledged bytes were delivered.
		atomic.AddUint64(&b.parent.metrics.Errors, 1)
		atomic.AddUint64(&b.metrics.Errors, 1)
		if b.failureLog.Allow(now) {
			logging.Warnf("TCP close timed out: flow=%s state=%d unacknowledged=%d", f.key, f.state, f.serverNxt-f.sndUna)
		}
		_ = b.sendToGuest(f, b.buildIPv4TCP(f.dstIP, f.srcIP, f.dstPort, f.srcPort, f.serverNxt, f.clientNxt, 0x14, nil))
		b.removeFlowLocked(f)
		return false
	}
	if f.finSent && f.sndUna != f.serverNxt && now.Sub(f.finSentAt) >= f.finRTO {
		sent := b.emitFINLocked(f, now)
		f.finRTO = minDur(2*f.finRTO, 2*time.Second)
		if sent {
			atomic.AddUint64(&b.rtoCount, 1)
		}
		return sent
	}
	return false
}
