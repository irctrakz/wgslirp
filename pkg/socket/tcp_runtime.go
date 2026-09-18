package socket

import (
	"errors"
	"github.com/irctrakz/wgslirp/pkg/core"
	"io"
	"net"
	"sync/atomic"
	"time"
)

// Host writes have a deadline because the packet handler holds flow state.
// This bounds shutdown even when the remote host stops reading.
func writeTCP(conn *net.TCPConn, data []byte) (int, error) {
	if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return 0, err
	}
	n, err := conn.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	return n, err
}

func (b *tcpBridge) waitForACK(f *tcpFlow, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-b.stopCh:
		return false
	case <-f.rtoStop:
		return false
	case <-f.ackCh:
		return true
	case <-timer.C:
		return true
	}
}

// sendAllowanceLocked requires stateMu. Peer windows of zero remain closed.
func (b *tcpBridge) sendAllowanceLocked(f *tcpFlow) int {
	if f.state == tcpSynRcvd || f.closed {
		return 0
	}
	blocked := f.txBytes >= b.retransmitCap
	if blocked && !f.retransmitBlocked {
		b.parent.admission.retransmitWaits.Add(1)
	}
	f.retransmitBlocked = blocked
	inFlight := int(f.serverNxt - f.sndUna)
	allowed := int(f.advWnd) - inFlight
	allowed = minInt(allowed, b.retransmitCap-f.txBytes)
	if f.ccEnabled && f.cc != nil {
		allowed = minInt(allowed, f.cc.Cwnd()-inFlight)
	}
	minInflight := b.ackIdleMinInflight
	if minInflight <= 0 {
		minInflight = f.mss
	}
	if b.ackIdleGate > 0 && inFlight >= minInflight && time.Since(f.lastAckTime) >= b.ackIdleGate {
		if b.ackIdleFail > 0 && time.Since(f.lastAckTime) >= b.ackIdleFail {
			if b.errorSignal != "none" {
				_ = b.sendToGuest(f, b.buildIPv4TCP(f.dstIP, f.srcIP, f.dstPort, f.srcPort, f.serverNxt, f.clientNxt, 0x14, nil))
			}
			b.removeFlowLocked(f)
		}
		return 0
	}
	return allowed
}

func (b *tcpBridge) reader(f *tcpFlow) {
	f.stateMu.Lock()
	conn := f.conn
	closed := f.closed
	f.stateMu.Unlock()
	if conn == nil || closed {
		return
	}
	b.launch(func() { b.retransmitLoop(f) })
	for {
		f.stateMu.Lock()
		allowed := b.sendAllowanceLocked(f)
		closed = f.closed
		f.stateMu.Unlock()
		if closed {
			return
		}
		if allowed <= 0 {
			if !b.waitForACK(f, 10*time.Millisecond) {
				return
			}
			continue
		}
		readSize := minInt(32*1024, allowed)
		readSize = minInt(readSize, maxInt(1, b.buffers.limit/2-bufferEntryAllowance))
		if !b.buffers.acquire(readSize) {
			if !b.waitForACK(f, 10*time.Millisecond) {
				return
			}
			continue
		}
		buf := make([]byte, readSize)
		_ = conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		n, err := conn.Read(buf)
		if n > 0 {
			f.touch()
			if !b.sendPayload(f, buf[:n]) {
				b.buffers.release(readSize)
				return
			}
		}
		b.buffers.release(readSize)
		if err == nil {
			continue
		}
		if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			continue
		}
		f.stateMu.Lock()
		if f.closed {
			f.stateMu.Unlock()
			return
		}
		if errors.Is(err, io.EOF) {
			b.startFINLocked(f, time.Now())
		} else {
			atomic.AddUint64(&b.parent.metrics.Errors, 1)
			atomic.AddUint64(&b.metrics.Errors, 1)
			b.abortBufferedFlowLocked(f)
		}
		f.stateMu.Unlock()
		return
	}
}

func (b *tcpBridge) sendPayload(f *tcpFlow, payload []byte) bool {
	for offset := 0; offset < len(payload); {
		f.stateMu.Lock()
		allowed := b.sendAllowanceLocked(f)
		if f.closed || f.finSent {
			f.stateMu.Unlock()
			return false
		}
		if allowed <= 0 {
			f.stateMu.Unlock()
			if !b.waitForACK(f, 10*time.Millisecond) {
				return false
			}
			continue
		}
		maxSegment := int(f.clientMSS)
		if clamp := int(b.mssClamp.Load()); clamp > 0 {
			maxSegment = minInt(maxSegment, clamp)
		}
		// Unconfigured interfaces retain the default IPv4 MTU. An explicit
		// positive MTU remains a hard limit on synthesized packets.
		mtu := b.parent.EffectiveMTU()
		if mtu <= 0 {
			mtu = 1500
		}
		maxSegment = minInt(maxSegment, mtu-40)
		if maxSegment <= 0 {
			b.removeFlowLocked(f)
			f.stateMu.Unlock()
			return false
		}
		size := minInt(minInt(maxSegment, allowed), len(payload)-offset)
		if !b.buffers.acquire(bufferCharge(size)) {
			b.abortBufferedFlowLocked(f)
			f.stateMu.Unlock()
			return false
		}
		data := make([]byte, size)
		copy(data, payload[offset:offset+size])
		f.txBytes += size
		seq := f.serverNxt
		// Publish the transmitted sequence range before another goroutine can
		// process its ACK. Each segment advances state exactly once.
		f.serverNxt += uint32(size)
		f.txMu.Lock()
		f.txQueue = append(f.txQueue, struct {
			seq     uint32
			data    []byte
			sentAt  time.Time
			retries int
			rtx     bool
		}{seq: seq, data: data, sentAt: time.Now()})
		f.txMu.Unlock()
		tos, ttl := b.parent.effTosTTL(f.tos, f.ttl)
		pkt := b.buildIPv4TCPWithIP(f.dstIP, f.srcIP, f.dstPort, f.srcPort, seq, f.clientNxt, 0x18, data, tos, ttl)
		if b.sendToGuest(f, pkt) {
			f.toCliBytes += uint64(size)
			f.toCliPkts++
		}
		if f.ccEnabled && f.cc != nil {
			f.cc.OnSent(size)
		}
		f.stateMu.Unlock()
		offset += size
		if pace := b.paceUS.Load(); pace > 0 {
			if !b.waitForACK(f, time.Duration(pace)*time.Microsecond) {
				return false
			}
		}
	}
	return true
}

func (b *tcpBridge) retransmitLoop(f *tcpFlow) {
	timer := time.NewTicker(50 * time.Millisecond)
	defer timer.Stop()
	for {
		select {
		case <-b.stopCh:
			return
		case <-f.rtoStop:
			return
		case <-timer.C:
		}
		f.stateMu.Lock()
		if f.closed {
			f.stateMu.Unlock()
			return
		}
		now := time.Now()
		finRetransmit := b.closeTickLocked(f, now)
		if f.closed {
			f.stateMu.Unlock()
			return
		}
		f.txMu.Lock()
		var packet core.Packet
		for i := range f.txQueue {
			seg := &f.txQueue[i]
			if !seqAfter(seg.seq+uint32(len(seg.data)), f.sndUna) || isSACKed(f, seg.seq, seg.seq+uint32(len(seg.data))) {
				continue
			}
			if !seg.sentAt.IsZero() && now.Sub(seg.sentAt) < f.rto {
				continue
			}
			seg.sentAt = now
			seg.retries++
			seg.rtx = true
			f.rto = minDur(2*f.rto, 2*time.Second)
			tos, ttl := b.parent.effTosTTL(f.tos, f.ttl)
			packet = b.buildIPv4TCPWithIP(f.dstIP, f.srcIP, f.dstPort, f.srcPort, seg.seq, f.clientNxt, 0x18, seg.data, tos, ttl)
			break
		}
		f.txMu.Unlock()
		if packet != nil {
			_ = b.sendToGuest(f, packet)
			if f.ccEnabled && f.cc != nil {
				f.cc.OnLoss(true)
			}
			atomic.AddUint64(&b.rtoCount, 1)
		}
		f.stateMu.Unlock()
		// Diagnostics take snapshots of multiple flows, so run them only
		// after releasing this flow's state lock.
		if packet != nil || finRetransmit {
			b.trackRTOFlow(f)
		}
	}
}
