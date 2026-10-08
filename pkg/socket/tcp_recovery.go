package socket

import (
	"encoding/binary"
	"github.com/irctrakz/wgslirp/pkg/core"
	"sync/atomic"
	"time"
)

// --- SACK helpers ---

func parseSACKBlocks(f *tcpFlow, opts []byte) {
	f.sackMu.Lock()
	defer f.sackMu.Unlock()
	// Collect blocks
	blocks := make([]struct{ left, right uint32 }, 0, 4)
	for i := 0; i < len(opts); {
		kind := opts[i]
		if kind == 0 {
			break
		}
		if kind == 1 {
			i++
			continue
		}
		if i+1 >= len(opts) {
			break
		}
		l := int(opts[i+1])
		if l < 2 || i+l > len(opts) {
			break
		}
		if kind == 5 && (l-2)%8 == 0 { // SACK
			for j := i + 2; j+7 < i+l; j += 8 {
				left := binary.BigEndian.Uint32(opts[j : j+4])
				right := binary.BigEndian.Uint32(opts[j+4 : j+8])
				if seqAfter(right, left) {
					blocks = append(blocks, struct{ left, right uint32 }{left, right})
				}
			}
		}
		i += l
	}
	// Merge only ranges inside the outstanding send window. Offsets from
	// sndUna are ordered even when the actual sequence numbers wrap. Drop
	// acknowledged/stale blocks on every ACK so they cannot survive a full lap.
	// Caller holds stateMu; TCP windows are smaller than half the sequence space.
	// Merge with existing, normalize and cap size
	all := append([]struct{ left, right uint32 }{}, f.sackList...)
	all = append(all, blocks...)
	valid := all[:0]
	for _, block := range all {
		if !seqAfter(block.right, f.sndUna) || seqAfter(block.right, f.serverNxt) {
			continue
		}
		if seqBefore(block.left, f.sndUna) {
			block.left = f.sndUna
		}
		if !seqBefore(block.left, block.right) {
			continue
		}
		valid = append(valid, block)
	}
	all = valid
	// sort by left (simple insertion sort for small N)
	for i := 1; i < len(all); i++ {
		j := i
		for j > 0 && all[j-1].left-f.sndUna > all[j].left-f.sndUna {
			all[j-1], all[j] = all[j], all[j-1]
			j--
		}
	}
	// merge overlaps
	merged := make([]struct{ left, right uint32 }, 0, len(all))
	for _, b := range all {
		if len(merged) == 0 || seqAfter(b.left, merged[len(merged)-1].right) {
			merged = append(merged, b)
		} else if seqAfter(b.right, merged[len(merged)-1].right) {
			merged[len(merged)-1].right = b.right
		}
	}
	// cap to last 4 blocks to match typical SACK cache sizes
	if len(merged) > 4 {
		merged = merged[len(merged)-4:]
	}
	f.sackList = merged
}

func isSACKed(f *tcpFlow, left, right uint32) bool {
	f.sackMu.Lock()
	list := append([]struct{ left, right uint32 }{}, f.sackList...)
	f.sackMu.Unlock()
	for _, b := range list {
		if seqBefore(left, right) && !seqBefore(left, b.left) && !seqAfter(right, b.right) {
			return true
		}
	}
	return false
}

// --- RFC 6675 simplified helpers ---

func (b *tcpBridge) retransmitNextHole(f *tcpFlow) {
	// Compute pipe (bytes in flight not SACKed)
	f.txMu.Lock()
	inFlight := 0
	for _, s := range f.txQueue {
		if !seqAfter(s.seq+uint32(len(s.data)), f.sndUna) {
			continue
		}
		if isSACKed(f, s.seq, s.seq+uint32(len(s.data))) {
			continue
		}
		inFlight += len(s.data)
	}
	f.pipeBytes = inFlight
	cw := b.cwndBytes(f)
	budget := cw - inFlight
	if budget < 1 {
		f.txMu.Unlock()
		return
	}
	// Find first unsacked, unacked hole segment
	idx := -1
	for i := 0; i < len(f.txQueue); i++ {
		s := f.txQueue[i]
		if !seqAfter(s.seq+uint32(len(s.data)), f.sndUna) {
			continue
		}
		if isSACKed(f, s.seq, s.seq+uint32(len(s.data))) {
			continue
		}
		idx = i
		break
	}
	if idx < 0 {
		f.txMu.Unlock()
		return
	}
	seg := f.txQueue[idx]
	// Mark retransmit
	f.txQueue[idx].sentAt = time.Now()
	f.txQueue[idx].retries++
	f.txQueue[idx].rtx = true
	f.txMu.Unlock()

	tosOut, ttlOut := f.tos, f.ttl
	if b.parent != nil {
		tosOut, ttlOut = b.parent.effTosTTL(f.tos, f.ttl)
	}
	pkt := b.buildIPv4TCPWithIP(f.dstIP, f.srcIP, f.dstPort, f.srcPort,
		seg.seq, f.clientNxt, 0x18, seg.data, tosOut, ttlOut)
	if pkt != nil {
		_ = b.sendToGuest(f, pkt)
		if f.ccEnabled && f.cc != nil {
			f.cc.OnLoss(false)
		}
	}
}

func (b *tcpBridge) cwndBytes(f *tcpFlow) int {
	if f.ccEnabled && f.cc != nil {
		cw := f.cc.Cwnd()
		if cw < f.mss {
			cw = f.mss
		}
		return cw
	}
	// Fallback to peer's advertised window when CC is disabled
	if f.advWnd > 0 {
		return int(f.advWnd)
	}
	return 65535
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
