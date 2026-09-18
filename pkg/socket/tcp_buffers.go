package socket

import (
	"context"
	"net"
	"sync/atomic"
	"time"
)

func dialTCP(ctx context.Context, address string, timeout time.Duration) (*net.TCPConn, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	return conn.(*net.TCPConn), nil
}

// Caller holds stateMu. Exhaustion resets only this flow; no acknowledged
// bytes are silently discarded and unrelated flows keep their reservations.
func (b *tcpBridge) abortBufferedFlowLocked(f *tcpFlow) {
	b.bufferDrops.Add(1)
	_ = b.sendToGuest(f, b.buildIPv4TCP(f.dstIP, f.srcIP, f.dstPort, f.srcPort, f.serverNxt, f.clientNxt, 0x14, nil))
	b.removeFlowLocked(f)
}

// queueFuture reserves replacement storage while the old buffers remain live.
// Duplicate data needs no allocation. Merge accounting counts unique bytes,
// including transient overlap copies until ownership moves to the new slice.
func (b *tcpBridge) queueFuture(f *tcpFlow, seq uint32, payload []byte) bool {
	if len(payload) == 0 {
		return true
	}
	start, end := uint64(seq), uint64(seq)+uint64(len(payload))
	// Numeric ordering is used by this bounded queue. Do not mix sequence
	// epochs or retain a segment spanning wrap; the peer must retry in order.
	if seq < f.clientNxt || end > 1<<32 {
		return false
	}
	left, right := 0, 0
	for left < len(f.ooo) && uint64(f.ooo[left].seq)+uint64(len(f.ooo[left].data)) < start {
		left++
	}
	right = left
	oldBytes := 0
	for right < len(f.ooo) && uint64(f.ooo[right].seq) <= end {
		s := f.ooo[right]
		sStart, sEnd := uint64(s.seq), uint64(s.seq)+uint64(len(s.data))
		if sStart <= uint64(seq) && sEnd >= uint64(seq)+uint64(len(payload)) {
			return true
		}
		if sStart < start {
			start = sStart
		}
		if sEnd > end {
			end = sEnd
		}
		oldBytes += len(s.data)
		right++
	}
	size := int(end - start)
	if size > b.reasmCap-(f.futureBytes-oldBytes) {
		if b.parent != nil {
			b.parent.admission.reassemblyBytes.Add(1)
		}
		b.bufferDrops.Add(1)
		return false
	}
	if !b.buffers.acquire(bufferCharge(size)) {
		b.bufferDrops.Add(1)
		return false
	}
	merged := make([]byte, size)
	for _, s := range f.ooo[left:right] {
		copy(merged[uint64(s.seq)-start:], s.data)
	}
	copy(merged[uint64(seq)-start:], payload)
	// Clear removed slice entries so popped backing arrays retain no payloads.
	oldLen := len(f.ooo)
	copy(f.ooo[left:], f.ooo[right:])
	newLen := oldLen - (right - left)
	clear(f.ooo[newLen:])
	f.ooo = f.ooo[:newLen]
	f.ooo = append(f.ooo, struct {
		seq  uint32
		data []byte
	}{})
	copy(f.ooo[left+1:], f.ooo[left:len(f.ooo)-1])
	f.ooo[left] = struct {
		seq  uint32
		data []byte
	}{uint32(start), merged}
	f.futureBytes += size - oldBytes
	b.buffers.release(oldBytes + (right-left)*bufferEntryAllowance)
	return true
}

// flushReassembly requires stateMu. Partially overlapped segments are trimmed
// on delivery without copying; their full reservation lives until removal.
func (b *tcpBridge) flushReassembly(f *tcpFlow) error {
	for len(f.ooo) > 0 && f.conn != nil {
		s := f.ooo[0]
		if seqAfter(s.seq, f.clientNxt) {
			break
		}
		skip := int(f.clientNxt - s.seq)
		if skip < len(s.data) {
			n, err := writeTCP(f.conn, s.data[skip:])
			if err != nil {
				return err
			}
			atomic.AddUint64(&b.metrics.BytesSent, uint64(n))
			atomic.AddUint64(&b.metrics.PacketsSent, 1)
			atomic.AddUint64(&b.parent.metrics.BytesSent, uint64(n))
			atomic.AddUint64(&b.parent.metrics.PacketsSent, 1)
			f.toSrvBytes += uint64(n)
			f.toSrvPkts++
			f.clientNxt += uint32(n)
		}
		f.ooo[0].data = nil
		f.ooo = f.ooo[1:]
		f.futureBytes -= len(s.data)
		b.buffers.release(bufferCharge(len(s.data)))
	}
	if len(f.ooo) == 0 {
		f.ooo = nil
	}
	return nil
}
