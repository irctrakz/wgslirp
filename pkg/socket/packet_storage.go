package socket

import (
	"encoding/binary"
	"fmt"
	"github.com/irctrakz/wgslirp/internal/packetwire"
	"github.com/irctrakz/wgslirp/pkg/core"
	"sync/atomic"
)

// buildPacket reserves before synthesis and transfers the reservation with the
// packet. Consumers release accepted packets; rejection remains the producer's
// responsibility. The builder must allocate exactly size bytes, or its pool class.
func (b *resourceBudget) buildPacket(size int, pooled bool, build func() []byte) core.Packet {
	if size <= 0 || size > 65535 {
		return nil
	}
	capacity := size
	if pooled && poolingEnabled() {
		capacity = packetCapacity(size)
	}
	release, err := b.ReservePacketBuffer(capacity)
	if err != nil {
		return nil
	}
	data := build()
	if data == nil {
		release()
		return nil
	}
	return core.NewPooledPacket(data, func(buf []byte) {
		if pooled && poolingEnabled() && pktShouldPut(buf) {
			pktPut(buf)
		}
		release()
	})
}

// deliverPacket transfers ownership on success, and releases on all rejection
// paths. A synchronous consumer may already have released before returning.
func deliverPacket(processor core.PacketProcessor, packet core.Packet) bool {
	if packet == nil {
		return false
	}
	if processor != nil && processor.ProcessPacket(packet) == nil {
		return true
	}
	core.ReleasePacket(packet)
	return false
}

// A refused initial SYN-ACK must not leave an unsendable candidate registered.
// The caller holds the flow state lock. A subsequent SYN can try admission again.
func (b *tcpBridge) sendSYNACKLocked(f *tcpFlow, packet core.Packet) error {
	if packet == nil {
		b.removeFlowLocked(f)
		return ErrBufferLimit
	}
	if !b.sendToGuest(f, packet) {
		b.removeFlowLocked(f)
		return fmt.Errorf("TCP SYN-ACK delivery refused")
	}
	f.synAckSent = true
	return nil
}

func (b *tcpBridge) buildIPv4TCP(src, dst [4]byte, sport, dport uint16, seq, ack uint32, flags byte, payload []byte) core.Packet {
	return b.buildIPv4TCPOptsWith(src, dst, sport, dport, seq, ack, flags, payload, nil, 0, 64)
}

func (b *tcpBridge) buildIPv4TCPOpts(src, dst [4]byte, sport, dport uint16, seq, ack uint32, flags byte, payload, options []byte) core.Packet {
	return b.buildIPv4TCPOptsWith(src, dst, sport, dport, seq, ack, flags, payload, options, 0, 64)
}

func (b *tcpBridge) buildIPv4TCPWithIP(src, dst [4]byte, sport, dport uint16, seq, ack uint32, flags byte, payload []byte, tos, ttl byte) core.Packet {
	return b.buildIPv4TCPOptsWith(src, dst, sport, dport, seq, ack, flags, payload, nil, tos, ttl)
}

func (b *tcpBridge) buildIPv4TCPOptsWith(src, dst [4]byte, sport, dport uint16, seq, ack uint32, flags byte, payload, options []byte, tos, ttl byte) core.Packet {
	if len(options) > 40 || len(payload) > 65535-40-((len(options)+3)&^3) {
		return nil
	}
	size := 40 + ((len(options) + 3) &^ 3) + len(payload)
	return b.buffers.buildPacket(size, true, func() []byte {
		return buildIPv4TCPOptsWith(src, dst, sport, dport, seq, ack, flags, payload, options, tos, ttl)
	})
}

// deliverDatagram reserves the full datagram before construction, then builds
// one fragment at a time. Downstream retention remains charged independently.
func (b *udpBridge) deliverDatagram(f *udpFlow, payload []byte, tos, ttl byte, mtu int) {
	if len(payload) > 65507 || mtu <= 28 {
		return
	}
	full := b.buffers.buildPacket(28+len(payload), false, func() []byte {
		return buildIPv4UDPWith(f.dstIP, f.srcIP, f.dstPort, f.srcPort, payload, tos, ttl)
	})
	if full == nil {
		return
	}
	if full.Length() <= mtu {
		b.deliverReply(full)
		return
	}
	defer core.ReleasePacket(full)
	data := core.BorrowPacketData(full)
	datagram := data[20:]
	maxFragment := (mtu - 20) &^ 7
	for offset := 0; offset < len(datagram); {
		size := minInt(maxFragment, len(datagram)-offset)
		fragment := b.buffers.buildPacket(20+size, false, func() []byte {
			out := make([]byte, 20+size)
			flags := uint16(offset / 8)
			if offset+size < len(datagram) {
				flags |= 0x2000
			}
			packetwire.IPv4Header(out, f.dstIP, f.srcIP, 17, data[1], data[8], binary.BigEndian.Uint16(data[4:6]), flags)
			copy(out[20:], datagram[offset:offset+size])
			return out
		})
		if fragment == nil || !b.deliverReply(fragment) {
			return
		}
		offset += size
	}
}

func (b *udpBridge) deliverReply(packet core.Packet) bool {
	if packet == nil {
		return false
	}
	size := packet.Length()
	b.txEnqueued.Add(1)
	if !b.deliver(packet) {
		b.deliveryRefused.Add(1)
		return false
	}
	b.txProcessed.Add(1)
	atomic.AddUint64(&b.metrics.PacketsReceived, 1)
	atomic.AddUint64(&b.metrics.BytesReceived, uint64(size))
	atomic.AddUint64(&b.parent.metrics.PacketsReceived, 1)
	atomic.AddUint64(&b.parent.metrics.BytesReceived, uint64(size))
	return true
}

func (b *tcpBridge) buildICMPUnreachable(src, dst [4]byte, code byte, original []byte) core.Packet {
	return b.buffers.buildICMPUnreachable(src, dst, code, original)
}

func (b *resourceBudget) buildICMPUnreachable(src, dst [4]byte, code byte, original []byte) core.Packet {
	if len(original) < 20 {
		return nil
	}
	ihl := int(original[0]&15) * 4
	if ihl < 20 || ihl > len(original) {
		return nil
	}
	size := 28 + minInt(ihl+8, len(original))
	return b.buildPacket(size, true, func() []byte {
		return buildICMPUnreachable(src, dst, code, original)
	})
}
