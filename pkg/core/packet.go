package core

import (
	"sync/atomic"
)

// Global debug flag that can be set via configuration
var debugMode uint32

// SetDebugMode sets the global debug mode flag
// When debug mode is enabled, packet data is copied for safety
// When disabled, packet data is not copied for performance
func SetDebugMode(enabled bool) {
	if enabled {
		atomic.StoreUint32(&debugMode, 1)
	} else {
		atomic.StoreUint32(&debugMode, 0)
	}
}

// IsDebugMode returns whether debug mode is enabled
func IsDebugMode() bool {
	return atomic.LoadUint32(&debugMode) == 1
}

// Packet represents a network packet
type Packet interface {
	// Data returns the packet data
	// In debug mode, this returns a copy of the data
	// In non-debug mode, this returns the internal data directly for performance
	Data() []byte

	// Length returns the packet length
	Length() int
}

// BorrowPacketData returns a read-only view valid until the packet is released.
// It avoids diagnostic copies for built-in packets. Callers must neither mutate
// nor retain the view beyond the packet's ownership lifetime.
func BorrowPacketData(packet Packet) []byte {
	switch p := packet.(type) {
	case *SimplePacket:
		return p.data
	case *pooledPacket:
		return p.data
	default:
		return packet.Data()
	}
}

// PacketBufferSize reports retained slice capacity rather than payload length.
// Built-in packets can be measured without Data's optional debug copy. Custom
// packets must expose their retained storage through Data; allocator overhead
// and unrelated storage hidden by a custom implementation are not included.
func PacketBufferSize(packet Packet) int {
	switch p := packet.(type) {
	case *SimplePacket:
		return cap(p.data)
	case *pooledPacket:
		return cap(p.data)
	default:
		return cap(packet.Data())
	}
}

// pooledPacket is a Packet implementation backed by a reusable buffer.
// The buffer must not be modified by consumers. When processing of the
// packet completes, ReleasePacket should be called to return the buffer
// to its pool. If the packet escapes, the buffer will be reclaimed by GC
// but not necessarily returned to any pool.
type pooledPacket struct {
	data     []byte
	releaser func([]byte)
}

// NewPooledPacket wraps an existing byte slice as a Packet with an optional
// releaser. The releaser may be nil. Do not mutate data after passing it in.
func NewPooledPacket(data []byte, releaser func([]byte)) Packet {
	if data == nil {
		data = make([]byte, 0)
	}
	return &pooledPacket{data: data, releaser: releaser}
}

func (p *pooledPacket) Data() []byte { return p.data }
func (p *pooledPacket) Length() int  { return len(p.data) }

// Released reports whether this pooled packet's buffer has already been
// released back to its pool (i.e., the buffer is no longer valid). This is
// primarily intended for guarded sanity checks in upstream processors to
// detect misuse (early release before processing completes).
func (p *pooledPacket) Released() bool { return p.data == nil }

// ReleasePacket returns a packet's underlying buffer to its pool if it was
// created via NewPooledPacket and a releaser was provided.
func ReleasePacket(p Packet) {
	if pp, ok := p.(*pooledPacket); ok {
		data, release := pp.data, pp.releaser
		pp.data, pp.releaser = nil, nil
		if release != nil {
			release(data)
		}
	}
}

// SimplePacket is a simple implementation of Packet
type SimplePacket struct {
	data []byte
}

// NewPacket creates a new packet
func NewPacket(data []byte) Packet {
	if data == nil {
		data = make([]byte, 0)
		return &SimplePacket{data: data}
	}

	// In debug mode, make a copy of the data for safety
	if IsDebugMode() {
		dataCopy := make([]byte, len(data))
		copy(dataCopy, data)
		return &SimplePacket{data: dataCopy}
	}

	// In non-debug mode, use the data directly for performance
	return &SimplePacket{data: data}
}

// Data returns the packet data
func (p *SimplePacket) Data() []byte {
	// In debug mode, make a copy of the data for safety
	if IsDebugMode() {
		dataCopy := make([]byte, len(p.data))
		copy(dataCopy, p.data)
		return dataCopy
	}

	// In non-debug mode, return the internal data directly for performance
	return p.data
}

// Length returns the packet length
func (p *SimplePacket) Length() int {
	return len(p.data)
}
