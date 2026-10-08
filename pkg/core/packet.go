package core

// Packet represents a network packet
type Packet interface {
	// Data returns a borrowed read-only view, valid until release.
	// Use CopyPacketData for independent mutable bytes.
	Data() []byte

	// Length returns the packet length
	Length() int
}

// NewBorrowedPacket wraps data without copying, independently of debug mode.
// The caller must keep the backing storage valid and unmodified until every
// consumer finishes. Use NewCopiedPacket when retaining or reusing caller data.
func NewBorrowedPacket(data []byte) Packet {
	return &readOnlyPacket{data: data}
}

// NewCopiedPacket snapshots data into independent storage, regardless of debug
// mode. Packet access remains read-only; use CopyPacketData for mutable bytes.
func NewCopiedPacket(data []byte) Packet {
	copyOfData := make([]byte, len(data))
	copy(copyOfData, data)
	return &readOnlyPacket{data: copyOfData}
}

type readOnlyPacket struct{ data []byte }

func (p *readOnlyPacket) Data() []byte { return p.data }
func (p *readOnlyPacket) Length() int  { return len(p.data) }

// CopyPacketData returns independent, mutable bytes that remain valid after
// the packet is released. It does not transfer or release packet ownership.
func CopyPacketData(packet Packet) []byte {
	data := BorrowPacketData(packet)
	result := make([]byte, len(data))
	copy(result, data)
	return result
}

// BorrowPacketData returns a read-only view valid until the packet is released.
// Built-in packets do not copy on access. Callers must neither mutate
// nor retain the view beyond the packet's ownership lifetime. For custom Packet
// implementations it uses Data(), which must obey the same borrowed-view contract.
func BorrowPacketData(packet Packet) []byte {
	return packet.Data()
}

// PacketBufferSize reports retained slice capacity rather than payload length.
// Built-in packets expose their retained backing storage directly. Custom
// packets must expose their retained storage through Data; allocator overhead
// and unrelated storage hidden by a custom implementation are not included.
func PacketBufferSize(packet Packet) int {
	return cap(packet.Data())
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
