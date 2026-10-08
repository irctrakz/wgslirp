package core

import (
	"bytes"
	"testing"
)

func TestExplicitPacketOwnership(t *testing.T) {
	input := make([]byte, 3, 64)
	copy(input, []byte{1, 2, 3})
	borrowed, copied := NewBorrowedPacket(input), NewCopiedPacket(input)
	if &BorrowPacketData(borrowed)[0] != &input[0] || &borrowed.Data()[0] != &input[0] {
		t.Fatal("borrowed constructor/access copied")
	}
	if &BorrowPacketData(copied)[0] == &input[0] || PacketBufferSize(borrowed) != 64 {
		t.Fatal("copy ownership or retained-capacity accounting differs")
	}
	mutable := CopyPacketData(copied)
	mutable[0] = 99
	if !bytes.Equal(BorrowPacketData(copied), []byte{1, 2, 3}) {
		t.Fatal("mutable copy changed packet")
	}
	if testing.AllocsPerRun(100, func() { _ = BorrowPacketData(borrowed) }) != 0 {
		t.Fatal("borrowed view allocated")
	}
	ReleasePacket(borrowed)
	input[0] = 88 // Consumer is finished; caller may reuse its input.
	if !bytes.Equal(BorrowPacketData(copied), []byte{1, 2, 3}) {
		t.Fatal("snapshot retained caller alias")
	}
}

func TestExplicitCopySurvivesPooledRelease(t *testing.T) {
	data := make([]byte, 3, 4096)
	copy(data, []byte{1, 2, 3})
	releases := 0
	p := NewPooledPacket(data, func(data []byte) { releases++; clear(data) })
	if PacketBufferSize(p) != 4096 || &p.Data()[0] != &data[0] {
		t.Fatal("pooled ownership or capacity changed")
	}
	retained := CopyPacketData(p)
	ReleasePacket(p)
	ReleasePacket(p)
	if releases != 1 || !bytes.Equal(retained, []byte{1, 2, 3}) || PacketBufferSize(p) != 0 {
		t.Fatal("copy lifetime, capacity or exactly-once release violated")
	}
	for _, empty := range []Packet{NewBorrowedPacket(nil), NewCopiedPacket(nil)} {
		if empty.Length() != 0 || len(CopyPacketData(empty)) != 0 {
			t.Fatal("invalid empty packet")
		}
	}
	empty := NewPooledPacket(nil, func([]byte) { releases++ })
	ReleasePacket(empty)
	ReleasePacket(empty)
	if releases != 2 {
		t.Fatal("empty pooled release was not exactly once")
	}
}
