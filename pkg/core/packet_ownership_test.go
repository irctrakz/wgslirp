package core

import (
	"bytes"
	"testing"
)

func TestExplicitPacketOwnershipIgnoresDebug(t *testing.T) {
	original := IsDebugMode()
	t.Cleanup(func() { SetDebugMode(original) })
	for _, constructDebug := range []bool{false, true} {
		SetDebugMode(constructDebug)
		input := make([]byte, 3, 64)
		copy(input, []byte{1, 2, 3})
		borrowed, copied := NewBorrowedPacket(input), NewCopiedPacket(input)
		for _, accessDebug := range []bool{false, true} {
			SetDebugMode(accessDebug)
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
		}
		// Borrowed consumer is finished; caller may now reuse its input.
		ReleasePacket(borrowed)
		input[0] = 88
		if !bytes.Equal(BorrowPacketData(copied), []byte{1, 2, 3}) {
			t.Fatal("snapshot retained caller alias")
		}
	}
}

func TestExplicitCopySurvivesPooledRelease(t *testing.T) {
	original := IsDebugMode()
	t.Cleanup(func() { SetDebugMode(original) })
	for _, debug := range []bool{false, true} {
		SetDebugMode(debug)
		releases := 0
		p := NewPooledPacket([]byte{1, 2, 3}, func(data []byte) { releases++; clear(data) })
		retained := CopyPacketData(p)
		ReleasePacket(p)
		ReleasePacket(p)
		if releases != 1 || !bytes.Equal(retained, []byte{1, 2, 3}) {
			t.Fatal("copy lifetime or exactly-once release violated")
		}
		for _, empty := range []Packet{NewBorrowedPacket(nil), NewCopiedPacket(nil)} {
			if empty.Length() != 0 || len(CopyPacketData(empty)) != 0 {
				t.Fatal("invalid empty packet")
			}
		}
	}
}
