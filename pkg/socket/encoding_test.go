package socket

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestUDPFragmentsPreserveComputedZeroChecksum(t *testing.T) {
	// Independently derived zero-checksum payload; a minimum MTU splits the
	// UDP header and payload. Reassemble without using production encoders.
	fragments := buildIPv4UDPFragmentsWith([4]byte{10, 0, 0, 2}, [4]byte{127, 0, 0, 1}, 40000, 53, []byte{0xda, 0x61}, 0x2e, 37, 29)
	if len(fragments) != 2 {
		t.Fatalf("fragments=%d", len(fragments))
	}
	var got []byte
	for i, p := range fragments {
		if p[1] != 0x2e || p[8] != 37 || !bytes.Equal(p[4:6], fragments[0][4:6]) {
			t.Fatal("fragment policy changed")
		}
		want := uint16(0x2000)
		if i == 1 {
			want = 1
		}
		if binary.BigEndian.Uint16(p[6:8]) != want {
			t.Fatal("fragment offset/flags")
		}
		got = append(got, p[20:]...)
	}
	if !bytes.Equal(got, []byte{0x9c, 0x40, 0, 0x35, 0, 10, 0xff, 0xff, 0xda, 0x61}) {
		t.Fatalf("reassembled: %x", got)
	}
}
