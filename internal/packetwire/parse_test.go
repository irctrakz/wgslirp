package packetwire_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/irctrakz/wgslirp/internal/packetwire"
)

func TestParseBorrowedDatagram(t *testing.T) {
	// Independent fixed wire fixture, including an odd-length UDP payload.
	packet, err := hex.DecodeString("4500001f123400004011df970a0000027f0000019c400035000b15fd616263")
	if err != nil {
		t.Fatal(err)
	}
	packet = append(packet, 0xaa, 0xbb)
	before := bytes.Clone(packet)
	got, ihl, err := packetwire.ParseTransport(packet, 17)
	if err != nil || ihl != 20 || len(got) != 31 || &got[0] != &packet[0] {
		t.Fatalf("borrowed boundary: %x %d %v", got, ihl, err)
	}
	if !bytes.Equal(packet, before) {
		t.Fatal("input mutated")
	}
	if n := testing.AllocsPerRun(100, func() { packetwire.ParseTransport(packet, 17) }); n != 0 {
		t.Fatalf("successful parser allocated: %v", n)
	}
	for i := 0; i < 31; i++ {
		got, ihl, err := packetwire.ParseTransport(packet[:i], 17)
		if err == nil || got != nil || ihl != 0 {
			t.Fatalf("truncation %d accepted", i)
		}
	}
	if _, _, err := packetwire.ParseTransport(packet, 6); !errors.Is(err, packetwire.ErrMalformedPacket) {
		t.Fatal(err)
	}
	packet[28] ^= 1
	if _, _, err := packetwire.ParseTransport(packet, 17); !errors.Is(err, packetwire.ErrInvalidChecksum) || !errors.Is(err, packetwire.ErrMalformedPacket) {
		t.Fatal(err)
	}
}
