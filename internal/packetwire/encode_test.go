package packetwire_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/irctrakz/wgslirp/internal/packetwire"
)

var src = [4]byte{10, 0, 0, 2}
var dst = [4]byte{127, 0, 0, 1}

func golden(t *testing.T, got []byte, want string) {
	t.Helper()
	data, err := hex.DecodeString(want)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("got %x want %x", got, data)
	}
}

// Literal expected bytes were independently calculated, not produced by the
// encoders/checksums under test. Dirty output models reused pooled storage.
func TestKnownWireBytes(t *testing.T) {
	ip := bytes.Repeat([]byte{0xa5}, 31)
	if !packetwire.IPv4Header(ip, src, dst, 17, 0x2e, 37, 0x1234, 0x2003) {
		t.Fatal("header refused")
	}
	golden(t, ip[:20], "452e001f123420032511da660a0000027f000001")
	if !bytes.Equal(ip[20:], bytes.Repeat([]byte{0xa5}, 11)) {
		t.Fatal("IP encoder touched payload")
	}
	udp := bytes.Repeat([]byte{0xa5}, 11)
	if !packetwire.UDP(udp, src, dst, 40000, 53, []byte("abc")) {
		t.Fatal("UDP refused")
	}
	golden(t, udp, "9c400035000b15fd616263")
	tcp := bytes.Repeat([]byte{0xa5}, 31)
	options := []byte{2, 4, 5, 180, 1}
	payload := []byte("abc")
	if !packetwire.TCP(tcp, src, dst, 40000, 80, 0xfffffff0, 0x10203040, 0x18, 4096, payload, options) {
		t.Fatal("TCP refused")
	}
	golden(t, tcp, "9c400050fffffff010203040701810004cc20000020405b401000000616263")
	if string(payload) != "abc" || !bytes.Equal(options, []byte{2, 4, 5, 180, 1}) {
		t.Fatal("input mutated")
	}
}

func TestUDPComputedZero(t *testing.T) {
	out := make([]byte, 10)
	if !packetwire.UDP(out, src, dst, 40000, 53, []byte{0xda, 0x61}) {
		t.Fatal("UDP refused")
	}
	golden(t, out, "9c400035000affffda61")
	if packetwire.TransportChecksum(out, src, dst, 17) != 0 {
		t.Fatal("wire checksum invalid")
	}
}

func TestInvalidSizesLeaveOutputUntouched(t *testing.T) {
	for _, size := range []int{0, 19, 65536} {
		out := bytes.Repeat([]byte{0xa5}, size)
		before := bytes.Clone(out)
		if packetwire.IPv4Header(out, src, dst, 6, 0, 64, 0, 0) || !bytes.Equal(out, before) {
			t.Fatal("invalid IP size modified output")
		}
	}
	for _, size := range []int{0, 7, 9} {
		out := bytes.Repeat([]byte{0xa5}, size)
		before := bytes.Clone(out)
		if packetwire.UDP(out, src, dst, 1, 2, nil) || !bytes.Equal(out, before) {
			t.Fatal("invalid UDP size modified output")
		}
	}
	for _, options := range [][]byte{nil, make([]byte, 41)} {
		out := bytes.Repeat([]byte{0xa5}, 19)
		before := bytes.Clone(out)
		if packetwire.TCP(out, src, dst, 1, 2, 3, 4, 2, 10, nil, options) || !bytes.Equal(out, before) {
			t.Fatal("invalid TCP size modified output")
		}
	}
	oversized := bytes.Repeat([]byte{0xa5}, 65516)
	before := bytes.Clone(oversized)
	if packetwire.UDP(oversized, src, dst, 1, 2, make([]byte, 65508)) || !bytes.Equal(oversized, before) {
		t.Fatal("oversized UDP accepted")
	}
	if packetwire.TCP(oversized, src, dst, 1, 2, 3, 4, 2, 10, make([]byte, 65496), nil) || !bytes.Equal(oversized, before) {
		t.Fatal("oversized TCP accepted")
	}
}

func TestMaximumSizesAndNoAllocations(t *testing.T) {
	payload := make([]byte, 65507)
	out := make([]byte, 65535)
	if !packetwire.IPv4Header(out, src, dst, 17, 0, 64, 1, 0) || !packetwire.UDP(out[20:], src, dst, 1, 2, payload) {
		t.Fatal("maximum UDP refused")
	}
	if !packetwire.TCP(out[20:], src, dst, 1, 2, 3, 4, 2, 65535, payload[:65455], make([]byte, 40)) {
		t.Fatal("maximum TCP refused")
	}
	if n := testing.AllocsPerRun(100, func() {
		packetwire.IPv4Header(out[:28], src, dst, 17, 0, 64, 1, 0)
		packetwire.UDP(out[20:28], src, dst, 1, 2, nil)
		packetwire.TCP(out[20:40], src, dst, 1, 2, 3, 4, 2, 65535, nil, nil)
	}); n != 0 {
		t.Fatalf("encoder allocated: %v", n)
	}
}
