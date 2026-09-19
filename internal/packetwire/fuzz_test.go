package packetwire_test

import (
	"bytes"
	"testing"

	"github.com/irctrakz/wgslirp/internal/packetwire"
)

// Independent byte-weighted oracle, using a wider accumulator than production.
func referenceChecksum(data []byte) uint16 {
	var total uint64
	for i, value := range data {
		if i%2 == 0 {
			total += uint64(value) * 256
		} else {
			total += uint64(value)
		}
	}
	for total > 65535 {
		total = total%65536 + total/65536
	}
	return uint16(65535 - total)
}

func FuzzEncoding(f *testing.F) {
	f.Add([]byte("abc"), []byte{2, 4, 5, 180, 1}, byte(1))
	f.Add([]byte{0xda, 0x61}, []byte{}, byte(1))
	f.Add([]byte{}, make([]byte, 41), byte(1))
	f.Fuzz(func(t *testing.T, payload, options []byte, mode byte) {
		// Bound per-execution allocation independently of generated input size.
		if len(payload) > 2048 || len(options) > 64 {
			t.Skip()
		}
		beforePayload, beforeOptions := bytes.Clone(payload), bytes.Clone(options)
		for _, protocol := range []byte{6, 17} {
			header := 8
			if protocol == 6 {
				header = 20 + ((len(options) + 3) &^ 3)
			}
			// Exact, too short and too long destination storage.
			delta := int(mode%3) - 1
			out := bytes.Repeat([]byte{0xa5}, 20+header+len(payload)+delta)
			before := bytes.Clone(out)
			var accepted bool
			if protocol == 6 {
				accepted = packetwire.TCP(out[20:], src, dst, 40000, 53, 0xfffffff0, 1, mode, 4096, payload, options)
			} else {
				accepted = packetwire.UDP(out[20:], src, dst, 40000, 53, payload)
			}
			want := delta == 0 && (protocol == 17 || len(options) <= 40)
			if accepted != want {
				t.Fatal("incorrect size admission")
			}
			if !accepted {
				if !bytes.Equal(out, before) {
					t.Fatal("rejection mutated output")
				}
				continue
			}
			if !bytes.Equal(out[:20], before[:20]) || !bytes.Equal(out[20+header:], payload) {
				t.Fatal("transport encoder crossed its boundary")
			}
			pseudo := append([]byte{}, src[:]...)
			pseudo = append(pseudo, dst[:]...)
			pseudo = append(pseudo, 0, protocol, byte((len(out)-20)>>8), byte(len(out)-20))
			pseudo = append(pseudo, out[20:]...)
			if referenceChecksum(pseudo) != 0 {
				t.Fatal("transport checksum")
			}
			if !packetwire.IPv4Header(out, src, dst, protocol, mode, 64, 123, 0) || referenceChecksum(out[:20]) != 0 {
				t.Fatal("IPv4 header checksum")
			}
		}
		if !bytes.Equal(payload, beforePayload) || !bytes.Equal(options, beforeOptions) {
			t.Fatal("borrowed input mutated")
		}
	})
}
