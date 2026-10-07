//go:build integration && mixed && linux

package wireguard

import (
	"bytes"
	"io"
	"testing"
)

// The sustained benchmark's byte verifier must reject corruption, truncation and
// trailing data; otherwise a faster incomplete transfer could look successful.
func TestMixedStreamingVerifier(t *testing.T) {
	block := []byte{1, 2, 3, 4, 5}
	want := bytes.Repeat(block, 3)
	for _, chunk := range []int{1, 3, 16} {
		r := &mixedRepeatedReader{block: block, remaining: int64(len(want))}
		var got []byte
		buf := make([]byte, chunk)
		for {
			n, err := r.Read(buf)
			got = append(got, buf[:n]...)
			if err == io.EOF {
				break
			}
			if err != nil || n == 0 {
				t.Fatal("invalid streaming reader progress")
			}
		}
		if !bytes.Equal(got, want) {
			t.Fatal("streamed bytes mismatch")
		}
	}
	if err := mixedVerifyRepeated(bytes.NewReader(want), block, 3); err != nil {
		t.Fatal(err)
	}
	corrupt := append([]byte(nil), want...)
	corrupt[7] ^= 0xff
	for name, data := range map[string][]byte{
		"corrupt": corrupt, "truncated": want[:len(want)-1], "trailing": append(append([]byte(nil), want...), 6),
	} {
		t.Run(name, func(t *testing.T) {
			if mixedVerifyRepeated(bytes.NewReader(data), block, 3) == nil {
				t.Fatal("invalid transfer accepted")
			}
		})
	}
}
