package socket

import (
	"bytes"
	"testing"
	"time"
	"unsafe"
)

// Fixtures are built outside the timed region so allocation results isolate the
// reassembler, including its completion/release and expiry ownership paths.
func BenchmarkIPv4Fragments(b *testing.B) {
	for _, tc := range []struct {
		name string
		size int
	}{{"Small", 128}, {"MTUDatagram", 1360}, {"Large", 8192}, {"Maximum", 65515}} {
		for _, reverse := range []bool{false, true} {
			name := tc.name + "/Ordered"
			if reverse {
				name = tc.name + "/ReorderedDuplicate"
			}
			b.Run(name, func(b *testing.B) {
				body := make([]byte, tc.size)
				for i := range body {
					body[i] = byte(i)
				}
				chunk := 1176
				if tc.size < chunk {
					chunk = 64
				}
				var packets [][]byte
				for offset := 0; offset < len(body); offset += chunk {
					end := minInt(offset+chunk, len(body))
					packets = append(packets, fragmentFixture(17, 1, offset, end < len(body), body[offset:end]))
				}
				if reverse {
					// Duplicate an incomplete range, then deliver remaining ranges
					// backwards; the first fragment still arrives first.
					ordered := [][]byte{packets[0], packets[0]}
					for i := len(packets) - 1; i > 0; i-- {
						ordered = append(ordered, packets[i])
					}
					packets = ordered
				}
				budget := &resourceBudget{limit: ipv4FragmentCharge}
				r := newIPv4Fragments(budget, ipv4FragmentCharge)
				now := time.Unix(1, 0)
				b.ReportAllocs()
				b.SetBytes(int64(tc.size))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					for _, p := range packets {
						out, release, err := r.add(p, now)
						if err != nil {
							b.Fatal(err)
						}
						if out != nil {
							if !bytes.Equal(out[20:], body) {
								b.Fatal("payload mismatch")
							}
							release()
						}
					}
				}
				b.StopTimer()
				if r.used != 0 || r.live != 0 {
					b.Fatal("completion retained ownership")
				}
			})
		}
	}
	for _, late := range []bool{false, true} {
		name := "MissingRangeExpiry"
		if late {
			name = "LateDuplicateExpiry"
		}
		b.Run(name, func(b *testing.B) {
			p := fragmentFixture(17, 1, 0, true, make([]byte, 1176))
			if late {
				p = fragmentFixture(17, 1, 1176, false, make([]byte, 184))
			}
			budget := &resourceBudget{limit: ipv4FragmentCharge}
			r := newIPv4Fragments(budget, ipv4FragmentCharge)
			now := time.Unix(1, 0)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, _, err := r.add(p, now); err != nil {
					b.Fatal(err)
				}
				for _, d := range r.expire(now.Add(ipv4FragmentLifetime)) {
					r.release(d)
				}
			}
			b.StopTimer()
			if r.used != 0 || r.live != 0 {
				b.Fatal("expiry retained ownership")
			}
		})
	}
	for _, highOffset := range []bool{false, true} {
		name := "QuotaSaturationInline"
		if highOffset {
			name = "QuotaSaturationFull"
		}
		b.Run(name, func(b *testing.B) {
			packets := make([][]byte, ipv4FragmentDatagrams+1)
			for i := range packets {
				start := 0
				if highOffset {
					start = 65504
				}
				p := fragmentFixture(17, uint16(i), start, !highOffset, make([]byte, 8))
				p[15] = byte(20 + i/ipv4FragmentSources)
				fragmentChecksum(p)
				packets[i] = p
			}
			budget := &resourceBudget{limit: DefaultIPv4FragmentBufferCap}
			r := newIPv4Fragments(budget, DefaultIPv4FragmentBufferCap)
			now := time.Unix(1, 0)
			ownedStorage := 0
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for j, p := range packets {
					_, _, err := r.add(p, now)
					if (j < ipv4FragmentDatagrams && err != nil) || (j == ipv4FragmentDatagrams && err != ErrIPv4FragmentLimit) {
						b.Fatal("quota admission", j, err)
					}
				}
				if i == 0 {
					for _, d := range r.entries {
						ownedStorage += int(unsafe.Sizeof(fragmentDatagram{}))
						if cap(d.data) == 65535 {
							ownedStorage += cap(d.data)
						}
					}
				}
				for _, d := range r.expire(now.Add(ipv4FragmentLifetime)) {
					r.release(d)
				}
			}
			b.StopTimer()
			if r.used != 0 || r.live != 0 || budget.used != 0 {
				b.Fatal("quota expiry retained ownership")
			}
			// Logical owned assembly storage, excluding map/allocator overhead;
			// the unchanged reservation is deliberately more conservative.
			b.ReportMetric(float64(ownedStorage), "owned-B/cycle")
		})
	}
}
