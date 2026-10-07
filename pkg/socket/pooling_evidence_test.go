//go:build pooling

package socket

import (
	"fmt"
	"os"
	"testing"

	"github.com/irctrakz/wgslirp/pkg/core"
)

func configurePoolingEvidence(tb testing.TB) bool {
	tb.Helper()
	value := os.Getenv("POOLING")
	if value != "true" && value != "false" {
		tb.Fatal("POOLING must be explicitly true or false")
	}
	enabled := value == "true"
	if err := ConfigurePooling(PoolConfig{Enabled: enabled}); err != nil {
		tb.Fatal(err)
	}
	return enabled
}

func BenchmarkPoolingPackets(b *testing.B) {
	configurePoolingEvidence(b)
	for _, size := range []int{40, 1380, 8192, 20000} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			budget := &resourceBudget{limit: DefaultSocketBufferCap}
			b.ReportAllocs()
			b.SetBytes(int64(size))
			for i := 0; i < b.N; i++ {
				packet := budget.buildPacket(size, true, func() []byte { return bufMaybePool(size) })
				if packet == nil {
					b.Fatal("unexpected admission refusal")
				}
				data := core.BorrowPacketData(packet)
				data[0], data[size-1] = byte(i), byte(i>>8)
				core.ReleasePacket(packet)
			}
			used, _, _, rejected := budget.snapshot()
			if used != 0 || rejected != 0 {
				b.Fatal("unclean benchmark budget")
			}
		})
	}
}

// Saturation is intentional: measure the cost of class rounding under a fixed
// downstream retention budget, then prove every reservation returns on release.
func TestPoolingQueueCapacityEvidence(t *testing.T) {
	enabled := configurePoolingEvidence(t)
	for _, size := range []int{40, 1380} {
		budget := &resourceBudget{limit: 64 * 1024}
		var retained []core.Packet
		for {
			packet := budget.buildPacket(size, true, func() []byte { return bufMaybePool(size) })
			if packet == nil {
				break
			}
			retained = append(retained, packet)
		}
		capacity := size
		if enabled {
			capacity = packetCapacity(size)
		}
		used, peak, _, rejected := budget.snapshot()
		if len(retained) != budget.limit/bufferCharge(capacity) || rejected != 1 {
			t.Fatal("incorrect saturation accounting")
		}
		for _, packet := range retained {
			core.ReleasePacket(packet)
		}
		if remaining, _, _, _ := budget.snapshot(); remaining != 0 {
			t.Fatal("reservation leak")
		}
		packet := budget.buildPacket(size, true, func() []byte { return bufMaybePool(size) })
		if packet == nil {
			t.Fatal("admission did not recover after release")
		}
		core.ReleasePacket(packet)
		t.Logf("POOLING_CAPACITY enabled=%t packet_bytes=%d charged_capacity=%d budget=65536 accepted=%d used=%d peak=%d intentional_refusals=%d recovered=true", enabled, size, capacity, len(retained), used, peak, rejected)
	}
}
