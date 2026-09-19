//go:build integration && performance && linux

package socket

import (
	"bytes"
	"encoding/json"
	"fmt"
	"runtime"
	"sort"
	"sync"
	"testing"
	"time"
)

// Fixed work, bounded peers and deadlines; no live Internet, forced GC or adaptive
// benchmark iteration count. Reuse the byte-checking production bridge fixture.
func TestTransportPerformance(t *testing.T) {
	for _, tcp := range []bool{true, false} {
		for sample := 0; sample < 5; sample++ {
			t.Run(fmt.Sprintf("tcp=%v/sample=%d", tcp, sample), func(t *testing.T) {
				original := poolPolicy.Load()
				poolPolicy.Store(&PoolConfig{})
				t.Cleanup(func() { poolPolicy.Store(original) })
				tcpPort, udpPort, stopServers := workloadServers(t)
				cfg := DefaultConfig()
				cfg.Protocol = "ip4:tcp"
				cfg.TCPAckDelayMs = 0
				s := NewSocketInterface(cfg)
				sink := &workloadSink{s, make(map[uint16]chan []byte)}
				guests := make([]*workloadGuest, 8)
				for i := range guests {
					remote := udpPort
					if tcp {
						remote = tcpPort
					}
					g := &workloadGuest{s: s, replies: make(chan []byte, 16), port: uint16(40000 + i), remote: remote, tcp: tcp, seq: 1000}
					guests[i] = g
					sink.replies[g.port] = g.replies
				}
				processor, err := NewSocketPacketProcessorWithConfig(sink, ProcessorConfig{Workers: 4, QueueCapacity: 512})
				if err != nil {
					t.Fatal(err)
				}
				if err := processor.Start(); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { s.Stop(); processor.Stop() })
				s.SetPacketProcessor(processor)
				if err := s.Start(); err != nil {
					t.Fatal(err)
				}
				payload := bytes.Repeat([]byte{0x5a}, 1024)
				dial := make([]int64, 0, 8)
				for _, g := range guests {
					if tcp {
						start := time.Now()
						if err := g.handshake(); err != nil {
							t.Fatal(err)
						}
						dial = append(dial, time.Since(start).Nanoseconds())
					}
					for i := 0; i < 16; i++ {
						if err := g.exchange(payload); err != nil {
							t.Fatal(err)
						}
					}
				}
				var before, after runtime.MemStats
				runtime.ReadMemStats(&before)
				samples := make([][]int64, len(guests))
				failures := make(chan error, len(guests))
				var workers sync.WaitGroup
				start := time.Now()
				for index, g := range guests {
					workers.Add(1)
					go func(index int, g *workloadGuest) {
						defer workers.Done()
						timings := make([]int64, 0, 256)
						for i := 0; i < 256; i++ {
							one := time.Now()
							if err := g.exchange(payload); err != nil {
								failures <- err
								return
							}
							timings = append(timings, time.Since(one).Nanoseconds())
						}
						samples[index] = timings
					}(index, g)
				}
				workers.Wait()
				elapsed := time.Since(start)
				close(failures)
				for err := range failures {
					t.Fatal(err)
				}
				runtime.ReadMemStats(&after)
				heap, rss := storageMemory()
				used, peak, limit, _ := s.buffers().snapshot()
				if used > limit || peak > limit {
					t.Fatal("reservation limit exceeded")
				}
				latencies := make([]int64, 0, 2048)
				for _, values := range samples {
					latencies = append(latencies, values...)
				}
				sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
				sort.Slice(dial, func(i, j int) bool { return dial[i] < dial[j] })
				dialP95 := int64(0)
				if len(dial) > 0 {
					dialP95 = dial[len(dial)-1]
				}
				if err := s.Stop(); err != nil {
					t.Fatal(err)
				}
				processor.Stop()
				stopServers()
				assertBudget(t, s.buffers(), 0)
				result := map[string]any{"tcp": tcp, "sample": sample, "exchanges": 2048, "payload_bytes": 2097152,
					"mb_s": 2.097152 / elapsed.Seconds(), "p50_ns": latencies[len(latencies)/2], "p95_ns": latencies[(len(latencies)*95-1)/100],
					"dial_p95_ns": dialP95, "allocs_op": float64(after.Mallocs-before.Mallocs) / 2048, "bytes_op": float64(after.TotalAlloc-before.TotalAlloc) / 2048,
					"heap_bytes": heap, "rss": rss, "reservation_peak": peak, "final_reservations": 0}
				data, err := json.Marshal(result)
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("PERF_RESULT %s", data)
			})
		}
	}
}
