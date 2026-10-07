//go:build integration && mixed && wan && pooling && linux

package wireguard

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/irctrakz/wgslirp/pkg/socket"
)

// Run only this test in a fresh process: packet pooling is a frozen startup policy.
// Ordinary timings include the independent encrypted guest and fixture, not compilation.
func TestPoolingEvidence(t *testing.T) {
	value := os.Getenv("POOLING")
	if value != "true" && value != "false" {
		t.Fatal("POOLING must be explicitly true or false for the comparison")
	}
	if err := socket.ConfigurePooling(socket.PoolConfig{Enabled: value == "true"}); err != nil {
		t.Fatal(err)
	}
	workload := os.Getenv("POOLING_WORKLOAD")
	var run func(*testing.T)
	switch workload {
	case "mixed":
		run = TestEncryptedMixed
	case "wan":
		run = TestEncryptedWANRecovery
	case "sustained-mixed":
		run = testEncryptedPoolingSustained
	default:
		t.Fatal("POOLING_WORKLOAD must be mixed, wan or sustained-mixed")
	}
	readRSS := func() uint64 {
		data, err := os.ReadFile("/proc/self/statm")
		if err != nil {
			return 0
		}
		fields := strings.Fields(string(data))
		if len(fields) < 2 {
			return 0
		}
		pages, _ := strconv.ParseUint(fields[1], 10, 64)
		return pages * uint64(os.Getpagesize())
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	var usageBefore, usageAfter syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usageBefore); err != nil {
		t.Fatal(err)
	}
	stop, sampled := make(chan struct{}), make(chan struct{})
	var heapPeak, rssPeak uint64
	go func() {
		defer close(sampled)
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			heapPeak = max(heapPeak, m.HeapAlloc)
			rssPeak = max(rssPeak, readRSS())
			select {
			case <-stop:
				return
			case <-ticker.C:
			}
		}
	}()
	started := time.Now()
	ok := t.Run(workload, run) // Fixture cleanup completes before final measurements.
	close(stop)
	<-sampled
	runtime.ReadMemStats(&after)
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usageAfter); err != nil {
		t.Fatal(err)
	}
	if rssPeak == 0 {
		t.Fatal("RSS sampling unavailable")
	}
	cpuUS := func(u syscall.Rusage) int64 { return u.Utime.Nano()/1000 + u.Stime.Nano()/1000 }
	t.Logf("POOLING_RESULT enabled=%s workload=%s elapsed_ms=%d cpu_us=%d allocated_bytes=%d allocations=%d gc_cycles=%d gc_pause_ns=%d heap_peak=%d rss_peak=%d heap_final=%d rss_final=%d", value, workload, time.Since(started).Milliseconds(), cpuUS(usageAfter)-cpuUS(usageBefore), after.TotalAlloc-before.TotalAlloc, after.Mallocs-before.Mallocs, after.NumGC-before.NumGC, after.PauseTotalNs-before.PauseTotalNs, heapPeak, rssPeak, after.HeapAlloc, readRSS())
	if ok {
		t.Log("POOLING_ACCEPTED")
	}
}

func testEncryptedPoolingSustained(t *testing.T) {
	baseline := runtime.NumGoroutine()
	repeats := 4096 // Two streams, each 256 MiB in each direction, with bounded scratch.
	if os.Getenv("POOLING_EVIDENCE_RACE") == "true" {
		repeats = 512
	} // Correctness only: 32 MiB per stream.
	ok := t.Run("traffic", func(t *testing.T) {
		runEncryptedMixedProfile(t, mixedTestLink, mixedProfile{
			shortRounds: 2048, udpRounds: 16384, bulkBytes: 64 << 10, bulkRepeats: repeats,
			shortPause: 25 * time.Millisecond, udpPause: 5 * time.Millisecond, deadline: 90 * time.Second, sustained: true,
		})
	})
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > baseline+4 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if runtime.NumGoroutine() > baseline+4 {
		t.Fatal("workers survived sustained mixed cleanup")
	}
	if ok {
		t.Log("SUSTAINED_POOLING_ACCEPTED")
	}
}
