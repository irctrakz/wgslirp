//go:build integration && soak && linux

package wireguard

import (
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This is a separate acceptance profile, not a relaxation of the original
// 64 MiB/30-second guard. Keep runtime GC policy and the process memory limit
// unchanged. Run in a fresh process so earlier devices cannot skew the baseline.
func TestEncryptedWANMemoryAcceptance(t *testing.T) {
	workers := runtime.NumGoroutine()
	var acceptance encryptedMemoryAcceptance
	if !t.Run("traffic", func(t *testing.T) { runEncryptedWAN(t, false, &acceptance) }) {
		return
	}
	// Child cleanup closes both devices, the relay and peers. No forced collection:
	// idle RSS need not return to cold-process RSS, but it must remain bounded.
	for i := 0; i < 5; i++ {
		time.Sleep(time.Second)
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		acceptance.checkBounds(t, m)
		encryptedMemorySample(t, "acceptance_drained")
	}
	if n := runtime.NumGoroutine(); n > workers+4 {
		t.Fatalf("workers survived teardown: before=%d after=%d", workers, n)
	}
	t.Logf("MEMORY_ACCEPTED rounds=%d natural_gc=%d first_gc_round=%d heap_peak=%d rss_peak=%d initialized_heap=%d", acceptance.rounds, acceptance.lastGC-acceptance.initial.NumGC, acceptance.firstGCRound, acceptance.heapPeak, acceptance.rssPeak, acceptance.initial.HeapAlloc)
}

type encryptedMemoryAcceptance struct {
	initial              runtime.MemStats
	lastGC               uint32
	firstGCRound, rounds int
	heapPeak, rssPeak    uint64
}

func (a *encryptedMemoryAcceptance) initialize(t *testing.T, m runtime.MemStats) {
	t.Helper()
	a.initial, a.lastGC = m, m.NumGC
	if m.HeapAlloc > 64<<20 {
		t.Fatalf("initialized heap exceeds profile: %d", m.HeapAlloc)
	}
	a.checkBounds(t, m)
	encryptedMemorySample(t, "acceptance_initialized")
}

func (a *encryptedMemoryAcceptance) checkBounds(t *testing.T, m runtime.MemStats) {
	t.Helper()
	rss, workers := encryptedRSS(t), runtime.NumGoroutine()
	if m.HeapAlloc > a.heapPeak {
		a.heapPeak = m.HeapAlloc
	}
	if rss > a.rssPeak {
		a.rssPeak = rss
	}
	if m.HeapAlloc > 128<<20 || rss > 256<<20 || workers > 256 {
		t.Fatalf("acceptance bound: heap=%d rss=%d goroutines=%d", m.HeapAlloc, rss, workers)
	}
	if m.NumForcedGC != a.initial.NumForcedGC {
		t.Fatal("forced GC invalidates natural memory acceptance")
	}
}

func (a *encryptedMemoryAcceptance) observe(t *testing.T, m runtime.MemStats, round int) {
	t.Helper()
	a.checkBounds(t, m)
	if m.NumGC != a.lastGC {
		// Sampling occurs once per completed round. Include the small allocation
		// allowance since collection; do not claim this is exact live-heap size.
		if m.HeapAlloc > a.initial.HeapAlloc+8<<20 {
			t.Fatalf("post-GC heap drift: initialized=%d sampled=%d round=%d", a.initial.HeapAlloc, m.HeapAlloc, round)
		}
		if a.firstGCRound == 0 {
			a.firstGCRound = round
		}
		a.lastGC = m.NumGC
		encryptedMemorySample(t, "acceptance_natural_gc")
	}
	if round%10 == 0 {
		encryptedMemorySample(t, "acceptance_traffic")
	}
}

func (a *encryptedMemoryAcceptance) finish(t *testing.T, rounds int) {
	t.Helper()
	a.rounds = rounds
	if rounds < 64 || a.firstGCRound == 0 || rounds-a.firstGCRound < 8 {
		t.Fatalf("insufficient natural-GC evidence: rounds=%d first_gc_round=%d", rounds, a.firstGCRound)
	}
}

func encryptedRSS(t *testing.T) uint64 {
	t.Helper()
	data, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		t.Fatal("missing process RSS")
	}
	pages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return pages * uint64(os.Getpagesize())
}

func encryptedMemorySample(t *testing.T, phase string) {
	t.Helper()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	t.Logf("MEMORY_SAMPLE phase=%s heap=%d heap_inuse=%d heap_idle=%d heap_released=%d next_gc=%d total_alloc=%d gc=%d forced_gc=%d rss=%d goroutines=%d gomaxprocs=%d", phase, m.HeapAlloc, m.HeapInuse, m.HeapIdle, m.HeapReleased, m.NextGC, m.TotalAlloc, m.NumGC, m.NumForcedGC, encryptedRSS(t), runtime.NumGoroutine(), runtime.GOMAXPROCS(0))
}

// Bounded, sampled allocation attribution. These are raw sampled bytes, not
// scaled process totals. GC can delay profile visibility by up to two cycles.
// Keep only function names, never packet contents, device state or keys.
func encryptedAllocationProfile(t *testing.T) {
	t.Helper()
	n, _ := runtime.MemProfile(nil, true)
	if n > 4096 {
		t.Fatal("allocation profile record bound")
	}
	records := make([]runtime.MemProfileRecord, n+64)
	n, ok := runtime.MemProfile(records, true)
	if !ok {
		t.Fatal("allocation profile grew beyond bounded snapshot")
	}
	records = records[:n]
	sort.Slice(records, func(i, j int) bool { return records[i].AllocBytes > records[j].AllocBytes })
	if len(records) > 8 {
		records = records[:8]
	}
	for _, r := range records {
		frames := runtime.CallersFrames(r.Stack())
		var names []string
		for i := 0; i < 6; i++ {
			f, more := frames.Next()
			names = append(names, f.Function)
			if !more {
				break
			}
		}
		t.Logf("MEMORY_PROFILE sampled_alloc=%d sampled_inuse=%d stack=%s", r.AllocBytes, r.InUseBytes(), strings.Join(names, ";"))
	}
}
