package main

import (
	"flag"
	"fmt"
	"math/rand"
	"os"
	"sync/atomic"
	"time"

	"github.com/irctrakz/wgslirp/pkg/core"
	"github.com/irctrakz/wgslirp/pkg/logging"
	wg "github.com/irctrakz/wgslirp/pkg/wireguard"
)

// noopWriter implements socket.SocketWriter but drops all writes.
type noopWriter struct{}

func (noopWriter) WritePacket(p core.Packet) error { return nil }

func main() {
	// Flags
	var (
		flows   = flag.Int("flows", 8, "number of simulated flows")
		perFlow = flag.Int("per", 2000, "packets per flow to enqueue")
		pktSize = flag.Int("size", 512, "packet size (bytes)")
		wgCap   = flag.Int("wgcap", 64, "WGTun queue capacity (WG_TUN_QUEUE_CAP)")
		holdMs  = flag.Int("hold", 500, "milliseconds to hold (no drain) to force saturation")
		drainMs = flag.Int("drain", 1000, "milliseconds to drain after hold")
		_       = flag.Int("qcap", 2048, "(removed)")
	)
	flag.Parse()

	// Quieter logs by default
	logging.SetLevel(logging.InfoLevel)

	// Configure tiny WG queue to force saturation quickly
	_ = os.Setenv("WG_TUN_QUEUE_CAP", fmt.Sprintf("%d", *wgCap))

	// Build a WGTun (we only use InjectToPeer path)
	tun := wg.NewWGTun("stress0", 1380, noopWriter{})
	proc := wg.NewWGPacketProcessor(tun)

	// Prepare packet payload
	if *pktSize < 20 {
		*pktSize = 20
	}
	payload := make([]byte, *pktSize)
	rand.Read(payload)

	// Enqueue batches directly into the WireGuard processor to exercise queue admission
	start := time.Now()
	for i := 0; i < *flows; i++ {
		for j := 0; j < *perFlow; j++ {
			b := append([]byte(nil), payload...)
			_ = proc.ProcessPacket(core.NewCopiedPacket(b))
		}
	}
	enqDur := time.Since(start)

	// Hold without draining to force WG InjectToPeer errors
	time.Sleep(time.Duration(*holdMs) * time.Millisecond)

	// Start a drainer that simulates wg device reading from tun
	stopDrain := make(chan struct{})
	go func() {
		buffs := make([][]byte, 1)
		sizes := make([]int, 1)
		buffs[0] = make([]byte, 65536)
		for {
			select {
			case <-stopDrain:
				return
			default:
			}
			// Read one packet if available; Read blocks on t.outCh
			_, _ = tun.Read(buffs, sizes, 0)
		}
	}()

	time.Sleep(time.Duration(*drainMs) * time.Millisecond)
	close(stopDrain)

	// Snapshot metrics
	wgMetrics := map[string]uint64{}
	if m, ok := proc.(interface{ Metrics() map[string]uint64 }); ok {
		wgMetrics = m.Metrics()
	}
	tmetrics := tun.Metrics()

	// Print summary
	fmt.Printf("Enqueue duration: %v\n", enqDur)
	fmt.Printf("WG Proc Metrics: wg_queue_full=%d short_packets=%d early_releases=%d\n",
		wgMetrics["wg_queue_full"], wgMetrics["short_packets"], wgMetrics["pooled_early_releases"])
	fmt.Printf("WGTun: toWG=%d fromWG=%d drops=%d\n",
		atomic.LoadUint64(&tmetrics.PlaintextToWG), atomic.LoadUint64(&tmetrics.PlaintextFromWG), atomic.LoadUint64(&tmetrics.QueueDrops))

	// Basic assertion-like outcomes (non-fatal):
	// - We expect some wg_queue_full > 0 during hold
	// - We expect PlaintextToWG to be > 0 after drain
	// - We expect RequeueDrops == 0 under reasonable settings
	if wgMetrics["wg_queue_full"] == 0 {
		fmt.Println("WARN: did not observe wg_queue_full; increase hold or lower wgcap")
	}
	if atomic.LoadUint64(&tmetrics.PlaintextToWG) == 0 {
		fmt.Println("ERROR: no packets made it to WG after drain; check FlowManager sender or wgcap")
	}
	// FlowManager removed; no requeue drop stats
}
