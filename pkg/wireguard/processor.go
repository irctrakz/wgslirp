package wireguard

import (
	"fmt"
	"github.com/irctrakz/wgslirp/pkg/core"
	"github.com/irctrakz/wgslirp/pkg/logging"
	"strings"
	"sync/atomic"
	"time"
)

// WGPacketProcessor forwards synthesized IP packets from the slirp bridges
// to the WG device by enqueueing them on the WGTun's Read queue.
type WGPacketProcessor struct {
	tun *WGTun
	// Debug/guard metric: count cases where a pooled packet arrives already
	// released (buffer returned) before processing, indicating a lifecycle bug.
	pooledEarlyReleases uint64
	// Packets that arrived empty/too short after copy (suspicious)
	shortPackets uint64
	// One-time warning latch for MTU oversize
	mtuWarned uint32
	// Count InjectToPeer queue-full errors observed
	wgQueueFull uint64

	// Additional saturation instrumentation
	lastSuccessUnixNano int64  // last successful InjectToPeer time
	fullStreak          uint64 // current consecutive queue-full streak length
	maxFullStreak       uint64 // max observed consecutive queue-full streak
	fullBursts          uint64 // number of queue-full streak episodes observed
}

// NewWGPacketProcessor creates a processor that writes to the given tun.
func NewWGPacketProcessor(tun *WGTun) core.PacketProcessor {
	return &WGPacketProcessor{tun: tun}
}

// ProcessPacket implements core.PacketProcessor.
func (p *WGPacketProcessor) ProcessPacket(packet core.Packet) error {
	if p == nil || p.tun == nil {
		return fmt.Errorf("WireGuard processor has no TUN")
	}
	if packet == nil {
		return fmt.Errorf("nil packet")
	}
	// Guarded sanity check: detect pooled packet early-release regressions.
	if r, ok := packet.(interface{ Released() bool }); ok && r.Released() {
		atomic.AddUint64(&p.pooledEarlyReleases, 1)
	}
	// InjectToPeer copies synchronously after reservation. Keep the original
	// alive through capture and injection; avoid a second intermediate copy.
	defer core.ReleasePacket(packet)
	data := core.BorrowPacketData(packet)
	// Optional PCAP tee of plaintext server->guest packet
	if IsIPv4(data) {
		pcapWriteIPv4(data)
	}
	if len(data) < 20 { // suspicious: empty or shorter than IPv4 header
		atomic.AddUint64(&p.shortPackets, 1)
	}
	// One-time warning if a synthesized slirp packet exceeds WG plaintext MTU
	if p.tun != nil {
		if m, err := p.tun.MTU(); err == nil && m > 0 && len(data) > m {
			if atomic.CompareAndSwapUint32(&p.mtuWarned, 0, 1) {
				logging.Warnf("slirp packet length %d exceeds WG MTU %d; potential truncation/clamping. Verify MTU alignment.", len(data), m)
			}
		}
	}
	if err := p.tun.InjectToPeer(data); err != nil {
		if strings.Contains(err.Error(), "queue full") {
			// Count event and track consecutive streak
			atomic.AddUint64(&p.wgQueueFull, 1)
			// increment streak; on first in a streak, count a burst
			if atomic.AddUint64(&p.fullStreak, 1) == 1 {
				atomic.AddUint64(&p.fullBursts, 1)
			}
		}
		return err
	}
	// success: reset streak and record last success time
	atomic.StoreInt64(&p.lastSuccessUnixNano, time.Now().UnixNano())
	// best-effort reset of the streak; losing races is fine for metrics
	atomic.StoreUint64(&p.fullStreak, 0)
	// keep maxFullStreak separately
	for {
		cur := atomic.LoadUint64(&p.maxFullStreak)
		streak := atomic.LoadUint64(&p.fullStreak)
		if streak <= cur {
			break
		}
		if atomic.CompareAndSwapUint64(&p.maxFullStreak, cur, streak) {
			break
		}
	}
	return nil
}

// Metrics exposes processor-specific counters for inclusion in system metrics.
func (p *WGPacketProcessor) Metrics() map[string]uint64 {
	if p == nil {
		return nil
	}
	return map[string]uint64{
		"pooled_early_releases": atomic.LoadUint64(&p.pooledEarlyReleases),
		"short_packets":         atomic.LoadUint64(&p.shortPackets),
		"wg_queue_full":         atomic.LoadUint64(&p.wgQueueFull),
		"wg_full_streak_cur":    atomic.LoadUint64(&p.fullStreak),
		"wg_full_streak_max":    atomic.LoadUint64(&p.maxFullStreak),
		"wg_full_bursts":        atomic.LoadUint64(&p.fullBursts),
		"wg_last_success_ns":    uint64(atomic.LoadInt64(&p.lastSuccessUnixNano)),
	}
}
