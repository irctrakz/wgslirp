package wireguard

import (
	"errors"
	"fmt"
	"github.com/irctrakz/wgslirp/pkg/core"
	"github.com/irctrakz/wgslirp/pkg/logging"
	"sync"
	"sync/atomic"
	"time"
)

// WGPacketProcessor forwards synthesized IP packets from the slirp bridges
// to the WG device by enqueueing them on the WGTun's Read queue.
type WGPacketProcessor struct {
	tun          *WGTun
	saturationMu sync.Mutex
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
	// Serialize enqueue outcomes so streak order matches actual injection order.
	p.saturationMu.Lock()
	defer p.saturationMu.Unlock()
	if err := p.tun.InjectToPeer(data); err != nil {
		if errors.Is(err, ErrQueueFull) {
			p.wgQueueFull++
			p.fullStreak++
			if p.fullStreak == 1 {
				p.fullBursts++
			}
			if p.fullStreak > p.maxFullStreak {
				p.maxFullStreak = p.fullStreak
			}
		} else {
			p.fullStreak = 0
		}
		return err
	}
	p.lastSuccessUnixNano = time.Now().UnixNano()
	p.fullStreak = 0

	return nil
}

// Metrics exposes processor-specific counters for inclusion in system metrics.
func (p *WGPacketProcessor) Metrics() map[string]uint64 {
	if p == nil {
		return nil
	}
	p.saturationMu.Lock()
	defer p.saturationMu.Unlock()
	return map[string]uint64{
		"pooled_early_releases": atomic.LoadUint64(&p.pooledEarlyReleases),
		"short_packets":         atomic.LoadUint64(&p.shortPackets),
		"wg_queue_full":         p.wgQueueFull,
		"wg_full_streak_cur":    p.fullStreak,
		"wg_full_streak_max":    p.maxFullStreak,
		"wg_full_bursts":        p.fullBursts,
		"wg_last_success_ns":    uint64(p.lastSuccessUnixNano),
	}
}
