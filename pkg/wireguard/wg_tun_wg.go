package wireguard

import (
	"fmt"
	"github.com/irctrakz/wgslirp/pkg/core"
	"github.com/irctrakz/wgslirp/pkg/logging"
	"golang.zx2c4.com/wireguard/conn"
	wtun "golang.zx2c4.com/wireguard/tun"
	"net"
	"os"
	"sync/atomic"
)

// File returns nil; userspace WGTun does not back with an os.File.
func (t *WGTun) File() *os.File { return nil }

// Read copies queued frames into caller-owned buffers at offset. After the first
// blocking receive, it drains only ready frames, up to the advertised batch cap.
func (t *WGTun) Read(buffs [][]byte, sizes []int, offset int) (int, error) {
	if len(buffs) == 0 || len(sizes) < len(buffs) || offset < 0 || offset >= len(buffs[0]) {
		return 0, fmt.Errorf("invalid TUN read buffers or offset")
	}
	for n := 0; n < min(len(buffs), t.BatchSize()); n++ {
		var frame queuedFrame
		if n == 0 {
			select {
			case <-t.closed:
				return 0, fmt.Errorf("wg tun closed")
			case frame = <-t.outCh:
			}
		} else {
			// Drain only already queued frames; never delay a packet to fill a
			// batch. Close owns frames that this Read has not dequeued.
			select {
			case <-t.closed:
				return n, nil
			case frame = <-t.outCh:
			default:
				return n, nil
			}
		}
		if offset > len(buffs[n]) || len(frame.data) > len(buffs[n])-offset {
			frame.release()
			return n, fmt.Errorf("TUN read buffer too small: need %d bytes", len(frame.data))
		}
		copy(buffs[n][offset:], frame.data)
		sizes[n] = len(frame.data)
		// The destination belongs to WireGuard; release only after copying.
		frame.release()
	}
	return min(len(buffs), t.BatchSize()), nil
}

// Write with offset compatibility for wireguard-go; offset is ignored.
func (t *WGTun) Write(buffs [][]byte, offset int) (int, error) {
	if offset < 0 {
		return 0, fmt.Errorf("invalid TUN write offset")
	}
	select {
	case <-t.closed:
		return 0, fmt.Errorf("wg tun closed")
	default:
	}
	// Attempt every buffer. Return the first failure after processing the batch;
	// only accepted packets contribute to the count and plaintext byte metrics.
	sent := 0
	var firstErr error

	for _, b := range buffs {
		if b == nil {
			continue
		}
		if offset >= len(b) {
			continue
		}
		pkt := b[offset:]
		// Handle non-IPv4 frames (e.g., WireGuard control or IPv6): count as consumed
		// but do not forward to the slirp writer which expects IPv4 packets.
		if !IsIPv4(pkt) {
			logging.Debugf("WGTun received non-IPv4/control frame: len=%d", len(pkt))
			sent++
			continue
		}
		// Optional PCAP tee of plaintext guest->server packet
		pcapWriteIPv4(pkt)
		dst := net.IPv4(pkt[16], pkt[17], pkt[18], pkt[19])
		// Exclusion first: always egress via slirp
		if t.dstInExclude(dst) {
			if err := t.writeToSocket(pkt); err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			sent++
			atomic.AddUint64(&t.metrics.PlaintextFromWG, uint64(len(pkt)))
			continue
		}
		// Overlay re-route: back into WG if destination is inside a peer prefix
		if t.dstInPeerCIDR(dst) {
			if err := t.InjectToPeer(pkt); err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			sent++
			atomic.AddUint64(&t.metrics.PlaintextFromWG, uint64(len(pkt)))
			continue
		}
		// Default: egress via slirp
		if err := t.writeToSocket(pkt); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		sent++
		atomic.AddUint64(&t.metrics.PlaintextFromWG, uint64(len(pkt)))
	}
	return sent, firstErr
}

// Flush is a no-op for userspace WGTun.
func (t *WGTun) Flush() error { return nil }

// Events provides a wtun.Event channel mapped from the internal event stream.
func (t *WGTun) Events() <-chan wtun.Event {
	ch := make(chan wtun.Event, 2)
	go func() {
		for e := range t.events {
			switch e {
			case EventUp:
				ch <- wtun.EventUp
			case EventDown:
				ch <- wtun.EventDown
			default:
			}
		}
		close(ch)
	}()
	return ch
}

// BatchSize matches the standard WireGuard bind's maximum batch. Read drains
// ready frames up to this bound without waiting for a full batch.
func (t *WGTun) BatchSize() int { return conn.IdealBatchSize }

// writeToSocket owns its copy until the synchronous SocketWriter returns.
func (t *WGTun) writeToSocket(data []byte) error {
	release, err := t.buffers.ReservePacketBuffer(len(data))
	if err != nil {
		return err
	}
	defer release()
	copied := make([]byte, len(data))
	copy(copied, data)
	packet := core.NewPooledPacket(copied, nil)
	defer core.ReleasePacket(packet)
	return t.writer.WritePacket(packet)
}
