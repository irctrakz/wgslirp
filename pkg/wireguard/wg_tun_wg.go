package wireguard

import (
	"fmt"
	"github.com/irctrakz/wgslirp/pkg/core"
	"github.com/irctrakz/wgslirp/pkg/logging"
	wtun "golang.zx2c4.com/wireguard/tun"
	"net"
	"os"
	"sync/atomic"
)

// File returns nil; userspace WGTun does not back with an os.File.
func (t *WGTun) File() *os.File { return nil }

// Read with offset compatibility for wireguard-go; offset is ignored.
func (t *WGTun) Read(buffs [][]byte, sizes []int, offset int) (int, error) {
	if len(buffs) == 0 || len(sizes) == 0 || offset < 0 || offset >= len(buffs[0]) {
		return 0, fmt.Errorf("invalid TUN read buffers or offset")
	}
	select {
	case <-t.closed:
		return 0, fmt.Errorf("wg tun closed")
	case frame := <-t.outCh:
		// A frame already dequeued during Close remains owned by this Read.
		// Release on every completion path, including an undersized destination.
		defer frame.release()
		pkt := frame.data
		if len(buffs) == 0 {
			return 0, nil
		}
		b := buffs[0]
		if offset >= len(b) {
			return 0, fmt.Errorf("offset beyond buffer")
		}
		dst := b[offset:]
		n := len(pkt)
		if n > len(dst) {
			return 0, fmt.Errorf("TUN read buffer too small: need %d bytes", n)
		}
		copy(dst, pkt[:n])
		if sizes != nil && len(sizes) > 0 {
			sizes[0] = n
		}
		return 1, nil
	}
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

// BatchSize returns 1 to indicate minimal batch support.
func (t *WGTun) BatchSize() int { return 1 }

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
