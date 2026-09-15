package wireguard

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/irctrakz/wgslirp/pkg/socket"
)

// Event is a minimal stand-in for wireguard-go's tun.Event for non-wg builds.
type Event uint32

const (
	EventUp   Event = 1
	EventDown Event = 2
)

// TUNMetrics exposes basic counters for the WG plaintext exchange.
type TUNMetrics struct {
	PlaintextFromWG uint64 // frames received from WG (Write)
	PlaintextToWG   uint64 // frames delivered to WG (Read)
	QueueDrops      uint64 // frames dropped due to full queue
}

// WGTun is a userspace TUN adapter that bridges plaintext IP frames
// between wireguard-go and the SocketInterface (slirp bridges).
type WGTun struct {
	name   string
	mtu    int
	writer socket.SocketWriter

	outCh   chan []byte
	events  chan Event
	closed  chan struct{}
	closeMu sync.Mutex

	metrics TUNMetrics

	// Peers' AllowedIPs (overlay prefixes) for routing decisions
	peerCIDRs []net.IPNet
	peerMu    sync.RWMutex

	// Excluded CIDRs (never re-route to WG even if they match a peer prefix)
	excludeCIDRs []net.IPNet
}

// NewWGTun creates a WGTun with the given name, MTU, and outbound writer.
func NewWGTun(name string, mtu int, writer socket.SocketWriter) *WGTun {
	if mtu <= 0 {
		mtu = 1380
	}
	// Allow tuning of out queue capacity via env.
	qcap := 1024
	if v := strings.TrimSpace(os.Getenv("WG_TUN_QUEUE_CAP")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			qcap = n
		}
	}
	t := &WGTun{
		name:   name,
		mtu:    mtu,
		writer: writer,
		outCh:  make(chan []byte, qcap),
		events: make(chan Event, 2),
		closed: make(chan struct{}),
	}
	// Buffer the event before consumers start. No sender can race with Close.
	t.events <- EventUp
	return t
}

// Name returns the interface name.
func (t *WGTun) Name() (string, error) { return t.name, nil }

// MTU returns the interface MTU.
func (t *WGTun) MTU() (int, error) { return t.mtu, nil }

// Close shuts down the device and emits a Down event.
func (t *WGTun) Close() error {
	t.closeMu.Lock()
	select {
	case <-t.closed:
		t.closeMu.Unlock()
		return nil
	default:
	}
	close(t.closed)
	select {
	case t.events <- EventDown:
	default:
	}
	close(t.events)
	for {
		select {
		case <-t.outCh:
		default:
			t.closeMu.Unlock()
			return nil
		}
	}
}

// InjectToPeer enqueues a plaintext IP frame to be read by the WG device.
func (t *WGTun) InjectToPeer(b []byte) error {
	t.closeMu.Lock()
	defer t.closeMu.Unlock()
	select {
	case <-t.closed:
		return fmt.Errorf("wg tun closed")
	default:
	}
	cp := append([]byte(nil), b...)
	select {
	case t.outCh <- cp:
		atomic.AddUint64(&t.metrics.PlaintextToWG, uint64(len(cp)))
		return nil
	default:
		atomic.AddUint64(&t.metrics.QueueDrops, 1)
		return fmt.Errorf("wg tun queue full")
	}
}

// Metrics returns a snapshot of counters.
func (t *WGTun) Metrics() TUNMetrics {
	return TUNMetrics{
		PlaintextFromWG: atomic.LoadUint64(&t.metrics.PlaintextFromWG),
		PlaintextToWG:   atomic.LoadUint64(&t.metrics.PlaintextToWG),
		QueueDrops:      atomic.LoadUint64(&t.metrics.QueueDrops),
	}
}

// SetPeerCIDRs updates the list of overlay prefixes (peers' AllowedIPs) used
// to decide whether a client packet should be re-routed back into WireGuard
// (to another peer) instead of egressing via slirp. Accepts CIDRs as strings.
func (t *WGTun) SetPeerCIDRs(cidrs []string) error {
	var nets []net.IPNet
	for _, c := range cidrs {
		_, ipn, err := net.ParseCIDR(strings.TrimSpace(c))
		if err != nil {
			return err
		}
		// Ignore default routes like 0.0.0.0/0 or ::/0 to avoid routing all traffic back into WG
		ones, bits := ipn.Mask.Size()
		if ones == 0 && bits > 0 {
			continue
		}
		nets = append(nets, *ipn)
	}
	t.peerMu.Lock()
	t.peerCIDRs = nets
	t.peerMu.Unlock()
	return nil
}

// SetExcludeCIDRs updates the exclusion list. Packets to these prefixes will
// always egress via slirp, not re-routed back to WG.
func (t *WGTun) SetExcludeCIDRs(cidrs []string) error {
	var nets []net.IPNet
	for _, c := range cidrs {
		_, ipn, err := net.ParseCIDR(strings.TrimSpace(c))
		if err != nil {
			return err
		}
		// Ignore /0
		ones, bits := ipn.Mask.Size()
		if ones == 0 && bits > 0 {
			continue
		}
		nets = append(nets, *ipn)
	}
	t.peerMu.Lock()
	t.excludeCIDRs = nets
	t.peerMu.Unlock()
	return nil
}

func (t *WGTun) dstInExclude(dst net.IP) bool {
	t.peerMu.RLock()
	defer t.peerMu.RUnlock()
	for _, n := range t.excludeCIDRs {
		if n.Contains(dst) {
			return true
		}
	}
	return false
}

func (t *WGTun) dstInPeerCIDR(dst net.IP) bool {
	t.peerMu.RLock()
	defer t.peerMu.RUnlock()
	for _, n := range t.peerCIDRs {
		if n.Contains(dst) {
			return true
		}
	}
	return false
}

// IsIPv4 reports whether b appears to be an IPv4 packet.
func IsIPv4(b []byte) bool { return len(b) >= 20 && b[0]>>4 == 4 }

// MakeIPv4 builds a minimal IPv4 packet (for tests) with src/dst and payload.
func MakeIPv4(src, dst net.IP, proto byte, payload []byte) []byte {
	ihl := 20
	total := ihl + len(payload)
	p := make([]byte, total)
	p[0] = 0x45
	p[1] = 0x00
	p[2] = byte(total >> 8)
	p[3] = byte(total & 0xff)
	p[8] = 64
	p[9] = proto
	copy(p[12:16], src.To4())
	copy(p[16:20], dst.To4())
	var sum uint32
	for i := 0; i < 20; i += 2 {
		if i == 10 {
			continue
		}
		sum += uint32(p[i])<<8 | uint32(p[i+1])
	}
	for (sum >> 16) != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	cs := ^uint16(sum)
	p[10] = byte(cs >> 8)
	p[11] = byte(cs)
	copy(p[ihl:], payload)
	return p
}
