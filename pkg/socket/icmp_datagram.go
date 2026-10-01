package socket

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/irctrakz/wgslirp/pkg/core"
	"github.com/irctrakz/wgslirp/pkg/logging"
)

const (
	maxPendingICMPEcho = 1024
	icmpEchoLifetime   = 5 * time.Second
)

// ErrICMPEchoLimit is a transient admission failure; existing requests survive.
var ErrICMPEchoLimit = errors.New("pending ICMP echo limit reached")

type pendingDgramEcho struct {
	id, seq     uint16
	guest, peer [4]byte
	payload     [sha256.Size]byte
	expiry      time.Time
	release     func()
}

// icmpDatagram owns ping-socket request correlation. The kernel replaces the
// echo ID, so we allocate a distinct wire sequence for each live request. Two
// guests may then ping the same destination with identical IDs and payloads,
// and reordered replies still go to the right guest. Payloads are not retained.
type icmpDatagram struct {
	conn    net.PacketConn
	mu      sync.Mutex // pending, next and serialized write deadlines
	pending map[uint16]pendingDgramEcho
	next    uint16
}

func newICMPDatagram(conn net.PacketConn) *icmpDatagram {
	return &icmpDatagram{conn: conn, pending: make(map[uint16]pendingDgramEcho)}
}

func (d *icmpDatagram) expireLocked(now time.Time) {
	for seq, p := range d.pending {
		if !p.expiry.After(now) {
			delete(d.pending, seq)
			p.release()
		}
	}
}

func (d *icmpDatagram) clear() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for seq, p := range d.pending {
		delete(d.pending, seq)
		p.release()
	}
}

func (d *icmpDatagram) send(s *SocketInterface, guest, peer net.IP, body []byte) error {
	// Ping sockets support only valid IPv4 echo requests, not arbitrary ICMP.
	if len(body) < 8 || body[0] != 8 || body[1] != 0 {
		return nil
	}
	if len(body) > 65515 || guest.To4() == nil || peer.To4() == nil || calculateChecksum(body) != 0 {
		return fmt.Errorf("icmp: invalid datagram echo request")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.expireLocked(time.Now())
	if len(d.pending) >= maxPendingICMPEcho {
		s.admission.icmpEchoes.Add(1)
		return ErrICMPEchoLimit
	}
	// Account fixed correlation metadata plus the shared entry allowance before
	// allocation; the temporary wire copy has its own packet reservation.
	release, err := s.ReservePacketBuffer(64)
	if err != nil {
		return err
	}
	packet := s.buffers().buildPacket(len(body), false, func() []byte {
		out := make([]byte, len(body))
		copy(out, body)
		return out
	})
	if packet == nil {
		release()
		return ErrBufferLimit
	}
	defer core.ReleasePacket(packet)
	for {
		d.next++
		if _, exists := d.pending[d.next]; !exists {
			break
		}
	}
	seq := d.next
	p := pendingDgramEcho{
		id: binary.BigEndian.Uint16(body[4:6]), seq: binary.BigEndian.Uint16(body[6:8]),
		payload: sha256.Sum256(body[8:]), expiry: time.Now().Add(icmpEchoLifetime), release: release,
	}
	copy(p.guest[:], guest.To4())
	copy(p.peer[:], peer.To4())
	wire := core.BorrowPacketData(packet)
	binary.BigEndian.PutUint16(wire[6:8], seq)
	wire[2], wire[3] = 0, 0
	binary.BigEndian.PutUint16(wire[2:4], calculateChecksum(wire))
	if err := d.conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		release()
		return err
	}
	// Hold mu through the send so a reply cannot consume an uncommitted entry.
	d.pending[seq] = p
	n, err := d.conn.WriteTo(wire, &net.UDPAddr{IP: peer})
	if err != nil || n != len(wire) {
		delete(d.pending, seq)
		release()
		if err == nil {
			err = fmt.Errorf("short ICMP datagram write: %d/%d", n, len(wire))
		}
		return fmt.Errorf("icmp: send datagram echo: %w", err)
	}
	return nil
}

// processReply borrows the listener's accounted receive buffer and rewrites it
// only after matching the source, wire sequence and payload. Reply construction
// and delivery use the same shared budget/ownership contract as raw ICMP.
func (d *icmpDatagram) processReply(s *SocketInterface, body []byte, peer net.IP) error {
	if len(body) < 8 || body[0] != 0 || body[1] != 0 || peer.To4() == nil || calculateChecksum(body) != 0 {
		return fmt.Errorf("icmp: invalid datagram echo reply")
	}
	seq := binary.BigEndian.Uint16(body[6:8])
	var peer4 [4]byte
	copy(peer4[:], peer.To4())
	d.mu.Lock()
	d.expireLocked(time.Now())
	p, ok := d.pending[seq]
	if !ok || p.peer != peer4 || p.payload != sha256.Sum256(body[8:]) {
		d.mu.Unlock()
		return fmt.Errorf("icmp: unmatched datagram echo reply")
	}
	delete(d.pending, seq)
	d.mu.Unlock()
	defer p.release()
	binary.BigEndian.PutUint16(body[4:6], p.id)
	binary.BigEndian.PutUint16(body[6:8], p.seq)
	body[2], body[3] = 0, 0
	binary.BigEndian.PutUint16(body[2:4], calculateChecksum(body))
	return s.processICMPReply(body, peer, net.IP(p.guest[:]))
}

func (d *icmpDatagram) listen(s *SocketInterface, releaseRead func()) {
	defer s.wg.Done()
	defer releaseRead()
	defer func() {
		_ = d.conn.Close()
		d.clear()
	}()
	buf := make([]byte, 65536)
	for {
		select {
		case <-s.stopCh:
			return
		default:
		}
		if err := d.conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			if !errors.Is(err, net.ErrClosed) {
				atomic.AddUint64(&s.metrics.Errors, 1)
				logging.Warnf("ICMP datagram reader stopped: %v", err)
			}
			return
		}
		n, from, err := d.conn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				d.mu.Lock()
				d.expireLocked(time.Now())
				d.mu.Unlock()
				continue
			}
			atomic.AddUint64(&s.metrics.Errors, 1)
			if s.failureLog.Allow(time.Now()) {
				logging.Warnf("ICMP datagram read failed: %v", err)
			}
			select {
			case <-s.stopCh:
				return
			case <-time.After(100 * time.Millisecond):
			}
			continue
		}
		peer, ok := from.(*net.UDPAddr)
		if !ok {
			continue
		}
		if err := d.processReply(s, buf[:n], peer.IP); err != nil {
			atomic.AddUint64(&s.metrics.Errors, 1)
			logging.Debugf("ICMP datagram reply dropped: %v", err)
		}
	}
}
