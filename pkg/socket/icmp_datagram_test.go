package socket

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/irctrakz/wgslirp/internal/packetwire"
	"github.com/irctrakz/wgslirp/pkg/core"
)

type fakePingConn struct {
	net.PacketConn
	writes      [][]byte // send serializes access; inspected after the send returns
	err         error
	short       bool
	deadlineErr error
	entered     chan struct{}
	closed      chan struct{}
	once        sync.Once
}

func (c *fakePingConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	if c.entered != nil {
		close(c.entered)
		<-c.closed
		return 0, net.ErrClosed
	}
	if c.err != nil {
		return 0, c.err
	}
	if c.short {
		return len(b) - 1, nil
	}
	c.writes = append(c.writes, append([]byte(nil), b...))
	return len(b), nil
}
func (c *fakePingConn) SetWriteDeadline(time.Time) error { return c.deadlineErr }
func (c *fakePingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakePingConn) ReadFrom([]byte) (int, net.Addr, error) {
	<-c.closed
	return 0, nil, net.ErrClosed
}
func (c *fakePingConn) Close() error {
	c.once.Do(func() {
		if c.closed != nil {
			close(c.closed)
		}
	})
	return nil
}

func echoBody(id, seq uint16) []byte {
	b := []byte{8, 0, 0, 0, 0, 0, 0, 0, 'p', 'i', 'n', 'g'}
	binary.BigEndian.PutUint16(b[4:6], id)
	binary.BigEndian.PutUint16(b[6:8], seq)
	fixEchoChecksum(b)
	return b
}
func fixEchoChecksum(b []byte) {
	b[2], b[3] = 0, 0
	binary.BigEndian.PutUint16(b[2:4], calculateChecksum(b))
}
func echoReply(wire []byte) []byte {
	b := append([]byte(nil), wire...)
	b[0] = 0
	binary.BigEndian.PutUint16(b[4:6], 0xbeef) // kernel-selected ping socket ID
	fixEchoChecksum(b)
	return b
}
func buildIPv4ICMP(src, dst net.IP, body []byte) []byte {
	b := make([]byte, 20+len(body))
	var source, destination [4]byte
	copy(source[:], src.To4())
	copy(destination[:], dst.To4())
	packetwire.IPv4Header(b, source, destination, 1, 0, 64, 0, 0)
	copy(b[20:], body)
	return b
}

func TestICMPDatagramCorrelation(t *testing.T) {
	s := NewSocketInterface(DefaultConfig())
	capture := &captureProcessor{}
	s.processor = capture
	c := &fakePingConn{}
	d := newICMPDatagram(c)
	t.Cleanup(d.clear)
	peer := net.IPv4(127, 0, 0, 1)
	body := echoBody(0x1234, 7)
	original := append([]byte(nil), body...)
	for _, guest := range []net.IP{net.IPv4(10, 0, 0, 2), net.IPv4(10, 0, 0, 3)} {
		if err := d.send(s, guest, peer, body); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(body, original) {
		t.Fatal("mutated borrowed request")
	}
	if bytes.Equal(c.writes[0], c.writes[1]) {
		t.Fatal("ambiguous wire identity")
	}
	for _, wire := range c.writes {
		if calculateChecksum(wire) != 0 {
			t.Fatal("invalid request checksum")
		}
	}
	// A forged source or payload must not consume another request's identity.
	if err := d.processReply(s, echoReply(c.writes[0]), net.IPv4(127, 0, 0, 2)); err == nil {
		t.Fatal("accepted wrong peer")
	}
	bad := echoReply(c.writes[0])
	bad[8]++
	fixEchoChecksum(bad)
	if err := d.processReply(s, bad, peer); err == nil {
		t.Fatal("accepted wrong payload")
	}
	for i := 1; i >= 0; i-- {
		if err := d.processReply(s, echoReply(c.writes[i]), peer); err != nil {
			t.Fatal(err)
		}
	}
	packets := capture.snapshot()
	if len(packets) != 2 {
		t.Fatalf("replies=%d", len(packets))
	}
	for i, p := range packets {
		if !net.IP(p[12:16]).Equal(peer) || !net.IP(p[16:20]).Equal(net.IPv4(10, 0, 0, byte(3-i))) {
			t.Fatalf("misrouted reply: %v -> %v", p[12:16], p[16:20])
		}
		if calculateChecksum(p[:20]) != 0 || calculateChecksum(p[20:]) != 0 || binary.BigEndian.Uint16(p[24:26]) != 0x1234 || binary.BigEndian.Uint16(p[26:28]) != 7 || !bytes.Equal(p[28:], body[8:]) {
			t.Fatalf("identity, checksum or payload changed: %x", p)
		}
	}
	if err := d.processReply(s, echoReply(c.writes[0]), peer); err == nil {
		t.Fatal("accepted duplicate reply")
	}
	assertBudget(t, s.buffers(), 0)
}

func TestICMPDatagramLimitsExpiryAndWrap(t *testing.T) {
	s := NewSocketInterface(DefaultConfig())
	d := newICMPDatagram(&fakePingConn{})
	t.Cleanup(d.clear)
	guest, peer := net.IPv4(10, 0, 0, 2), net.IPv4(127, 0, 0, 1)
	for i := 0; i < maxPendingICMPEcho; i++ {
		if err := d.send(s, guest, peer, echoBody(1, 1)); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.send(s, guest, peer, echoBody(1, 1)); !errors.Is(err, ErrICMPEchoLimit) {
		t.Fatal(err)
	}
	assertAdmission(t, s, map[string]uint64{"icmp_echo_limit": 1})
	assertBudget(t, s.buffers(), uint64(maxPendingICMPEcho*bufferCharge(64)))
	for seq, p := range d.pending {
		p.expiry = time.Now().Add(-time.Second)
		d.pending[seq] = p
	}
	if err := d.send(s, guest, peer, echoBody(1, 1)); err != nil {
		t.Fatal(err)
	}
	assertBudget(t, s.buffers(), uint64(bufferCharge(64)))
	d.clear()
	// Sequence wrap must skip an occupied wire sequence.
	d.next = 0
	if err := d.send(s, guest, peer, echoBody(1, 1)); err != nil {
		t.Fatal(err)
	}
	d.next = 65535
	for i := 0; i < 2; i++ {
		if err := d.send(s, guest, peer, echoBody(2, 2)); err != nil {
			t.Fatal(err)
		}
	}
	if len(d.pending) != 3 {
		t.Fatal("overwrote live correlation")
	}
	d.clear()
	d.clear()
	assertBudget(t, s.buffers(), 0)
}

func TestICMPDatagramFailureAccounting(t *testing.T) {
	for _, mode := range []string{"write", "short", "deadline", "entry-budget", "wire-budget", "reply-budget", "delivery"} {
		t.Run(mode, func(t *testing.T) {
			s := NewSocketInterface(DefaultConfig())
			c := &fakePingConn{}
			s.processor = &captureProcessor{}
			switch mode {
			case "write":
				c.err = errors.New("injected send failure")
			case "short":
				c.short = true
			case "deadline":
				c.deadlineErr = errors.New("injected deadline failure")
			case "entry-budget":
				s.config.SocketBufferCapBytes = 1
			case "wire-budget":
				s.config.SocketBufferCapBytes = bufferCharge(64)
			case "delivery":
				s.processor = packetConsumer(func(core.Packet) error { return errors.New("injected delivery failure") })
			}
			d := newICMPDatagram(c)
			t.Cleanup(d.clear)
			peer := net.IPv4(127, 0, 0, 1)
			err := d.send(s, net.IPv4(10, 0, 0, 2), peer, echoBody(1, 2))
			if mode == "reply-budget" || mode == "delivery" {
				if err != nil {
					t.Fatal(err)
				}
				held := 0
				if mode == "reply-budget" {
					used, _, limit, _ := s.buffers().snapshot()
					held = int(limit - used)
					if !s.buffers().acquire(held) {
						t.Fatal("fixture budget")
					}
				}
				err = d.processReply(s, echoReply(c.writes[0]), peer)
				if held > 0 {
					s.buffers().release(held)
				}
			}
			if err == nil {
				t.Fatal("negative control accepted")
			}
			if len(d.pending) != 0 {
				t.Fatal("failed operation retained identity")
			}
			assertBudget(t, s.buffers(), 0)
		})
	}
}

func TestICMPDatagramStopInterruptsIO(t *testing.T) {
	s := NewSocketInterface(DefaultConfig())
	c := &fakePingConn{entered: make(chan struct{}), closed: make(chan struct{})}
	s.dgram = newICMPDatagram(c)
	s.icmp = newICMPBridge(s)
	s.running = true
	release, err := s.ReservePacketBuffer(65536)
	if err != nil {
		t.Fatal(err)
	}
	s.wg.Add(1)
	go s.dgram.listen(s, release)
	t.Cleanup(func() { _ = s.Stop() })
	p := core.NewCopiedPacket(buildIPv4ICMP(net.IPv4(10, 0, 0, 2), net.IPv4(127, 0, 0, 1), echoBody(1, 2)))
	defer core.ReleasePacket(p)
	done := make(chan error, 1)
	go func() { done <- s.WritePacket(p) }()
	select {
	case <-c.entered:
	case <-time.After(time.Second):
		t.Fatal("send not entered")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.StopContext(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil {
		t.Fatal("blocked send survived close")
	}
	if err := s.WritePacket(p); err == nil {
		t.Fatal("write admitted after stop")
	}
	if err := s.StopContext(ctx); err != nil {
		t.Fatal(err)
	}
	assertBudget(t, s.buffers(), 0)
}
