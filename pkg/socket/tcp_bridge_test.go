package socket

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestBuildIPv4TCP(t *testing.T) {
	var sip, dip [4]byte
	copy(sip[:], net.IPv4(192, 168, 0, 2).To4())
	copy(dip[:], net.IPv4(1, 1, 1, 1).To4())
	seq := uint32(1000)
	ack := uint32(2000)
	pkt := buildIPv4TCP(sip, dip, 12345, 80, seq, ack, 0x12, nil) // SYN|ACK
	if pkt == nil {
		t.Fatal("nil packet")
	}
	if pkt[0]>>4 != 4 {
		t.Fatalf("not ipv4")
	}
	if pkt[9] != 6 {
		t.Fatalf("not tcp proto")
	}
	sp := binary.BigEndian.Uint16(pkt[20:22])
	dp := binary.BigEndian.Uint16(pkt[22:24])
	if sp != 12345 || dp != 80 {
		t.Fatalf("bad ports %d->%d", sp, dp)
	}
	s := binary.BigEndian.Uint32(pkt[24:28])
	a := binary.BigEndian.Uint32(pkt[28:32])
	if s != seq || a != ack {
		t.Fatalf("bad seq/ack %d/%d", s, a)
	}
}

// Test reassembly merging: send out-of-order client segments and ensure
// the bridge writes to the server in order once missing data arrives.
func TestTCPBridge_ReassemblyMerge(t *testing.T) {
	// Start a local TCP server
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	srvRead := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		want := len("hello world")
		buf := make([]byte, 0, want)
		tmp := make([]byte, 64)
		for len(buf) < want {
			n, er := c.Read(tmp)
			if n > 0 {
				buf = append(buf, tmp[:n]...)
			}
			if er != nil {
				break
			}
		}
		srvRead <- buf
	}()

	// Parent with mock processor to receive SYN-ACK/ACKs
	parent := &SocketInterface{config: Config{MTU: 1500}}
	mp := &mockProc{}
	parent.processor = mp
	b := newTCPBridge(parent)
	t.Cleanup(b.stop)

	// Handshake
	var sip, dip [4]byte
	copy(sip[:], net.ParseIP("10.0.0.2").To4())
	dip4 := ln.Addr().(*net.TCPAddr).IP.To4()
	copy(dip[:], dip4)
	sport := uint16(40000)
	dport := uint16(ln.Addr().(*net.TCPAddr).Port)
	cseq := uint32(1000)
	syn := buildIPv4TCP(sip, dip, sport, dport, cseq, 0, 0x02, nil)
	if err := b.HandleOutbound(syn); err != nil {
		t.Fatalf("syn: %v", err)
	}

	// Wait for SYN-ACK from bridge
	var sseq uint32
	{ // find last pkt in mp.snapshot()
		if len(mp.snapshot()) == 0 {
			t.Fatalf("no SYN-ACK emitted")
		}
		p := mp.snapshot()[len(mp.snapshot())-1]
		ihl := int(p[0]&0x0f) * 4
		off := ihl
		flags := p[off+13]
		if (flags & 0x12) != 0x12 {
			t.Fatalf("not SYN-ACK: flags=0x%02x", flags)
		}
		sseq = binary.BigEndian.Uint32(p[off+4 : off+8])
	}
	ack := buildIPv4TCP(sip, dip, sport, dport, cseq+1, sseq+1, 0x10, nil)
	if err := b.HandleOutbound(ack); err != nil {
		t.Fatalf("ack: %v", err)
	}

	// Send out-of-order data: second segment first, then first
	p1 := []byte("hello ")
	p2 := []byte("world")
	d2 := buildIPv4TCP(sip, dip, sport, dport, cseq+1+uint32(len(p1)), sseq+1, 0x18, p2)
	if err := b.HandleOutbound(d2); err != nil {
		t.Fatalf("d2: %v", err)
	}
	d1 := buildIPv4TCP(sip, dip, sport, dport, cseq+1, sseq+1, 0x18, p1)
	if err := b.HandleOutbound(d1); err != nil {
		t.Fatalf("d1: %v", err)
	}

	// Expect the server to read concatenated data in order
	select {
	case got := <-srvRead:
		if string(got) != "hello world" {
			t.Fatalf("server read %q, want %q", string(got), "hello world")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for server read")
	}
}

// Test that host->guest segmentation respects client MSS.
func TestTCPBridge_MSSClamp(t *testing.T) {
	// Start a local TCP server that writes a large payload
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	payload := make([]byte, 3000)
	for i := range payload {
		payload[i] = byte('A' + (i % 26))
	}
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		// small delay to allow handshake
		time.Sleep(50 * time.Millisecond)
		_, _ = c.Write(payload)
		time.Sleep(50 * time.Millisecond)
		c.Close()
	}()

	// Parent with mock processor to capture outgoing to guest
	parent := &SocketInterface{config: Config{MTU: 1500}}
	mp := &mockProc{}
	parent.processor = mp
	b := newTCPBridge(parent)
	t.Cleanup(b.stop)

	// Client/Server addresses
	var sip, dip [4]byte
	copy(sip[:], net.ParseIP("10.0.0.2").To4())
	dip4 := ln.Addr().(*net.TCPAddr).IP.To4()
	copy(dip[:], dip4)
	sport := uint16(40001)
	dport := uint16(ln.Addr().(*net.TCPAddr).Port)
	cseq := uint32(2000)

	// SYN with MSS=600 to force small segments
	// Build SYN with MSS option
	// MSS=600 encoded big-endian
	opts := []byte{2, 4, 0x02, 0x58}
	syn := buildIPv4TCPOpts(sip, dip, sport, dport, cseq, 0, 0x02, nil, opts)
	if err := b.HandleOutbound(syn); err != nil {
		t.Fatalf("syn: %v", err)
	}
	if len(mp.snapshot()) == 0 {
		t.Fatalf("no SYN-ACK emitted")
	}
	p := mp.snapshot()[len(mp.snapshot())-1]
	ihl := int(p[0]&0x0f) * 4
	off := ihl
	sseq := binary.BigEndian.Uint32(p[off+4 : off+8])
	ack := buildIPv4TCP(sip, dip, sport, dport, cseq+1, sseq+1, 0x10, nil)
	if err := b.HandleOutbound(ack); err != nil {
		t.Fatalf("ack: %v", err)
	}

	// Allow server to write and bridge to emit segments
	time.Sleep(300 * time.Millisecond)

	// Inspect captured packets to guest for payload sizes
	maxPL := 0
	for _, pkt := range mp.snapshot() {
		if len(pkt) < 40 {
			continue
		}
		if pkt[9] != 6 {
			continue
		}
		ih := int(pkt[0]&0x0f) * 4
		toff := ih
		doff := int((pkt[toff+12] >> 4) * 4)
		pl := len(pkt) - (ih + doff)
		if pl > maxPL {
			maxPL = pl
		}
	}
	if maxPL > 600 {
		t.Fatalf("max payload len %d exceeds MSS clamp 600", maxPL)
	}
}

// Test fast retransmit via 3 duplicate ACKs.
func TestTCPBridge_FastRetransmit(t *testing.T) {
	// Start a local TCP server that writes once to trigger a single data segment
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	payload := []byte("abcdefghij")
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		time.Sleep(50 * time.Millisecond)
		_, _ = c.Write(payload)
		time.Sleep(500 * time.Millisecond)
	}()

	parent := &SocketInterface{config: Config{MTU: 1500}}
	mp := &mockProc{}
	parent.processor = mp
	b := newTCPBridge(parent)
	t.Cleanup(b.stop)

	var sip, dip [4]byte
	copy(sip[:], net.ParseIP("10.0.0.2").To4())
	dip4 := ln.Addr().(*net.TCPAddr).IP.To4()
	copy(dip[:], dip4)
	sport := uint16(40002)
	dport := uint16(ln.Addr().(*net.TCPAddr).Port)
	cseq := uint32(3000)

	syn := buildIPv4TCP(sip, dip, sport, dport, cseq, 0, 0x02, nil)
	if err := b.HandleOutbound(syn); err != nil {
		t.Fatalf("syn: %v", err)
	}
	if len(mp.snapshot()) == 0 {
		t.Fatalf("no SYN-ACK")
	}
	p := mp.snapshot()[len(mp.snapshot())-1]
	ihl := int(p[0]&0x0f) * 4
	off := ihl
	sseq := binary.BigEndian.Uint32(p[off+4 : off+8])
	ack := buildIPv4TCP(sip, dip, sport, dport, cseq+1, sseq+1, 0x10, nil)
	if err := b.HandleOutbound(ack); err != nil {
		t.Fatalf("ack: %v", err)
	}

	// Give time for server write and initial segment to be emitted
	time.Sleep(200 * time.Millisecond)
	// Capture last data segment sequence
	var firstDataSeq uint32
	for i := len(mp.snapshot()) - 1; i >= 0; i-- {
		pkt := mp.snapshot()[i]
		if len(pkt) < 40 || pkt[9] != 6 {
			continue
		}
		ih := int(pkt[0]&0x0f) * 4
		to := ih
		do := int((pkt[to+12] >> 4) * 4)
		pl := len(pkt) - (ih + do)
		if pl > 0 {
			firstDataSeq = binary.BigEndian.Uint32(pkt[to+4 : to+8])
			break
		}
	}
	if firstDataSeq == 0 {
		t.Fatalf("no data seg observed")
	}

	// Send 3 duplicate ACKs (no advancement) to trigger fast retransmit
	beforeRetransmit := len(mp.snapshot())
	for i := 0; i < 3; i++ {
		da := buildIPv4TCP(sip, dip, sport, dport, cseq+1, sseq+1, 0x10, nil)
		if err := b.HandleOutbound(da); err != nil {
			t.Fatalf("dup ack: %v", err)
		}
	}

	// Expect a retransmitted segment with same seq to appear
	deadline := time.Now().Add(1 * time.Second)
	found := false
	for time.Now().Before(deadline) {
		for _, pkt := range mp.snapshot()[beforeRetransmit:] {
			if len(pkt) < 40 || pkt[9] != 6 {
				continue
			}
			ih := int(pkt[0]&0x0f) * 4
			to := ih
			do := int((pkt[to+12] >> 4) * 4)
			pl := len(pkt) - (ih + do)
			if pl == 0 {
				continue
			}
			s := binary.BigEndian.Uint32(pkt[to+4 : to+8])
			if s == firstDataSeq {
				found = true
				break
			}
		}
		if found {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !found {
		t.Fatalf("no retransmit observed for seq %d", firstDataSeq)
	}
}

// Test simple RTO: if no ACKs arrive, retransmit after timeout.
func TestTCPBridge_RTO(t *testing.T) {
	holdOpen := make(chan struct{})
	defer close(holdOpen)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	payload := []byte("xxxxxxxxxx")
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		time.Sleep(50 * time.Millisecond)
		_, _ = c.Write(payload)
		<-holdOpen
	}()

	parent := &SocketInterface{config: Config{MTU: 1500}}
	mp := &mockProc{}
	parent.processor = mp
	b := newTCPBridge(parent)
	t.Cleanup(b.stop)

	var sip, dip [4]byte
	copy(sip[:], net.ParseIP("10.0.0.2").To4())
	dip4 := ln.Addr().(*net.TCPAddr).IP.To4()
	copy(dip[:], dip4)
	sport := uint16(40003)
	dport := uint16(ln.Addr().(*net.TCPAddr).Port)
	cseq := uint32(4000)

	syn := buildIPv4TCP(sip, dip, sport, dport, cseq, 0, 0x02, nil)
	if err := b.HandleOutbound(syn); err != nil {
		t.Fatalf("syn: %v", err)
	}
	if len(mp.snapshot()) == 0 {
		t.Fatalf("no SYN-ACK")
	}
	p := mp.snapshot()[len(mp.snapshot())-1]
	ihl := int(p[0]&0x0f) * 4
	off := ihl
	sseq := binary.BigEndian.Uint32(p[off+4 : off+8])
	ack := buildIPv4TCP(sip, dip, sport, dport, cseq+1, sseq+1, 0x10, nil)
	if err := b.HandleOutbound(ack); err != nil {
		t.Fatalf("ack: %v", err)
	}

	// Wait for initial data segment
	time.Sleep(200 * time.Millisecond)
	var firstDataSeq uint32
	for i := len(mp.snapshot()) - 1; i >= 0; i-- {
		pkt := mp.snapshot()[i]
		if len(pkt) < 40 || pkt[9] != 6 {
			continue
		}
		ih := int(pkt[0]&0x0f) * 4
		to := ih
		do := int((pkt[to+12] >> 4) * 4)
		pl := len(pkt) - (ih + do)
		if pl > 0 {
			firstDataSeq = binary.BigEndian.Uint32(pkt[to+4 : to+8])
			break
		}
	}
	if firstDataSeq == 0 {
		t.Fatalf("no data seg observed")
	}

	// Do not send ACKs; wait for RTO
	deadline := time.Now().Add(1200 * time.Millisecond)
	retrans := 0
	for time.Now().Before(deadline) {
		retrans = 0 // Count distinct captured packets, not repeated observations.
		for _, pkt := range mp.snapshot() {
			if len(pkt) < 40 || pkt[9] != 6 {
				continue
			}
			ih := int(pkt[0]&0x0f) * 4
			to := ih
			do := int((pkt[to+12] >> 4) * 4)
			pl := len(pkt) - (ih + do)
			if pl == 0 {
				continue
			}
			s := binary.BigEndian.Uint32(pkt[to+4 : to+8])
			if s == firstDataSeq {
				retrans++
			}
		}
		if retrans >= 2 { // initial send + one retransmit
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if retrans < 2 {
		t.Fatalf("expected retransmission for seq %d", firstDataSeq)
	}
}
