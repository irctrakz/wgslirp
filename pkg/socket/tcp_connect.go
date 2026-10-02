package socket

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/irctrakz/wgslirp/pkg/logging"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// establishTCP runs within HandleOutbound's admitted operation. It dials without
// registry/flow locks, then publishes a state-locked candidate under the registry
// lock. A losing candidate closes only its own socket and processes the winner
// before its deferred dial reservation release, matching the ordinary SYN path.
func (b *tcpBridge) establishTCP(segment tcpSegment) error {
	pkt := segment.pkt
	ihl := segment.ihl
	tcpOff := segment.tcpOff
	dataOff := segment.dataOff
	srcIP := segment.srcIP
	dstIP := segment.dstIP
	srcPort := segment.srcPort
	dstPort := segment.dstPort
	seq := segment.seq
	key := segment.key
	var flow *tcpFlow
	// Early advisory check; publication rechecks after dialing.
	if b.atFlowCapacity() {
		b.parent.admission.tcpFlows.Add(1)
		rst := b.buildIPv4TCP(dstIP, srcIP, dstPort, srcPort, 0, seq+1, 0x04|0x10, nil)
		if rst != nil {
			_ = b.sendToGuest(nil, rst)
		}
		return fmt.Errorf("tcp: %w", ErrFlowLimit)
	}
	// One reservation spans fast dialing and asynchronous fallback.
	if !b.dialSlots.acquire(1) {
		b.parent.admission.pendingDials.Add(1)
		if b.parent.processor != nil {
			_ = b.sendToGuest(nil, b.buildIPv4TCP(dstIP, srcIP, dstPort, srcPort, 0, seq+1, fRST|fACK, nil))
		}
		return ErrDialLimit
	}
	dialCtx, cancelDial := context.WithCancel(b.ctx)
	releaseDial := sync.OnceFunc(func() { cancelDial(); b.dialSlots.release(1) })
	handedOff := false
	defer func() {
		if !handedOff {
			releaseDial()
		}
	}()
	// Fast pre-dial to detect immediate refusal before emitting SYN-ACK; fallback to async otherwise
	var preConn *net.TCPConn
	{
		raddr := &net.TCPAddr{IP: net.IP(dstIP[:]), Port: int(dstPort)}
		fastT := time.Duration(b.tuning.FastDialMs) * time.Millisecond
		if fastT <= 0 {
			fastT = time.Millisecond
		}
		if c, err := b.dial(dialCtx, raddr.String(), fastT); err == nil {
			preConn = c
			b.configureHostSocket(c)
			releaseDial()
		} else {
			if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
				// Hard failure: signal guest per policy and abort without SYN-ACK
				b.signalDialFailure(srcIP, dstIP, srcPort, dstPort, seq, pkt)
				atomic.AddUint64(&b.parent.metrics.Errors, 1)
				atomic.AddUint64(&b.metrics.Errors, 1)
				return nil
			}
		}
	}
	serverISN := rand.Uint32()
	candidate := &tcpFlow{
		key:        key,
		srcIP:      srcIP,
		dstIP:      dstIP,
		srcPort:    srcPort,
		dstPort:    dstPort,
		conn:       preConn,
		connecting: preConn == nil,
		cancelDial: cancelDial,
		clientISN:  seq,
		serverISN:  serverISN,
		clientNxt:  seq + 1,
		serverNxt:  serverISN + 1,
		sndUna:     serverISN + 1,
		state:      tcpSynRcvd,
		ooo:        nil,
		tos:        pkt[1],
		ttl:        pkt[8],
		ackCh:      make(chan struct{}, 1),
		rtoStop:    make(chan struct{}),
		rto:        time.Second,
		pendCap:    b.defaultPendCap,
	}
	// Bound the peer MSS by our current egress policy.
	eff, _ := b.synACKMSS()
	candidate.clientMSS = uint16(eff)
	candidate.mss = eff
	// Parse client SYN options for MSS, Window Scale, and SACK
	if dataOff > 20 {
		opts := pkt[tcpOff+20 : tcpOff+dataOff]
		for i := 0; i < len(opts); {
			kind := opts[i]
			switch kind {
			case 0: // EOL
				i = len(opts)
				continue
			case 1: // NOP
				i++
				continue
			default:
				if i+1 >= len(opts) {
					i = len(opts)
					continue
				}
				l := int(opts[i+1])
				if l < 2 || i+l > len(opts) {
					i = len(opts)
					continue
				}
				if kind == 2 && l == 4 { // MSS
					m := int(binary.BigEndian.Uint16(opts[i+2 : i+4]))
					if int(b.mssClamp.Load()) > 0 && m > int(b.mssClamp.Load()) {
						m = int(b.mssClamp.Load())
					}
					if m > eff {
						m = eff
					}
					candidate.clientMSS = uint16(m)
					candidate.mss = m
				} else if kind == 3 && l == 3 { // Window scale
					candidate.wsIn = opts[i+2]
				} else if kind == 4 && l == 2 { // SACK Permitted
					candidate.sackPermitted = true
				}
				i += l
			}
		}
	}
	candidate.touch()
	candidate.lastAckTime = time.Now()
	if b.tuning.CongestionControl != "off" {
		candidate.ccEnabled = true
		candidate.cc = newNewReno(candidate.mss, b.tuning.InitialCwndMSS)
	}
	// Preserve state-before-registry ordering through candidate publication.
	candidate.stateMu.Lock()
	registered, err := b.registerCandidateLocked(candidate)
	if err != nil {
		candidate.stateMu.Unlock()
		if preConn != nil {
			preConn.Close()
		}
		if errors.Is(err, ErrFlowLimit) && b.parent.processor != nil {
			_ = b.sendToGuest(nil, b.buildIPv4TCP(dstIP, srcIP, dstPort, srcPort, 0, seq+1, fRST|fACK, nil))
		}
		return err
	}
	if registered != candidate {
		candidate.stateMu.Unlock()
		if preConn != nil {
			preConn.Close()
		}
		flow = registered
	} else {
		flow = candidate
		defer flow.stateMu.Unlock()
		// Async success attaches the host socket, starts its reader and flushes pending data.
		if flow.connecting {
			f := flow
			quoteLen := ihl + 8
			if !b.buffers.acquire(quoteLen) {
				b.abortBufferedFlowLocked(f)
				return ErrBufferLimit
			}
			quotedPacket := make([]byte, quoteLen)
			copy(quotedPacket, pkt[:quoteLen])
			handedOff = true
			if !b.launch(func() {
				defer releaseDial()
				defer b.buffers.release(quoteLen)
				atomic.AddUint64(&b.dialStart, 1)
				atomic.AddInt64(&b.dialInflight, 1)
				raddr := &net.TCPAddr{IP: net.IP(f.dstIP[:]), Port: int(f.dstPort)}
				conn, err := b.dial(dialCtx, raddr.String(), 5*time.Second)
				releaseDial()
				if err != nil {
					f.stateMu.Lock()
					defer f.stateMu.Unlock()
					if f.closed {
						atomic.AddInt64(&b.dialInflight, -1)
						return
					}
					b.signalDialFailure(f.srcIP, f.dstIP, f.srcPort, f.dstPort, f.clientISN, quotedPacket)
					atomic.AddUint64(&b.dialFail, 1)
					atomic.AddUint64(&b.parent.metrics.Errors, 1)
					atomic.AddUint64(&b.metrics.Errors, 1)
					atomic.AddInt64(&b.dialInflight, -1)
					// Remove the flow on dial failure
					b.removeFlowLocked(f)
					return
				}
				b.configureHostSocket(conn)
				f.stateMu.Lock()
				defer f.stateMu.Unlock()
				if f.closed {
					conn.Close()
					atomic.AddInt64(&b.dialInflight, -1)
					return
				}
				f.conn = conn
				f.connecting = false
				f.lastAckTime = time.Now()
				atomic.AddUint64(&b.dialOk, 1)
				atomic.AddInt64(&b.dialInflight, -1)

				// Start reader now that conn exists
				b.launch(func() { b.reader(f) })
				// Flush any pre-connect pending data and contiguous reassembly
				b.flushPending(f)
			}) {
				releaseDial()
				b.buffers.release(quoteLen)
				b.removeFlowLocked(f)
				return fmt.Errorf("TCP bridge stopped")
			}
		}
		// Publication keeps stateMu until this send completes. Async completion
		// cannot attach/start a reader before it; refusal closes the candidate.
		if err := b.sendInitialSYNACKLocked(flow); err != nil {
			return err
		}
		// If already connected (fast pre-dial), start reader immediately
		if flow.conn != nil {
			b.launch(func() { b.reader(flow) })
		}
		return nil
	}

	return b.handleTCPFlow(flow, segment)
}

func (b *tcpBridge) signalDialFailure(src, dst [4]byte, sport, dport uint16, seq uint32, quote []byte) {
	if b.parent.processor == nil {
		return
	}
	switch b.errorSignal {
	case "icmp":
		_ = b.sendToGuest(nil, b.buildICMPUnreachable(dst, src, 1, quote))
	case "rst":
		_ = b.sendToGuest(nil, b.buildIPv4TCP(dst, src, dport, sport, 0, seq+1, fRST|fACK, nil))
	}
}

// synACKMSS returns our advertised MSS and the MTU used to derive it. The
// client's MSS may lower data segment size, but does not change this offer.
func (b *tcpBridge) synACKMSS() (int, int) {
	mtu := b.parent.EffectiveMTU()
	if mtu <= 0 {
		mtu = b.parent.config.MTU
	}
	mss := mtu - 40
	if mss < 536 {
		mss = 536
	}
	if mss > 1460 {
		mss = 1460
	}
	if clamp := int(b.mssClamp.Load()); clamp > 0 && mss > clamp {
		mss = clamp
	}
	return mss, mtu
}

// sendInitialSYNACKLocked requires stateMu on the newly published candidate.
// Establishment is its sole caller; async dial completion never emits SYN-ACK.
func (b *tcpBridge) sendInitialSYNACKLocked(f *tcpFlow) error {
	mss, mtu := b.synACKMSS()
	f.wsOut = uint8(b.tuning.WindowScale)
	opts := []byte{2, 4, byte(mss >> 8), byte(mss), 3, 3, f.wsOut}
	if f.sackPermitted || b.tuning.EnableSACK {
		opts = append(opts, 4, 2)
	}
	if b.logHandshake {
		logging.Infof("TCP SYN-ACK MSS: flow=%s effMTU=%d clamp=%d clientMSS=%d advMSS=%d",
			f.key, mtu, int(b.mssClamp.Load()), int(f.clientMSS), mss)
	}
	packet := b.buildIPv4TCPOpts(f.dstIP, f.srcIP, f.dstPort, f.srcPort, f.serverISN, f.clientISN+1, fSYN|fACK, nil, opts)
	return b.sendSYNACKLocked(f, packet)
}

// Caller holds f.stateMu throughout writes and reservation release.
// flushPending drains any pre-connect pending client->server data and then
// flushes contiguous reassembly segments once a connection is available.
func (b *tcpBridge) flushPending(f *tcpFlow) {
	if f == nil || f.conn == nil {
		return
	}
	// Drain pending FIFO
	var batches [][]byte
	reserved := f.pendingBytes + len(f.pending)*bufferEntryAllowance
	defer b.buffers.release(reserved)
	f.pendMu.Lock()
	if len(f.pending) > 0 {
		batches = f.pending
		f.pending = nil
		f.pendingBytes = 0
	}
	f.pendMu.Unlock()
	for _, p := range batches {
		if f.conn == nil {
			break
		}
		if n, err := writeTCP(f.conn, p); err == nil {
			atomic.AddUint64(&b.metrics.BytesSent, uint64(n))
			atomic.AddUint64(&b.metrics.PacketsSent, 1)
			f.toSrvBytes += uint64(n)
			f.toSrvPkts += 1
			atomic.AddUint64(&b.pendFlush, 1)
		} else {
			atomic.AddUint64(&b.parent.metrics.Errors, 1)
			atomic.AddUint64(&b.metrics.Errors, 1)
			b.abortBufferedFlowLocked(f)
			return
		}
	}
	if err := b.flushReassembly(f); err != nil {
		atomic.AddUint64(&b.parent.metrics.Errors, 1)
		atomic.AddUint64(&b.metrics.Errors, 1)
		b.abortBufferedFlowLocked(f)
		return
	}
	if f.finReceived {
		if err := b.closeHostWriteLocked(f); err != nil {
			atomic.AddUint64(&b.parent.metrics.Errors, 1)
			atomic.AddUint64(&b.metrics.Errors, 1)
		}
	}
}

// configureHostSocket applies the same policy to fast and asynchronous dials.
// Kernels may clamp buffer sizes; failures retain OS defaults and are observable.
func (b *tcpBridge) configureHostSocket(conn *net.TCPConn) {
	_ = conn.SetNoDelay(true)
	_ = conn.SetKeepAlive(true)
	_ = conn.SetKeepAlivePeriod(30 * time.Second)
	if n := b.tuning.SocketReceiveBuffer; n > 0 {
		if err := conn.SetReadBuffer(n); err != nil {
			if b.failureLog.Allow(time.Now()) {
				logging.Warnf("TCP receive buffer: %v", err)
			}
		}
	}
	if n := b.tuning.SocketSendBuffer; n > 0 {
		if err := conn.SetWriteBuffer(n); err != nil {
			if b.failureLog.Allow(time.Now()) {
				logging.Warnf("TCP send buffer: %v", err)
			}
		}
	}
}

func dialTCP(ctx context.Context, address string, timeout time.Duration) (*net.TCPConn, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	return conn.(*net.TCPConn), nil
}
