package socket

import (
	"context"
	"encoding/binary"
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
	// Early cap check
	if b.maxFlows > 0 {
		b.mu.RLock()
		cur := len(b.flows)
		b.mu.RUnlock()
		if cur >= b.maxFlows {
			b.parent.admission.tcpFlows.Add(1)
			rst := b.buildIPv4TCP(dstIP, srcIP, dstPort, srcPort, 0, seq+1, 0x04|0x10, nil)
			if rst != nil {
				_ = b.sendToGuest(nil, rst)
			}
			return fmt.Errorf("tcp: %w", ErrFlowLimit)
		}
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
				if b.parent != nil && b.parent.processor != nil {
					switch b.errorSignal {
					case "icmp":
						if icmp := b.buildICMPUnreachable(dstIP, srcIP, 1, pkt); icmp != nil {
							_ = b.sendToGuest(nil, icmp)
						}
					case "rst":
						rst := b.buildIPv4TCP(dstIP, srcIP, dstPort, srcPort, 0, seq+1, 0x04|0x10, nil)
						if rst != nil {
							_ = b.sendToGuest(nil, rst)
						}
					case "none":
					}
				}
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
	// Default MSS from effective MTU (respects runtime override)
	defMSS := 1460
	if b.parent != nil {
		mtu := b.parent.EffectiveMTU()
		if mtu <= 0 {
			mtu = b.parent.config.MTU
		}
		v := mtu - 40
		if v < 536 {
			v = 536
		}
		if v > 1460 {
			v = 1460
		}
		defMSS = v
	}
	// Apply MSS clamp (if configured) and MTU-derived cap
	eff := defMSS
	if int(b.mssClamp.Load()) > 0 && int(b.mssClamp.Load()) < eff {
		eff = int(b.mssClamp.Load())
	}
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
	// Insert under write lock with double-check
	candidate.stateMu.Lock()
	b.mu.Lock()
	select {
	case <-b.stopCh:
		b.mu.Unlock()
		candidate.stateMu.Unlock()
		if preConn != nil {
			preConn.Close()
		}
		return fmt.Errorf("TCP bridge stopped")
	default:
	}
	if exist := b.flows[key]; exist != nil {
		b.mu.Unlock()
		candidate.stateMu.Unlock()
		if preConn != nil {
			preConn.Close()
		}
		flow = exist
	} else {
		// Dialing happens outside the registry lock. Recheck admission here
		// so concurrent candidates cannot exceed the configured active cap.
		if b.maxFlows > 0 && len(b.flows) >= b.maxFlows {
			b.parent.admission.tcpFlows.Add(1)
			b.mu.Unlock()
			candidate.stateMu.Unlock()
			if preConn != nil {
				preConn.Close()
			}
			if b.parent.processor != nil {
				_ = b.sendToGuest(nil, b.buildIPv4TCP(dstIP, srcIP, dstPort, srcPort, 0, seq+1, fRST|fACK, nil))
			}
			return fmt.Errorf("tcp: %w", ErrFlowLimit)
		}
		b.flows[key] = candidate
		atomic.AddUint64(&b.metrics.ConnectionsCreated, 1)
		atomic.AddUint64(&b.parent.metrics.ConnectionsCreated, 1)
		b.mu.Unlock()
		flow = candidate
		defer flow.stateMu.Unlock()
		// Kick off async host dial; on success, attach conn, emit SYN-ACK (if not already), start reader, and flush pending
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
					// Signal guest per policy
					if b.parent != nil && b.parent.processor != nil {
						switch b.errorSignal {
						case "icmp":
							if icmp := b.buildICMPUnreachable(f.dstIP, f.srcIP, 1, quotedPacket); icmp != nil {
								_ = b.sendToGuest(nil, icmp)
							}
						case "rst":
							rst := b.buildIPv4TCP(f.dstIP, f.srcIP, f.dstPort, f.srcPort, 0, f.clientISN+1, 0x04|0x10, nil)
							if rst != nil {
								_ = b.sendToGuest(nil, rst)
							}
						case "none":
						}
					}
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
				// Send SYN-ACK now that dial succeeded (with MSS/WS/SACK options) unless already sent
				{
					mss := uint16(1460)
					effMTU := 1500
					if b.parent != nil {
						effMTU = b.parent.EffectiveMTU()
						if effMTU <= 0 {
							effMTU = b.parent.config.MTU
						}
						val := effMTU - 40
						if val < 536 {
							val = 536
						}
						if val > 1460 {
							val = 1460
						}
						if int(b.mssClamp.Load()) > 0 && val > int(b.mssClamp.Load()) {
							val = int(b.mssClamp.Load())
						}
						mss = uint16(val)
					} else if int(b.mssClamp.Load()) > 0 && int(mss) > int(b.mssClamp.Load()) {
						mss = uint16(int(b.mssClamp.Load()))
					}
					synOpts := make([]byte, 0, 8)
					synOpts = append(synOpts, 2, 4, byte(mss>>8), byte(mss))
					wsOut := uint8(b.tuning.WindowScale)
					f.wsOut = wsOut
					synOpts = append(synOpts, 3, 3, byte(wsOut))
					if f.sackPermitted || b.tuning.EnableSACK {
						synOpts = append(synOpts, 4, 2)
					}
					if !f.synAckSent {
						synAck := b.buildIPv4TCPOpts(f.dstIP, f.srcIP, f.dstPort, f.srcPort, f.serverISN, f.clientISN+1, fSYN|fACK, nil, synOpts)
						if b.logHandshake {
							logging.Infof("TCP SYN-ACK MSS: flow=%s effMTU=%d clamp=%d clientMSS=%d advMSS=%d",
								f.key, effMTU, int(b.mssClamp.Load()), int(f.clientMSS), int(mss))
						}
						if err := b.sendSYNACKLocked(f, synAck); err != nil {
							return
						}
					}
				}
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
		// Emit SYN-ACK immediately; if dial later succeeds, the goroutine will avoid duplicate send.
		if !flow.synAckSent {
			mss := uint16(1460)
			effMTU := 1500
			if b.parent != nil {
				effMTU = b.parent.EffectiveMTU()
				if effMTU <= 0 {
					effMTU = b.parent.config.MTU
				}
				val := effMTU - 40
				if val < 536 {
					val = 536
				}
				if val > 1460 {
					val = 1460
				}
				if int(b.mssClamp.Load()) > 0 && val > int(b.mssClamp.Load()) {
					val = int(b.mssClamp.Load())
				}
				mss = uint16(val)
			} else if int(b.mssClamp.Load()) > 0 && int(mss) > int(b.mssClamp.Load()) {
				mss = uint16(int(b.mssClamp.Load()))
			}
			synOpts := make([]byte, 0, 8)
			synOpts = append(synOpts, 2, 4, byte(mss>>8), byte(mss))
			wsOut := uint8(b.tuning.WindowScale)
			flow.wsOut = wsOut
			synOpts = append(synOpts, 3, 3, byte(wsOut))
			if flow.sackPermitted || b.tuning.EnableSACK {
				synOpts = append(synOpts, 4, 2)
			}
			synAck := b.buildIPv4TCPOpts(dstIP, srcIP, dstPort, srcPort, serverISN, seq+1, fSYN|fACK, nil, synOpts)
			if b.logHandshake {
				logging.Infof("TCP SYN-ACK MSS: flow=%s effMTU=%d clamp=%d clientMSS=%d advMSS=%d",
					key, effMTU, int(b.mssClamp.Load()), int(flow.clientMSS), int(mss))
			}
			if err := b.sendSYNACKLocked(flow, synAck); err != nil {
				return err
			}
		}
		// If already connected (fast pre-dial), start reader immediately
		if flow.conn != nil {
			b.launch(func() { b.reader(flow) })
		}
		return nil
	}

	return b.handleTCPFlow(flow, segment)
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
