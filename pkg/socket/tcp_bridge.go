package socket

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"sync/atomic"

	"github.com/irctrakz/wgslirp/pkg/core"
	"github.com/irctrakz/wgslirp/pkg/logging"
)

// TCP slirp bridge for host networking.
//
// Overview (generic, protocol-agnostic):
// - Performs a full TCP handshake to a host socket on initial SYN.
// - Parses and honors client MSS and Window Scale options.
// - Handles guest out-of-order data with a per-flow reassembly buffer that
//   merges/compacts segments until missing data arrives.
// - Segments server→guest payloads respecting advertised window and MSS.
// - Implements delayed-ACK scheduling and wakes senders on ACK/window updates
//   via a per-flow notifier, without protocol-specific heuristics.
// - Implements basic loss recovery:
//   * Fast retransmit on 3 duplicate ACKs.
//   * Simple RTO with exponential backoff and a retransmission queue.
// - Applies backpressure end-to-end:
//   * Reader pauses when per-flow queues exceed a high watermark and resumes
//     on a low watermark.
//   * Scheduler cooperates with downstream (e.g., WG TUN) backpressure by
//     requeueing and yielding briefly instead of dropping.
//
// The goal is a robust, generic TCP bridge that relies on TCP flow control and
// retransmission rather than protocol-specific tweaks.

type tcpBridge struct {
	deliveryRefused atomic.Uint64
	failureLog      logging.RateLimiter
	deliver         packetDelivery
	startOnce       sync.Once
	tuning          TransportConfig
	dialSlots       *resourceBudget
	buffers         *resourceBudget
	retransmitCap   int
	dial            func(context.Context, string, time.Duration) (*net.TCPConn, error)
	bufferDrops     atomic.Uint64
	lifecycleMu     sync.Mutex
	workers         sync.WaitGroup
	stopOnce        sync.Once
	ctx             context.Context
	cancel          context.CancelFunc
	parent          *SocketInterface
	mu              sync.RWMutex
	flows           map[string]*tcpFlow
	stopCh          chan struct{}
	lifetime        time.Duration

	metrics  core.SocketMetrics
	maxFlows int
	ackDelay time.Duration
	reasmCap int
	// How to signal guest on outbound connect failures: "icmp" (default), "rst", or "none"
	errorSignal string
	// Optional ACK-idle gating configuration
	ackIdleGate        time.Duration // 0 = disabled; gate reads when no ACK for >= this
	ackIdleMinInflight int           // only gate if inFlight > this (bytes); 0 -> auto = MSS
	// Optional ACK-idle fail threshold: if no ACK progress for >= this duration
	// while there is in-flight data, treat the flow as hung and actively reset
	// it (policy-controlled) to avoid indefinite stalls. 0 disables.
	ackIdleFail time.Duration

	// debug removed (was verbose per-flow tracing)

	// Optional MSS clamp (bytes). When >0, we clamp advertised MSS in
	// SYN-ACK and the effective segmentation MSS to min(client, clamp, MTU-40).
	mssClamp atomic.Int64

	// Optional lightweight pacing between segments (microseconds). When >0,
	// we sleep this long between enqueued segments to reduce burst loss on
	// marginal paths.
	paceUS atomic.Int64

	// RTO retransmissions observed (for diagnostics/metrics)
	rtoCount uint64

	// RTO metrics tracking
	rtoMu              sync.Mutex
	rtoActiveFlows     map[string]*tcpFlow // Tracks flows currently in RTO retransmission
	rtoMetricsDumped   bool                // Flag to prevent repeated dumps for the same event
	rtoMetricsDumpTime time.Time           // Last time metrics were dumped

	// ACK classification counters (userspace visibility for return path)
	ackAdv     uint64 // ACK advanced sndUna
	ackDup     uint64 // Duplicate ACK (no payload, ack==sndUna)
	ackWndOnly uint64 // Pure window update (ack==sndUna, window increased)

	// Optional per-ACK trace (debug)
	ackTrace bool

	// Async dial + pending buffering instrumentation
	dialStart    uint64
	dialOk       uint64
	dialFail     uint64
	dialInflight int64

	pendEnq   uint64
	pendFlush uint64
	pendDrop  uint64

	// Default per-flow pre-connect pending cap (bytes)
	defaultPendCap int

	// Handshake logging toggle (SYN-ACK MSS). Enable via TCP_LOG_HANDSHAKE=1|true|on|yes
	logHandshake bool

	// Send-gate logging controls
	gateLogDisabled bool // disable "TCP send-gated" logs entirely
	gateLogDebug    bool // log send-gated at debug level instead of info
}

type tcpState int

const (
	tcpSynRcvd tcpState = iota
	tcpEstablished
	tcpFinWait1
	tcpFinWait2
	tcpCloseWait
	tcpClosing
	tcpLastAck
	tcpTimeWait
	tcpClosed
)

type tcpFlow struct {
	retransmitBlocked bool // stateMu; counts transitions, not polling iterations
	// stateMu owns connection attachment, sequence/window state, timers and
	// flow accounting. Never acquire it while holding the bridge registry lock.
	// The existing buffer locks may only be nested inside stateMu.
	stateMu    sync.Mutex
	closed     bool
	cancelDial context.CancelFunc
	txBytes    int
	key        string
	srcIP      [4]byte
	dstIP      [4]byte
	srcPort    uint16
	dstPort    uint16

	conn *net.TCPConn
	// Deferred connect support
	connecting   bool
	pendMu       sync.Mutex
	pending      [][]byte
	pendingBytes int
	pendCap      int // max bytes to buffer before connect (per flow)

	// Sequence tracking
	clientISN uint32
	serverISN uint32
	clientNxt uint32 // next expected from client
	serverNxt uint32 // next to send to client
	sndUna    uint32 // lowest unacknowledged seq we sent

	state tcpState

	lastMu       sync.Mutex
	lastActivity time.Time
	lastAckTime  time.Time

	finSent         bool
	finReceived     bool
	hostWriteClosed bool
	finSeq          uint32
	finSentAt       time.Time
	finRTO          time.Duration
	closeDeadline   time.Time
	timeWaitUntil   time.Time

	mu sync.Mutex
	// Out-of-order reassembly buffer (sorted by seq, merged)
	ooo []struct {
		seq  uint32
		data []byte
	}
	futureBytes int

	// Peer receive window information (from client)
	clientMSS uint16
	wsIn      uint8  // peer's window scale (client SYN option)
	wsOut     uint8  // our advertised window scale (SYN-ACK)
	advWnd    uint32 // latest advertised peer window in bytes

	// delayed ack scheduling
	ackMu        sync.Mutex
	ackScheduled bool

	// Preserve DSCP/ECN and TTL for host->guest data segments
	tos byte
	ttl byte

	// Per-flow accounting for post-mortem analysis
	toSrvBytes uint64 // guest->server bytes written on host socket
	toSrvPkts  uint64 // guest->server write operations
	toCliBytes uint64 // server->guest bytes emitted toward guest
	toCliPkts  uint64 // server->guest segments emitted

	// Send tracking for retransmissions
	txMu    sync.Mutex
	txQueue []struct {
		seq     uint32
		data    []byte
		sentAt  time.Time
		retries int
		rtx     bool
	}
	dupAckCnt int
	lastAck   uint32
	// RTT/RTO estimation (RFC 6298)
	srtt    time.Duration
	rttvar  time.Duration
	rto     time.Duration
	rtoStop chan struct{}

	// Notify sender when ACK/window updates arrive.
	ackCh chan struct{}

	// handshake state
	synAckSent bool

	// SACK loss recovery (RFC 6675 simplified)
	sackRecovery bool
	recover      uint32
	pipeBytes    int

	// SACK support
	sackPermitted bool
	// scoreboard of SACKed ranges (left,right), normalized and compacted
	sackMu   sync.Mutex
	sackList []struct {
		left  uint32
		right uint32
	}

	// Congestion control (server->guest)
	cc        congestionControl
	ccEnabled bool
	mss       int

	// Throttled logging for send-gated (zero-window/cwnd) messages
	gateMu          sync.Mutex
	lastGateLog     time.Time
	suppressedGates int
}

// newTCPBridge constructs a TCP bridge instance and wires optional per-flow
// scheduling/backpressure via the parent's FlowManager when present.
func newTCPBridge(parent *SocketInterface) *tcpBridge {
	b := &tcpBridge{
		parent:   parent,
		deliver:  parent.packetDelivery(),
		flows:    make(map[string]*tcpFlow),
		stopCh:   make(chan struct{}),
		lifetime: 2 * time.Minute,
		ackDelay: 10 * time.Millisecond,
		reasmCap: 128 * 1024,
		// Defaults: proactively gate reads after 6s of no ACK progress,
		// and fail/reset truly stuck flows after 120s.
		ackIdleGate:    6 * time.Second,
		ackIdleFail:    120 * time.Second,
		rtoActiveFlows: make(map[string]*tcpFlow),
	}
	if parent != nil {
		cfg := parent.config
		b.ackDelay = time.Duration(cfg.TCPAckDelayMs) * time.Millisecond
		if cfg.TCPFlowLifetimeSec > 0 {
			b.lifetime = time.Duration(cfg.TCPFlowLifetimeSec) * time.Second
		}
		if cfg.TCPReassemblyCapBytes > 0 {
			b.reasmCap = cfg.TCPReassemblyCapBytes
		}
		b.maxFlows = cfg.MaxTCPFlows
	}
	b.tuning = parent.config.transportConfig()
	b.ackIdleGate = time.Duration(b.tuning.AckIdleGateMs) * time.Millisecond
	b.ackIdleMinInflight = b.tuning.AckIdleMinInflight
	b.ackIdleFail = time.Duration(b.tuning.AckIdleFailSec) * time.Second
	b.ackTrace = b.tuning.AckTrace
	b.mssClamp.Store(int64(b.tuning.MSSClamp))
	b.paceUS.Store(int64(b.tuning.PaceUS))
	b.errorSignal = b.tuning.ErrorSignal
	b.logHandshake = b.tuning.LogHandshake
	b.gateLogDisabled = b.tuning.GateLog == "off"
	b.gateLogDebug = b.tuning.GateLog == "debug"

	// Log the creation of the TCP bridge
	logging.Infof("Creating TCP bridge: lifetime=%v, ackDelay=%v, reasmCap=%d, errSignal=%s",
		b.lifetime, b.ackDelay, b.reasmCap, b.errorSignal)

	b.defaultPendCap = budgetDefault(parent.config.TCPPendingCapBytes, DefaultTCPPendingCap)
	b.retransmitCap = budgetDefault(parent.config.TCPRetransmitCapBytes, DefaultTCPRetransmitCap)
	b.buffers = parent.buffers()
	b.dialSlots = &resourceBudget{limit: budgetDefault(parent.config.MaxPendingTCPDials, DefaultPendingTCPDials)}
	b.dial = dialTCP
	b.ctx, b.cancel = context.WithCancel(context.Background())
	return b
}

// start owns periodic work; construction performs no I/O or goroutine launch.
func (b *tcpBridge) start() {
	b.startOnce.Do(func() { b.launch(b.reaper); b.launch(b.monitorConnectionHealth) })
}

// sendToGuest transfers a reserved packet to the downstream processor.
func (b *tcpBridge) sendToGuest(f *tcpFlow, pkt core.Packet) bool {
	if pkt == nil {
		return false
	}
	size := pkt.Length()
	if b.parent == nil {
		core.ReleasePacket(pkt)
		return false
	}
	if b.deliver(pkt) {
		atomic.AddUint64(&b.metrics.PacketsReceived, 1)
		atomic.AddUint64(&b.metrics.BytesReceived, uint64(size))
		atomic.AddUint64(&b.parent.metrics.PacketsReceived, 1)
		atomic.AddUint64(&b.parent.metrics.BytesReceived, uint64(size))
		return true
	}
	b.deliveryRefused.Add(1)
	return false
}

// monitorConnectionHealth periodically checks for stalled connections and resets them.
// This helps prevent indefinite stalls that can exhaust resources.
func (b *tcpBridge) monitorConnectionHealth() {
	// Check every 15 seconds for stalled connections
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	// Configure stall detection parameters
	stallThreshold := 30 * time.Second // Consider connection stalled after 30s without ACK progress
	minInFlight := 1024                // Only check connections with at least 1KB in flight

	for {
		select {
		case <-b.stopCh:
			return
		case <-ticker.C:
			now := time.Now()
			stalledFlows := make([]*tcpFlow, 0)

			// Identify stalled flows
			for _, f := range b.flowSnapshot() {
				f.stateMu.Lock()
				k := f.key
				// Only check established connections with in-flight data
				if f.state == tcpEstablished {
					inFlight := int(f.serverNxt - f.sndUna)
					idleTime := now.Sub(f.lastAckTime)

					// Connection is stalled if:
					// 1. It has meaningful in-flight data
					// 2. No ACK progress for a significant period
					if inFlight >= minInFlight && idleTime >= stallThreshold {
						stalledFlows = append(stalledFlows, f)
						logging.Warnf("Stalled connection detected: flow=%s idle=%v inFlight=%d bytes",
							k, idleTime.Round(time.Second), inFlight)
					}
				}
				f.stateMu.Unlock()
			}

			// Reset stalled flows
			reset := 0
			for _, f := range stalledFlows {
				// Recheck progress after taking a snapshot: an ACK may have arrived.
				if b.removeFlowIf(f, func(f *tcpFlow) bool {
					return f.state == tcpEstablished && int(f.serverNxt-f.sndUna) >= minInFlight && now.Sub(f.lastAckTime) >= stallThreshold
				}) {
					reset++
				}
			}

			// Log health check summary if any issues found
			if reset > 0 {
				logging.Infof("Connection health check: reset %d stalled flows", reset)
			}
		}
	}
}

// SetMSSClamp updates the runtime MSS clamp (bytes). 0 disables the clamp.
func (b *tcpBridge) SetMSSClamp(n int) {
	if n < 0 {
		n = 0
	}
	b.mssClamp.Store(int64(n))
	logging.Infof("TCP MSS clamp set to %d (0=disabled)", n)
}

// SetPaceUS updates the per-segment pacing interval in microseconds (0 disables).
func (b *tcpBridge) SetPaceUS(us int) {
	if us < 0 {
		us = 0
	}
	b.paceUS.Store(int64(us))
	logging.Infof("TCP pacing set to %d us (0=disabled)", us)
}

func (b *tcpBridge) requestStop() {
	b.lifecycleMu.Lock()
	defer b.lifecycleMu.Unlock()
	select {
	case <-b.stopCh:
		return
	default:
	}
	close(b.stopCh)
	b.cancel()
}

func (b *tcpBridge) stop() {
	b.requestStop()
	b.stopOnce.Do(func() {
		for _, f := range b.flowSnapshot() {
			b.removeFlowIf(f, nil)
		}
		b.workers.Wait()
	})
}

func (b *tcpBridge) Name() string { return "tcp" }

func (b *tcpBridge) HandleOutbound(pkt []byte) (err error) {
	admitted := false
	// Publish the operation's error before allowing lifecycle waits to complete.
	defer func() {
		if err != nil {
			atomic.AddUint64(&b.metrics.Errors, 1)
		}
		if admitted {
			b.workers.Done()
		}
	}()
	if !b.beginWork() {
		return fmt.Errorf("TCP bridge stopped")
	}
	admitted = true

	pkt, ihl, err := parseTransport(pkt, 6)
	if err != nil {
		return err
	}

	var srcIP, dstIP [4]byte
	copy(srcIP[:], pkt[12:16])
	copy(dstIP[:], pkt[16:20])

	tcpOff := ihl
	dataOff := int((pkt[tcpOff+12] >> 4) * 4)
	if dataOff < 20 || len(pkt) < tcpOff+dataOff {
		return fmt.Errorf("tcp: header length invalid")
	}
	flags := pkt[tcpOff+13]
	seq := binary.BigEndian.Uint32(pkt[tcpOff+4 : tcpOff+8])
	ack := binary.BigEndian.Uint32(pkt[tcpOff+8 : tcpOff+12])
	srcPort := binary.BigEndian.Uint16(pkt[tcpOff : tcpOff+2])
	dstPort := binary.BigEndian.Uint16(pkt[tcpOff+2 : tcpOff+4])
	payload := pkt[tcpOff+dataOff:]

	key := fmt.Sprintf("%d.%d.%d.%d:%d-%d.%d.%d.%d:%d",
		srcIP[0], srcIP[1], srcIP[2], srcIP[3], srcPort,
		dstIP[0], dstIP[1], dstIP[2], dstIP[3], dstPort,
	)

	// SYN: create flow and respond with SYN-ACK after dialing host
	const (
		fFIN = 0x01
		fSYN = 0x02
		fRST = 0x04
		fPSH = 0x08
		fACK = 0x10
	)

	if flags&fRST != 0 {
		// Remove flow if exists
		b.removeFlow(key)
		return nil
	}

	// Fast path: lookup existing flow under read lock
	b.mu.RLock()
	flow := b.flows[key]
	b.mu.RUnlock()
	if flow == nil && (flags&fSYN) != 0 && (flags&fACK) == 0 {
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
	}

	if flow == nil {
		// No flow: send RST per RFC depending on ACK flag
		const fACK = 0x10
		const fRST = 0x04
		if (flags & fACK) != 0 {
			// RST with seq = ack
			rst := b.buildIPv4TCP(dstIP, srcIP, dstPort, srcPort, ack, 0, fRST, nil)
			if rst != nil {
				_ = b.sendToGuest(flow, rst)
			}
		} else {
			// RST|ACK with ack = seq + len
			segLen := uint32(len(payload))
			// SYN/FIN consume 1 sequence number
			if (flags & 0x02) != 0 { // SYN
				segLen++
			}
			if (flags & 0x01) != 0 { // FIN
				segLen++
			}
			rst := b.buildIPv4TCP(dstIP, srcIP, dstPort, srcPort, 0, seq+segLen, fRST|fACK, nil)
			if rst != nil {
				_ = b.sendToGuest(flow, rst)
			}
		}
		return nil
	}

	flow.stateMu.Lock()
	defer flow.stateMu.Unlock()
	if flow.closed {
		return fmt.Errorf("TCP flow closed")
	}
	flow.touch()

	switch flow.state {
	case tcpSynRcvd:
		if (flags&fACK) != 0 && ack == flow.serverISN+1 {
			flow.state = tcpEstablished
			// Seed advertised window from this ACK
			wnd := uint32(binary.BigEndian.Uint16(pkt[tcpOff+14 : tcpOff+16]))
			if flow.wsIn > 0 {
				wnd = wnd << flow.wsIn
			}
			flow.advWnd = wnd
			select {
			case flow.ackCh <- struct{}{}:
			default:
			}
		} else {
			return nil
		}
		// The handshake ACK may also carry data and/or FIN.
		fallthrough
	case tcpEstablished, tcpFinWait1, tcpFinWait2, tcpCloseWait, tcpClosing, tcpLastAck, tcpTimeWait:
		if flow.state == tcpTimeWait {
			if flags&fFIN != 0 && seq+uint32(len(payload))+1 == flow.clientNxt {
				b.enterTimeWaitLocked(flow, time.Now())
				b.sendCloseACKLocked(flow)
			}
			return nil
		}
		if flags&fACK != 0 && seqAfter(ack, flow.serverNxt) {
			b.sendCloseACKLocked(flow)
			return nil
		}
		// Handle ACK updates and possible FIN teardown
		if (flags & fACK) != 0 {
			// dupACK detection
			if ack == flow.sndUna && len(payload) == 0 {
				flow.dupAckCnt++
				atomic.AddUint64(&b.ackDup, 1)
			} else {
				flow.dupAckCnt = 0
			}
			if !seqAfter(ack, flow.serverNxt) && seqAfter(ack, flow.sndUna) {
				prevUna := flow.sndUna
				flow.sndUna = ack
				flow.lastAckTime = time.Now()
				if !flow.closeDeadline.IsZero() {
					b.beginCloseLocked(flow, flow.lastAckTime)
				}
				atomic.AddUint64(&b.ackAdv, 1)
				// drop acknowledged segments from txQueue and update RTT/RTO
				now := time.Now()
				flow.txMu.Lock()
				for len(flow.txQueue) > 0 {
					head := flow.txQueue[0]
					if !seqAfter(head.seq+uint32(len(head.data)), ack) {
						// RTT sample (Karn's algorithm: only if not retransmitted)
						if head.retries == 0 && !head.sentAt.IsZero() {
							sample := now.Sub(head.sentAt)
							if sample > 0 {
								if flow.srtt == 0 {
									// RFC 6298 init
									flow.srtt = sample
									flow.rttvar = sample / 2
								} else {
									// RFC 6298 update
									err := flow.srtt - sample
									if err < 0 {
										err = -err
									}
									flow.rttvar = (3*flow.rttvar + err) / 4
									flow.srtt = (7*flow.srtt + sample) / 8
								}
								// RTO = SRTT + 4*RTTVAR, with bounds
								rto := flow.srtt + 4*flow.rttvar
								if rto < 200*time.Millisecond {
									rto = 200 * time.Millisecond
								}
								if rto > 60*time.Second {
									rto = 60 * time.Second
								}
								flow.rto = rto
							}
						}
						flow.txQueue[0].data = nil
						flow.txQueue = flow.txQueue[1:]
						flow.txBytes -= len(head.data)
						b.buffers.release(bufferCharge(len(head.data)))
					} else {
						break
					}
				}
				flow.txMu.Unlock()
				// Notify CC of ACKed bytes
				if flow.ccEnabled && flow.cc != nil {
					diff := int(ack - prevUna)
					if diff > 0 {
						flow.cc.OnAck(diff)
					}
				}
				// trimmed: per-flow verbose ack debug removed
				// Notify sender waiters
				select {
				case flow.ackCh <- struct{}{}:
				default:
				}
			}
			// Track previous window to detect pure window updates that should wake senders.
			prevWnd := flow.advWnd
			wnd := uint32(binary.BigEndian.Uint16(pkt[tcpOff+14 : tcpOff+16]))
			if flow.wsIn > 0 {
				wnd = wnd << flow.wsIn
			}
			flow.advWnd = wnd
			// If the peer opened its window without advancing ACK, wake senders.
			if wnd > prevWnd {
				// Treat as progress for idle tracking to avoid false ACK-idle.
				flow.lastAckTime = time.Now()
				// Count as window-only update if ACK did not advance
				if ack <= flow.sndUna {
					atomic.AddUint64(&b.ackWndOnly, 1)
				}
				select {
				case flow.ackCh <- struct{}{}:
				default:
				}
			}
			if b.ackTrace {
				class := "adv"
				if ack == flow.sndUna && len(payload) == 0 {
					class = "dup"
				} else if ack <= flow.sndUna && wnd > prevWnd {
					class = "wnd"
				}
				logging.Infof("TCP ACK trace: flow=%s class=%s ack=%d sndUna=%d nxt=%d wnd=%d ws=%d txq=%d",
					flow.key, class, ack, flow.sndUna, flow.serverNxt, flow.advWnd, flow.wsIn, len(flow.txQueue))
			}
			// Parse SACK blocks if any and SACK permitted
			if flow.sackPermitted || b.tuning.EnableSACK {
				if dataOff > 20 {
					opts := pkt[tcpOff+20 : tcpOff+dataOff]
					parseSACKBlocks(flow, opts)
					// trimmed: verbose SACK block debug removed
				}
			}
			b.ackFINLocked(flow, ack, time.Now())
			if flow.closed {
				return nil
			}
			// Fast retransmit on 3 dupACKs
			if flow.dupAckCnt >= 3 {
				flow.dupAckCnt = 0
				// Enter SACK recovery and retransmit a hole if available
				flow.sackRecovery = true
				if flow.serverNxt > 0 {
					flow.recover = flow.serverNxt - 1
				}
				b.retransmitNextHole(flow)
			}
			// Partial ACK handling: in recovery, keep sending next hole
			if flow.sackRecovery {
				if ack >= flow.recover {
					flow.sackRecovery = false
				} else {
					b.retransmitNextHole(flow)
				}
			}
		}

		// A consumed FIN closes only the guest->host direction. Continue
		// processing ACKs/windows above for the host's response and FIN.
		if flow.finReceived {
			if len(payload) > 0 || flags&fFIN != 0 {
				b.sendCloseACKLocked(flow)
			}
			return nil
		}
		finSeq := seq + uint32(len(payload))
		if seqBefore(seq, flow.clientNxt) {
			skip := uint32(flow.clientNxt - seq)
			if skip > uint32(len(payload)) {
				b.sendCloseACKLocked(flow)
				return nil
			}
			// Keep a new suffix/FIN when only its prefix was retransmitted.
			payload = payload[skip:]
			seq = flow.clientNxt
		}
		if seqAfter(seq, flow.clientNxt) {
			// Retain admitted data, but do not consume an out-of-order FIN.
			// The cumulative ACK asks the peer to retransmit the missing range.
			b.queueFuture(flow, seq, payload)
			b.sendCloseACKLocked(flow)
			return nil
		}
		if len(payload) > 0 {
			if flow.conn == nil {
				if !b.reservePending(flow, len(payload)) {
					atomic.AddUint64(&b.pendDrop, 1)
					b.bufferDrops.Add(1)
					b.sendCloseACKLocked(flow)
					return nil
				}
				pending := make([]byte, len(payload))
				copy(pending, payload)
				flow.pending = append(flow.pending, pending)
				flow.pendingBytes += len(payload)
				atomic.AddUint64(&b.pendEnq, 1)
			} else {
				n, err := writeTCP(flow.conn, payload)
				if err != nil {
					b.abortBufferedFlowLocked(flow)
					return fmt.Errorf("tcp: write: %w", err)
				}
				atomic.AddUint64(&b.metrics.BytesSent, uint64(n))
				atomic.AddUint64(&b.metrics.PacketsSent, 1)
			}
			flow.clientNxt += uint32(len(payload))
			if !flow.closeDeadline.IsZero() {
				b.beginCloseLocked(flow, time.Now())
			}
			// Data buffered beyond an in-order FIN is outside the stream.
			if flags&fFIN == 0 {
				if err := b.flushReassembly(flow); err != nil {
					b.abortBufferedFlowLocked(flow)
					return fmt.Errorf("tcp: write (reassembly): %w", err)
				}
			}
			b.scheduleAck(flow)
		}
		if flags&fFIN != 0 && finSeq == flow.clientNxt {
			return b.receiveFINLocked(flow, time.Now())
		}
		return nil
	default:
		return nil
	}
}

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
func (b *tcpBridge) removeFlow(key string) {
	b.mu.RLock()
	f := b.flows[key]
	b.mu.RUnlock()
	if f == nil {
		return
	}
	b.removeFlowIf(f, nil)
}

// removeFlowIf acts on the observed identity, never a later tuple replacement.
// The predicate runs under stateMu so expiry/health checks cannot race progress.
func (b *tcpBridge) removeFlowIf(f *tcpFlow, predicate func(*tcpFlow) bool) bool {
	f.stateMu.Lock()
	defer f.stateMu.Unlock()
	b.mu.RLock()
	current := b.flows[f.key] == f
	b.mu.RUnlock()
	if !current || f.closed || (predicate != nil && !predicate(f)) {
		return false
	}
	b.removeFlowLocked(f)
	return true
}

// removeFlowLocked requires stateMu; removal is conditional on identity so an
// old reader cannot remove a replacement connection with the same tuple.
func (b *tcpBridge) removeFlowLocked(f *tcpFlow) {
	if f.closed {
		return
	}
	b.mu.Lock()
	if b.flows[f.key] == f {
		delete(b.flows, f.key)
	}
	b.mu.Unlock()
	f.closed = true
	f.state = tcpClosed
	if f.cancelDial != nil {
		f.cancelDial()
	}
	b.buffers.release(f.pendingBytes + f.futureBytes + f.txBytes + (len(f.pending)+len(f.ooo)+len(f.txQueue))*bufferEntryAllowance)
	f.pending = nil
	f.ooo = nil
	f.txQueue = nil
	f.pendingBytes = 0
	f.futureBytes = 0
	f.txBytes = 0
	if f.conn != nil {
		_ = f.conn.Close()
	}
	if f.rtoStop != nil {
		close(f.rtoStop)
	}
	b.rtoMu.Lock()
	if b.rtoActiveFlows[f.key] == f {
		delete(b.rtoActiveFlows, f.key)
	}
	b.rtoMu.Unlock()
	atomic.AddUint64(&b.metrics.ConnectionsClosed, 1)
	atomic.AddUint64(&b.parent.metrics.ConnectionsClosed, 1)
}

func (b *tcpBridge) reaper() {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-b.stopCh:
			return
		case <-t.C:
			cutoff := time.Now().Add(-b.lifetime)
			b.expireFlows(cutoff)
		}
	}
}

// expireFlows rechecks liveness under flow state after registry observation.
func (b *tcpBridge) expireFlows(cutoff time.Time) {
	for _, f := range b.flowSnapshot() {
		if f.lastActive().Before(cutoff) {
			b.removeFlowIf(f, func(f *tcpFlow) bool { return f.closeDeadline.IsZero() && f.lastActive().Before(cutoff) })
		}
	}
}

// scheduleAck schedules a delayed ACK for the given flow if one isn't already scheduled.
// Caller holds stateMu. All timer work is owned by the bridge.
func (b *tcpBridge) scheduleAck(f *tcpFlow) {
	if f.ackScheduled || f.closed {
		return
	}
	f.ackScheduled = true
	if !b.launch(func() {
		timer := time.NewTimer(b.ackDelay)
		defer timer.Stop()
		select {
		case <-f.rtoStop:
			return
		case <-b.stopCh:
			return
		case <-timer.C:
		}
		f.stateMu.Lock()
		defer f.stateMu.Unlock()
		f.ackScheduled = false
		if f.closed {
			return
		}
		ack := b.buildIPv4TCP(f.dstIP, f.srcIP, f.dstPort, f.srcPort, f.serverNxt, f.clientNxt, 0x10, nil)
		_ = b.sendToGuest(f, ack)
	}) {
		f.ackScheduled = false
	}
}

func (f *tcpFlow) touch() {
	f.lastMu.Lock()
	f.lastActivity = time.Now()
	f.lastMu.Unlock()
}

func (f *tcpFlow) lastActive() time.Time {
	f.lastMu.Lock()
	defer f.lastMu.Unlock()
	return f.lastActivity
}

// buildIPv4TCP builds an IPv4+TCP packet with given sequence/ack and flags.
func buildIPv4TCP(srcIP, dstIP [4]byte, srcPort, dstPort uint16, seq, ack uint32, flags byte, payload []byte) []byte {
	return buildIPv4TCPOptsWith(srcIP, dstIP, srcPort, dstPort, seq, ack, flags, payload, nil, 0x00, 64)
}

// buildIPv4TCPOpts allows specifying TCP options (must be padded to 4-byte multiple).
func buildIPv4TCPOpts(srcIP, dstIP [4]byte, srcPort, dstPort uint16, seq, ack uint32, flags byte, payload []byte, options []byte) []byte {
	return buildIPv4TCPOptsWith(srcIP, dstIP, srcPort, dstPort, seq, ack, flags, payload, options, 0x00, 64)
}

// buildIPv4TCPWithIP allows specifying IP TOS/TTL without options.
func buildIPv4TCPWithIP(srcIP, dstIP [4]byte, srcPort, dstPort uint16, seq, ack uint32, flags byte, payload []byte, tos byte, ttl byte) []byte {
	return buildIPv4TCPOptsWith(srcIP, dstIP, srcPort, dstPort, seq, ack, flags, payload, nil, tos, ttl)
}

// buildIPv4TCPOptsWith allows specifying both options and IP TOS/TTL.
func buildIPv4TCPOptsWith(srcIP, dstIP [4]byte, srcPort, dstPort uint16, seq, ack uint32, flags byte, payload []byte, options []byte, tos byte, ttl byte) []byte {
	ihl := 20
	thl := 20 + ((len(options) + 3) &^ 3)
	total := ihl + thl + len(payload)
	pkt := bufMaybePool(total)

	// IPv4 header
	pkt[0] = 0x45
	pkt[1] = tos
	pkt[2] = byte(total >> 8)
	pkt[3] = byte(total & 0xff)
	// Identification: incrementing ID to avoid zero-ID issues on some paths
	id := nextIPID()
	pkt[4] = byte(id >> 8)
	pkt[5] = byte(id)
	pkt[6], pkt[7] = 0, 0
	pkt[8] = ttl
	pkt[9] = 6
	copy(pkt[12:16], srcIP[:])
	copy(pkt[16:20], dstIP[:])
	ipcs := calculateChecksum(pkt[:20])
	pkt[10] = byte(ipcs >> 8)
	pkt[11] = byte(ipcs & 0xff)

	// TCP header
	off := 20
	binary.BigEndian.PutUint16(pkt[off:off+2], srcPort)
	binary.BigEndian.PutUint16(pkt[off+2:off+4], dstPort)
	binary.BigEndian.PutUint32(pkt[off+4:off+8], seq)
	binary.BigEndian.PutUint32(pkt[off+8:off+12], ack)
	pkt[off+12] = byte((thl / 4) << 4) // data offset
	pkt[off+13] = flags
	// Window size: choose a large default
	pkt[off+14] = 0xff
	pkt[off+15] = 0xff
	// Checksum later
	// Urgent pointer = 0
	// Options
	copy(pkt[off+20:off+20+len(options)], options)
	copy(pkt[off+thl:], payload)

	// TCP checksum with pseudo-header
	csum := tcpChecksum(pkt[off:off+thl+len(payload)], srcIP, dstIP)
	binary.BigEndian.PutUint16(pkt[off+16:off+18], csum)
	return pkt
}

func tcpChecksum(tcp []byte, srcIP, dstIP [4]byte) uint16 {
	sum := uint32(0)
	var pseudo [12]byte
	copy(pseudo[0:4], srcIP[:])
	copy(pseudo[4:8], dstIP[:])
	pseudo[8] = 0
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcp)))
	for i := 0; i < len(pseudo); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pseudo[i : i+2]))
	}
	for i := 0; i+1 < len(tcp); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(tcp[i : i+2]))
	}
	if len(tcp)%2 == 1 {
		sum += uint32(uint16(tcp[len(tcp)-1]) << 8)
	}
	for (sum >> 16) != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// ordered is a minimal constraint for types that support < and > comparisons
// used by the generic min/max helpers below. We keep it local to avoid an
// external dependency on x/exp/constraints.
// Local typed helpers (avoid generics to keep compatibility with older toolchains)
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
func minU32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}
func maxU32(a, b uint32) uint32 {
	if a > b {
		return a
	}
	return b
}
func minDur(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
func maxDur(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

// --- SACK helpers ---

func parseSACKBlocks(f *tcpFlow, opts []byte) {
	f.sackMu.Lock()
	defer f.sackMu.Unlock()
	// Collect blocks
	blocks := make([]struct{ left, right uint32 }, 0, 4)
	for i := 0; i < len(opts); {
		kind := opts[i]
		if kind == 0 {
			break
		}
		if kind == 1 {
			i++
			continue
		}
		if i+1 >= len(opts) {
			break
		}
		l := int(opts[i+1])
		if l < 2 || i+l > len(opts) {
			break
		}
		if kind == 5 && (l-2)%8 == 0 { // SACK
			for j := i + 2; j+7 < i+l; j += 8 {
				left := binary.BigEndian.Uint32(opts[j : j+4])
				right := binary.BigEndian.Uint32(opts[j+4 : j+8])
				if right > left {
					blocks = append(blocks, struct{ left, right uint32 }{left, right})
				}
			}
		}
		i += l
	}
	if len(blocks) == 0 {
		return
	}
	// Merge with existing, normalize and cap size
	all := append([]struct{ left, right uint32 }{}, f.sackList...)
	all = append(all, blocks...)
	// sort by left (simple insertion sort for small N)
	for i := 1; i < len(all); i++ {
		j := i
		for j > 0 && all[j-1].left > all[j].left {
			all[j-1], all[j] = all[j], all[j-1]
			j--
		}
	}
	// merge overlaps
	merged := make([]struct{ left, right uint32 }, 0, len(all))
	for _, b := range all {
		if len(merged) == 0 || b.left > merged[len(merged)-1].right {
			merged = append(merged, b)
		} else if b.right > merged[len(merged)-1].right {
			merged[len(merged)-1].right = b.right
		}
	}
	// cap to last 4 blocks to match typical SACK cache sizes
	if len(merged) > 4 {
		merged = merged[len(merged)-4:]
	}
	f.sackList = merged
}

func isSACKed(f *tcpFlow, left, right uint32) bool {
	f.sackMu.Lock()
	list := append([]struct{ left, right uint32 }{}, f.sackList...)
	f.sackMu.Unlock()
	for _, b := range list {
		if left >= b.left && right <= b.right {
			return true
		}
	}
	return false
}

// --- RFC 6675 simplified helpers ---

func (b *tcpBridge) retransmitNextHole(f *tcpFlow) {
	// Compute pipe (bytes in flight not SACKed)
	f.txMu.Lock()
	inFlight := 0
	for _, s := range f.txQueue {
		if s.seq+uint32(len(s.data)) <= f.sndUna {
			continue
		}
		if isSACKed(f, s.seq, s.seq+uint32(len(s.data))) {
			continue
		}
		inFlight += len(s.data)
	}
	f.pipeBytes = inFlight
	cw := b.cwndBytes(f)
	budget := cw - inFlight
	if budget < 1 {
		f.txMu.Unlock()
		return
	}
	// Find first unsacked, unacked hole segment
	idx := -1
	for i := 0; i < len(f.txQueue); i++ {
		s := f.txQueue[i]
		if s.seq+uint32(len(s.data)) <= f.sndUna {
			continue
		}
		if isSACKed(f, s.seq, s.seq+uint32(len(s.data))) {
			continue
		}
		idx = i
		break
	}
	if idx < 0 {
		f.txMu.Unlock()
		return
	}
	seg := f.txQueue[idx]
	// Mark retransmit
	f.txQueue[idx].sentAt = time.Now()
	f.txQueue[idx].retries++
	f.txQueue[idx].rtx = true
	f.txMu.Unlock()

	tosOut, ttlOut := f.tos, f.ttl
	if b.parent != nil {
		tosOut, ttlOut = b.parent.effTosTTL(f.tos, f.ttl)
	}
	pkt := b.buildIPv4TCPWithIP(f.dstIP, f.srcIP, f.dstPort, f.srcPort,
		seg.seq, f.clientNxt, 0x18, seg.data, tosOut, ttlOut)
	if pkt != nil {
		_ = b.sendToGuest(f, pkt)
		if f.ccEnabled && f.cc != nil {
			f.cc.OnLoss(false)
		}
	}
}

func (b *tcpBridge) cwndBytes(f *tcpFlow) int {
	if f.ccEnabled && f.cc != nil {
		cw := f.cc.Cwnd()
		if cw < f.mss {
			cw = f.mss
		}
		return cw
	}
	// Fallback to peer's advertised window when CC is disabled
	if f.advWnd > 0 {
		return int(f.advWnd)
	}
	return 65535
}

// logSendGated emits a throttled message about send gating. To avoid
// log spam, it logs at most once per 5 seconds per flow and includes the number of
// suppressed messages since the previous emission.
func (b *tcpBridge) logSendGated(f *tcpFlow, cause string, advWnd, inFlight, cw int) {
	if b.gateLogDisabled {
		return
	}
	const gateEvery = 5 * time.Second // Increased from 200ms to reduce log volume
	now := time.Now()
	f.gateMu.Lock()
	defer f.gateMu.Unlock()
	if !f.lastGateLog.IsZero() && now.Sub(f.lastGateLog) < gateEvery {
		f.suppressedGates++
		return
	}

	if f.suppressedGates > 0 {
		if b.gateLogDebug {
			logging.Debugf("TCP send-gated: flow=%s cause=%s advWnd=%d inflight=%d cwnd=%d (suppressed=%d)",
				f.key, cause, advWnd, inFlight, cw, f.suppressedGates)
		} else {
			logging.Infof("TCP send-gated: flow=%s cause=%s advWnd=%d inflight=%d cwnd=%d (suppressed=%d)",
				f.key, cause, advWnd, inFlight, cw, f.suppressedGates)
		}
	} else {
		if b.gateLogDebug {
			logging.Debugf("TCP send-gated: flow=%s cause=%s advWnd=%d inflight=%d cwnd=%d",
				f.key, cause, advWnd, inFlight, cw)
		} else {
			logging.Infof("TCP send-gated: flow=%s cause=%s advWnd=%d inflight=%d cwnd=%d",
				f.key, cause, advWnd, inFlight, cw)
		}
	}
	f.lastGateLog = now
	f.suppressedGates = 0
}

// trackRTOFlow adds a flow to the RTO tracking map and checks if we need to dump metrics
func (b *tcpBridge) trackRTOFlow(f *tcpFlow) {
	f.stateMu.Lock()
	b.mu.RLock()
	current := b.flows[f.key] == f
	b.mu.RUnlock()
	if f.closed || !current {
		f.stateMu.Unlock()
		return
	}
	// Decide whether a dump is needed without holding the lock during the dump
	needDump := false
	b.rtoMu.Lock()
	// Add this flow to the active RTO flows map
	b.rtoActiveFlows[f.key] = f
	if len(b.rtoActiveFlows) >= 3 {
		if !b.rtoMetricsDumped || time.Since(b.rtoMetricsDumpTime) > 30*time.Second {
			// Mark as dumped and record time under lock
			b.rtoMetricsDumped = true
			b.rtoMetricsDumpTime = time.Now()
			needDump = true
			// Own the reset timer so bridge shutdown joins all diagnostics.
			b.launch(func() {
				timer := time.NewTimer(10 * time.Second)
				defer timer.Stop()
				select {
				case <-b.stopCh:
					return
				case <-timer.C:
				}
				b.rtoMu.Lock()
				b.rtoMetricsDumped = false
				b.rtoActiveFlows = make(map[string]*tcpFlow)
				b.rtoMu.Unlock()
			})
		}
	}
	b.rtoMu.Unlock()
	f.stateMu.Unlock()
	if needDump {
		b.dumpDetailedMetrics()
	}
}

// dumpDetailedMetrics logs detailed system metrics when multiple flows are in RTO state
// This function is designed to be robust against errors and always complete the metrics dump
func (b *tcpBridge) dumpDetailedMetrics() {
	// Snapshot registry membership first; never lock flow state under b.mu.
	for _, f := range b.flowSnapshot() {
		f.stateMu.Lock()
		logging.Warnf("TCP flow=%s inflight=%d window=%d rto=%v closed=%v",
			f.key, f.serverNxt-f.sndUna, f.advWnd, f.rto, f.closed)
		f.stateMu.Unlock()
	}
}

// getMaxRetries returns the maximum retry count for any segment in the flow's txQueue
func (b *tcpBridge) getMaxRetries(f *tcpFlow) int {
	f.txMu.Lock()
	defer f.txMu.Unlock()

	maxRetries := 0
	for _, seg := range f.txQueue {
		if seg.retries > maxRetries {
			maxRetries = seg.retries
		}
	}
	return maxRetries
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
