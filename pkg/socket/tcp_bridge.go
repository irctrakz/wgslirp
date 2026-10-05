package socket

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"sync/atomic"

	"github.com/irctrakz/wgslirp/pkg/core"
	"github.com/irctrakz/wgslirp/pkg/logging"
)

// TCP slirp bridge for host networking.
//
// Overview (independent of the application protocol):
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
//   * Reader waits for ACK/window progress when send allowances are exhausted.
//   * Retained payloads are charged to per-flow and aggregate buffer limits.
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
	}
	dupAckCnt int
	// RTT/RTO estimation (RFC 6298)
	srtt    time.Duration
	rttvar  time.Duration
	rto     time.Duration
	rtoStop chan struct{}

	// Notify sender when ACK/window updates arrive.
	ackCh chan struct{}

	// SACK loss recovery (RFC 6675 simplified)
	sackRecovery bool
	recover      uint32

	// SACK support
	sackPermitted bool
	// scoreboard of SACKed ranges (left,right), normalized and compacted
	sackMu   sync.Mutex
	sackList []struct {
		left  uint32
		right uint32
	}

	// Congestion control (server->guest)
	cc  congestionControl // nil when congestion control is disabled
	mss int
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

	segment, err := parseTCPSegment(pkt)
	if err != nil {
		return err
	}
	if segment.flags&fRST != 0 {
		b.removeFlow(segment.key)
		return nil
	}
	flow := b.lookupFlow(segment.key)

	if flow == nil && segment.flags&fSYN != 0 && segment.flags&fACK == 0 {
		return b.establishTCP(segment)
	}
	return b.handleTCPFlow(flow, segment)
}

// Typed bounds used by transport buffering and retransmission timing.
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
func minDur(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
