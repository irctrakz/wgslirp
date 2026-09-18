package socket

import (
	"context"
	"encoding/binary"
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
				if seqAfter(right, left) {
					blocks = append(blocks, struct{ left, right uint32 }{left, right})
				}
			}
		}
		i += l
	}
	// Merge only ranges inside the outstanding send window. Offsets from
	// sndUna are ordered even when the actual sequence numbers wrap. Drop
	// acknowledged/stale blocks on every ACK so they cannot survive a full lap.
	// Caller holds stateMu; TCP windows are smaller than half the sequence space.
	// Merge with existing, normalize and cap size
	all := append([]struct{ left, right uint32 }{}, f.sackList...)
	all = append(all, blocks...)
	valid := all[:0]
	for _, block := range all {
		if !seqAfter(block.right, f.sndUna) || seqAfter(block.right, f.serverNxt) {
			continue
		}
		if seqBefore(block.left, f.sndUna) {
			block.left = f.sndUna
		}
		if !seqBefore(block.left, block.right) {
			continue
		}
		valid = append(valid, block)
	}
	all = valid
	// sort by left (simple insertion sort for small N)
	for i := 1; i < len(all); i++ {
		j := i
		for j > 0 && all[j-1].left-f.sndUna > all[j].left-f.sndUna {
			all[j-1], all[j] = all[j], all[j-1]
			j--
		}
	}
	// merge overlaps
	merged := make([]struct{ left, right uint32 }, 0, len(all))
	for _, b := range all {
		if len(merged) == 0 || seqAfter(b.left, merged[len(merged)-1].right) {
			merged = append(merged, b)
		} else if seqAfter(b.right, merged[len(merged)-1].right) {
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
		if seqBefore(left, right) && !seqBefore(left, b.left) && !seqAfter(right, b.right) {
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
		if !seqAfter(s.seq+uint32(len(s.data)), f.sndUna) {
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
		if !seqAfter(s.seq+uint32(len(s.data)), f.sndUna) {
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
