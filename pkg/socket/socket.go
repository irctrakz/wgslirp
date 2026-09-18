package socket

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/irctrakz/wgslirp/pkg/core"
	"github.com/irctrakz/wgslirp/pkg/logging"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// SocketInterface represents a socket interface for connecting to the host network
// It implements the core.SocketInterface interface and the SocketWriter interface
type SocketInterface struct {
	// Configuration
	config       Config
	budgetOnce   sync.Once
	bufferBudget *resourceBudget

	// Packet processor for handling packets from the socket
	processor core.PacketProcessor

	// Metrics
	metrics core.SocketMetrics

	// Raw socket connection
	conn net.PacketConn

	// Control
	mu       sync.Mutex
	running  bool
	stopped  bool
	stopDone chan struct{}
	stopCh   chan struct{}
	wg       sync.WaitGroup

	// Slirp bridges
	udp  *udpBridge
	tcp  *tcpBridge
	icmp *icmpBridge

	// (FlowManager and egress limiter removed)

	// Effective MTU override for synthesized packets (TCP seg/UDP frags).
	// If <=0, falls back to config.MTU. Allows runtime fallback under trouble.
	mtuOverride int32

	// (historical fields removed)

	// IP header synthesis options
	tosCopy     bool // if true, preserve DSCP/ECN from origin; else set to 0
	ttlOverride int  // if >0, use this TTL; else use default 64
}

// Ensure SocketInterface implements SocketWriter
var _ SocketWriter = (*SocketInterface)(nil)

// NewSocketInterface creates a new socket interface
func NewSocketInterface(config Config) *SocketInterface {
	transport := config.transportConfig()
	config.Transport = &transport
	return &SocketInterface{
		config:  config,
		metrics: core.SocketMetrics{},
		stopCh:  make(chan struct{}),
	}
}

// Start starts the socket interface
func (s *SocketInterface) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.stopped {
		return fmt.Errorf("socket interface stopped; create a new instance")
	}
	if s.running {
		return fmt.Errorf("socket interface already running")
	}

	if s.processor == nil {
		return fmt.Errorf("no packet processor set")
	}
	if err := s.config.Validate(); err != nil {
		return fmt.Errorf("socket config: %w", err)
	}

	// Create a raw socket based on the protocol specified in the config
	var err error
	protocol := "ip4:icmp" // Default to ICMP

	// If a specific protocol is specified in the config, use it
	if s.config.Protocol != "" {
		protocol = s.config.Protocol
	}

	logging.Debugf("Creating raw socket with protocol: %s", protocol)

	// Create the appropriate socket based on the protocol
	if strings.Contains(protocol, "icmp") {
		// For ICMP, use the icmp package. This works in privileged mode ("ip4:icmp").
		s.conn, err = icmp.ListenPacket(protocol, "0.0.0.0") // Bind to all interfaces
		if err != nil {
			return fmt.Errorf("failed to create raw socket with protocol %s: %v", protocol, err)
		}
	} else if strings.Contains(protocol, "tcp") || strings.Contains(protocol, "udp") {
		// Slirp modes don't require a raw socket listener. We'll rely on bridges (tcp/udp) only.
		s.conn = nil
	} else {
		return fmt.Errorf("unsupported protocol: %s", protocol)
	}

	if err != nil {
		return fmt.Errorf("failed to create raw socket with protocol %s: %v", protocol, err)
	}

	if s.conn != nil {
		// Set a reasonable read deadline to prevent blocking indefinitely
		err = s.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		if err != nil {
			s.conn.Close()
			s.conn = nil
			return fmt.Errorf("failed to set read deadline: %v", err)
		}
	}

	var releaseRead func()
	if s.conn != nil {
		releaseRead, err = s.ReservePacketBuffer(65536)
		if err != nil {
			_ = s.conn.Close()
			s.conn = nil
			return err
		}
	}
	s.running = true
	if s.conn != nil {
		s.wg.Add(1)
		go s.listenLoop(releaseRead)
	}

	// SIMPLE_MODE bypasses FlowManager and egress limiter to reduce moving parts
	logging.Infof("Simple mode active: bypassing FlowManager and egress limiter; inline delivery to processor")

	// Initialize UDP/TCP slirp bridges
	s.tosCopy = s.config.Transport.CopyTOS
	s.ttlOverride = s.config.Transport.TTL
	s.udp = newUDPBridge(s)
	s.tcp = newTCPBridge(s)
	s.icmp = newICMPBridge(s)

	// No egress limiter configuration

	logging.Debugf("Socket interface started with IP: %s", s.config.IPAddress)
	return nil
}

// Stop stops the socket interface
func (s *SocketInterface) Stop() error {
	s.mu.Lock()
	if s.stopped {
		done := s.stopDone
		s.mu.Unlock()
		<-done
		return nil
	}
	s.stopped = true
	s.running = false
	s.stopDone = make(chan struct{})
	if s.stopCh != nil {
		close(s.stopCh)
	}
	conn, udp, tcp := s.conn, s.udp, s.tcp
	s.mu.Unlock()
	// Close descriptors before joining blocked readers. Bridge pointers remain
	// stable after startup so concurrent snapshots never observe torn teardown.
	if conn != nil {
		_ = conn.Close()
	}
	if udp != nil {
		udp.stop()
	}
	if tcp != nil {
		tcp.stop()
	}
	s.wg.Wait()
	close(s.stopDone)
	return nil
}

// SetPacketProcessor configures delivery before Start. Runtime replacement is
// rejected because callbacks may own packet buffers and in-flight work.
func (s *SocketInterface) SetPacketProcessor(processor core.PacketProcessor) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running || s.stopped {
		logging.Warnf("Socket packet processor can only be configured before startup")
		return
	}
	s.processor = processor
}

// WritePacket writes a packet to the host network
func (s *SocketInterface) WritePacket(packet core.Packet) error {
	s.mu.Lock()
	running := s.running
	if running {
		s.wg.Add(1)
	}
	s.mu.Unlock()

	if !running {
		return fmt.Errorf("socket interface not running")
	}

	defer s.wg.Done()
	if packet == nil {
		return fmt.Errorf("nil packet")
	}

	data, _, err := parseIPv4(core.BorrowPacketData(packet))
	if err != nil {
		atomic.AddUint64(&s.metrics.Errors, 1)
		return err
	}
	// Check packet size against MTU
	if len(data) > s.config.MTU {
		logging.Warnf("Packet size %d exceeds MTU %d, packet will be fragmented", len(data), s.config.MTU)
	}

	// Extract IP header information for detailed logging
	if len(data) >= 20 {
		srcIP := fmt.Sprintf("%d.%d.%d.%d", data[12], data[13], data[14], data[15])
		dstIP := fmt.Sprintf("%d.%d.%d.%d", data[16], data[17], data[18], data[19])
		protocol := data[9]

		logging.Debugf("SOCKET OUTGOING: src=%s, dst=%s, proto=%d, len=%d",
			srcIP, dstIP, protocol, len(data))

		// Extract more details for ICMP packets
		if protocol == 1 { // ICMP
			ihl := int(data[0]&0x0f) * 4 // IP header length
			if len(data) >= ihl+8 {
				icmpType := data[ihl]
				icmpCode := data[ihl+1]
				icmpId := uint16(data[ihl+4])<<8 | uint16(data[ihl+5])
				icmpSeq := uint16(data[ihl+6])<<8 | uint16(data[ihl+7])

				logging.Debugf("SOCKET OUTGOING ICMP: type=%d, code=%d, id=%d, seq=%d",
					icmpType, icmpCode, icmpId, icmpSeq)
			}
		}
	}

	// Determine protocol number for handling
	protocol := data[9]

	// Handle different protocols
	switch protocol {
	case 1: // ICMP protocol
		// Route ICMP through a thin bridge so implementation is modular.

		if err := s.icmp.HandleOutbound(data); err != nil {
			atomic.AddUint64(&s.metrics.Errors, 1)
			return fmt.Errorf("ICMP slirp error: %w", err)
		}
	case 6: // TCP protocol
		if s.tcp == nil {
			atomic.AddUint64(&s.metrics.Errors, 1)
			return fmt.Errorf("TCP bridge not initialized")
		}
		if err := s.tcp.HandleOutbound(data); err != nil {
			atomic.AddUint64(&s.metrics.Errors, 1)
			return fmt.Errorf("TCP slirp error: %w", err)
		}
		break
	case 17: // UDP protocol
		// Use UDP slirp bridge to forward payloads
		if s.udp == nil {
			atomic.AddUint64(&s.metrics.Errors, 1)
			return fmt.Errorf("UDP bridge not initialized")
		}
		if err := s.udp.HandleOutbound(data); err != nil {
			atomic.AddUint64(&s.metrics.Errors, 1)
			return fmt.Errorf("UDP slirp error: %w", err)
		}
		// Metrics count the original packet bytes
		break
	case 2: // IGMP
		// Silently drop IGMP; not supported in slirp bridges. Avoid propagating
		// an error back to WireGuard which would log loudly. Count as an error
		// for visibility at most.
		logging.Debugf("dropping unsupported IGMP packet (len=%d)", len(data))
		atomic.AddUint64(&s.metrics.Errors, 1)
		return nil
	default:
		// Other unsupported protocols: drop quietly with a debug log.
		logging.Debugf("dropping packet with unsupported IP protocol=%d len=%d", protocol, len(data))
		atomic.AddUint64(&s.metrics.Errors, 1)
		return nil
	}

	// Update metrics
	atomic.AddUint64(&s.metrics.PacketsSent, 1)
	atomic.AddUint64(&s.metrics.BytesSent, uint64(len(data)))

	logging.Debugf("Sent packet of length %d to host network", len(data))
	return nil
}

// Metrics returns the metrics for the socket interface
func (s *SocketInterface) Metrics() core.SocketMetrics {
	return loadSocketMetrics(&s.metrics)
}

// SetTCPMSSClamp updates the TCP bridge MSS clamp at runtime.
func (s *SocketInterface) SetTCPMSSClamp(n int) {
	s.mu.Lock()
	tb := s.tcp
	s.mu.Unlock()
	if tb == nil {
		return
	}
	tb.SetMSSClamp(n)
}

// SetTCPPaceUS updates the TCP bridge per-segment pacing interval at runtime.
func (s *SocketInterface) SetTCPPaceUS(us int) {
	s.mu.Lock()
	tb := s.tcp
	s.mu.Unlock()
	if tb == nil {
		return
	}
	tb.SetPaceUS(us)
}

// effTosTTL computes the TOS/TTL to use for host->guest synthesized packets
// given the original values observed on the outbound path.
func (s *SocketInterface) effTosTTL(origTOS byte, origTTL byte) (byte, byte) {
	tos := byte(0x00)
	if s.tosCopy {
		tos = origTOS
	}
	ttl := byte(64)
	if s.ttlOverride > 0 {
		ttl = byte(s.ttlOverride)
	}
	return tos, ttl
}

// EffectiveMTU returns the MTU to use for segmentation/fragmentation.
func (s *SocketInterface) EffectiveMTU() int {
	o := atomic.LoadInt32(&s.mtuOverride)
	if o > 0 {
		return int(o)
	}
	return s.config.MTU
}

// SetEgressMTU sets a runtime MTU override for synthesized packets.
func (s *SocketInterface) SetEgressMTU(mtu int) {
	if mtu <= 0 {
		atomic.StoreInt32(&s.mtuOverride, 0)
	} else {
		atomic.StoreInt32(&s.mtuOverride, int32(mtu))
	}
	logging.Infof("Egress MTU override set to %d (0=disabled)", mtu)
}

// DetailedMetrics returns total and per-bridge metrics, including active flows.
func (s *SocketInterface) DetailedMetrics() SocketDetailedMetrics {
	s.mu.Lock()
	udp, tcp, processor := s.udp, s.tcp, s.processor
	s.mu.Unlock()
	dm := SocketDetailedMetrics{
		Total: loadSocketMetrics(&s.metrics),
	}
	if udp != nil {
		udp.flowsMu.Lock()
		active := uint64(len(udp.flows))
		udp.flowsMu.Unlock()
		dm.UDP.Counters = loadSocketMetrics(&udp.metrics)
		dm.UDP.ActiveFlows = active
		// Add UDP debug counters
		enq, proc := getUDPTxDebug()
		dm.UDPExt = map[string]uint64{"tx_enq": enq, "tx_proc": proc}
	}
	if tcp != nil {
		flows := tcp.flowSnapshot()
		active := uint64(len(flows))
		// Snapshot membership before taking individual flow locks.
		ackIdle := uint64(0)
		if tcp.ackIdleGate > 0 {
			for _, f := range flows {
				f.stateMu.Lock()
				inFlight := int(f.serverNxt - f.sndUna)
				minInflight := tcp.ackIdleMinInflight
				if minInflight <= 0 {
					minInflight = f.mss
				}
				if inFlight >= minInflight {
					if time.Since(f.lastAckTime) >= tcp.ackIdleGate {
						ackIdle++
					}
				}
				f.stateMu.Unlock()
			}
		}
		dm.TCP.Counters = loadSocketMetrics(&tcp.metrics)
		dm.TCP.ActiveFlows = active
		// TCP extra debug counters
		tcp.rtoMu.Lock()
		activeRTOFlows := uint64(len(tcp.rtoActiveFlows))
		tcp.rtoMu.Unlock()
		// Compose TCPExt with RTO and ACK classification counters
		dialUsed, dialPeak, dialLimit, dialRejected := tcp.dialSlots.snapshot()
		bufferUsed, bufferPeak, bufferLimit, bufferRejected := tcp.buffers.snapshot()
		dm.TCPExt = map[string]uint64{
			"dial_reserved":         dialUsed,
			"dial_peak":             dialPeak,
			"dial_limit":            dialLimit,
			"dial_refused":          dialRejected,
			"socket_buffer_bytes":   bufferUsed,
			"socket_buffer_peak":    bufferPeak,
			"socket_buffer_limit":   bufferLimit,
			"socket_buffer_refused": bufferRejected,
			"buffer_dropped":        tcp.bufferDrops.Load(),
			"rto":                   atomic.LoadUint64(&tcp.rtoCount),
			"active_rto_flows":      activeRTOFlows,
			"ack_advanced":          atomic.LoadUint64(&tcp.ackAdv),
			"ack_duplicate":         atomic.LoadUint64(&tcp.ackDup),
			"ack_window_update":     atomic.LoadUint64(&tcp.ackWndOnly),
			"ack_idle_flows":        ackIdle,
			// Async dial and pending-buffer instrumentation
			"dial_start":    atomic.LoadUint64(&tcp.dialStart),
			"dial_ok":       atomic.LoadUint64(&tcp.dialOk),
			"dial_fail":     atomic.LoadUint64(&tcp.dialFail),
			"dial_inflight": uint64(atomic.LoadInt64(&tcp.dialInflight)),
			"pend_enq":      atomic.LoadUint64(&tcp.pendEnq),
			"pend_flush":    atomic.LoadUint64(&tcp.pendFlush),
			"pend_drop":     atomic.LoadUint64(&tcp.pendDrop),
		}
	}
	// FlowManager and egress limiter removed
	// Fallback removed
	// Include processor metrics if available
	if processor != nil {
		if m, ok := processor.(interface{ Metrics() map[string]uint64 }); ok {
			dm.Processor = m.Metrics()
		}
	}
	return dm
}

// ResetAllTCPFlows resets all active TCP flows to clear any stalled connections.
// Returns the number of flows that were reset.
func (s *SocketInterface) ResetAllTCPFlows() int {
	s.mu.Lock()
	tcp := s.tcp
	s.mu.Unlock()

	if tcp == nil {
		return 0
	}

	// Get all flow keys
	tcp.mu.RLock()
	keys := make([]string, 0, len(tcp.flows))
	for k := range tcp.flows {
		keys = append(keys, k)
	}
	tcp.mu.RUnlock()

	// Reset each flow
	for _, k := range keys {
		tcp.removeFlow(k)
	}

	return len(keys)
}

// ResetRTOTCPFlows resets only TCP flows that are in the retransmit state.
// Returns the number of flows that were reset.
func (s *SocketInterface) ResetRTOTCPFlows() int {
	s.mu.Lock()
	tcp := s.tcp
	s.mu.Unlock()

	if tcp == nil {
		return 0
	}

	// Get RTO flow keys
	tcp.rtoMu.Lock()
	rtoKeys := make([]string, 0, len(tcp.rtoActiveFlows))
	for k := range tcp.rtoActiveFlows {
		rtoKeys = append(rtoKeys, k)
	}
	tcp.rtoMu.Unlock()

	// Reset only RTO flows
	for _, k := range rtoKeys {
		tcp.removeFlow(k)
	}

	return len(rtoKeys)
}

// listenLoop listens for packets from the host network
func (s *SocketInterface) listenLoop(releaseRead func()) {
	defer s.wg.Done()
	defer releaseRead()

	// Create a buffer for receiving packets
	buf := make([]byte, 65536) // Use a large buffer to accommodate jumbo frames

	// Keep track of our own IP address to filter out loopback packets
	myIP := net.ParseIP(s.config.IPAddress)
	if myIP == nil {
		logging.Errorf("Failed to parse socket IP address: %s", s.config.IPAddress)
		return
	}

	for {
		select {
		case <-s.stopCh:
			return
		default:
			// Reset read deadline to prevent permanent timeout
			err := s.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			if err != nil {
				logging.Errorf("Failed to reset read deadline: %v", err)
				time.Sleep(100 * time.Millisecond) // Avoid tight loop if errors persist
				continue
			}

			// Read a packet
			n, peer, err := s.conn.ReadFrom(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// This is just a timeout, not an error
					continue
				}
				logging.Errorf("Failed to read from socket: %v", err)
				atomic.AddUint64(&s.metrics.Errors, 1)
				time.Sleep(100 * time.Millisecond) // Avoid tight loop if errors persist
				continue
			}

			peerAddr, ok := peer.(*net.IPAddr)
			if !ok || peerAddr.IP.To4() == nil || peerAddr.IP.Equal(myIP) {
				continue
			}
			if err := s.processICMPReply(buf[:n], peerAddr.IP, myIP); err != nil {
				logging.Debugf("ICMP reply dropped: %v", err)
				atomic.AddUint64(&s.metrics.Errors, 1)
			}
		}
	}
}

// calculateChecksum calculates the Internet checksum for the given data
func calculateChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(^sum)
}

// processICMPReply accounts parser scratch and the synthesized reply separately.
func (s *SocketInterface) processICMPReply(body []byte, peerIP, myIP net.IP) error {
	if len(body) > 65515 {
		return fmt.Errorf("ICMP reply exceeds IPv4 length")
	}
	release, err := s.ReservePacketBuffer(len(body))
	if err != nil {
		return err
	}
	defer release()
	if _, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), body); err != nil {
		return err
	}
	packet := s.buffers().buildPacket(20+len(body), false, func() []byte {
		out := make([]byte, 20+len(body))
		out[0], out[8], out[9] = 0x45, 64, 1
		total := len(out)
		out[2], out[3] = byte(total>>8), byte(total)
		id := nextIPID()
		out[4], out[5] = byte(id>>8), byte(id)
		copy(out[12:16], peerIP.To4())
		copy(out[16:20], myIP.To4())
		checksum := calculateChecksum(out[:20])
		out[10], out[11] = byte(checksum>>8), byte(checksum)
		copy(out[20:], body)
		return out
	})
	if packet == nil {
		return ErrBufferLimit
	}
	size := packet.Length()
	if !deliverPacket(s.processor, packet) {
		return fmt.Errorf("ICMP reply delivery rejected")
	}
	atomic.AddUint64(&s.metrics.PacketsReceived, 1)
	atomic.AddUint64(&s.metrics.BytesReceived, uint64(size))
	return nil
}
