package socket

import (
	"context"
	"errors"
	"fmt"
	"github.com/irctrakz/wgslirp/internal/packetwire"
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
	failureLog        logging.RateLimiter
	admission         admissionCounters
	oversizedAccepted atomic.Uint64
	localSizeRejected atomic.Uint64
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
	// Immutable after Start; Close interrupts I/O before Stop joins accepted work.
	dgram *icmpDatagram

	// Control
	mu       sync.Mutex
	running  bool
	stopped  bool
	stopDone chan struct{}
	stopCh   chan struct{}
	wg       sync.WaitGroup

	// Slirp bridges
	udp       *udpBridge
	tcp       *tcpBridge
	icmp      *icmpBridge
	fragments *ipv4Fragments // assigned during Start, immutable until joined shutdown

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
	_ = poolingPolicy()
	config = config.Effective()
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
		var conn *icmp.PacketConn
		conn, err = icmp.ListenPacket(protocol, "0.0.0.0")
		if err != nil {
			// Linux ping sockets permit echo without CAP_NET_RAW when the
			// process group is allowed by ping_group_range. Never change it here.
			conn, err = icmp.ListenPacket("udp4", "0.0.0.0")
			if err != nil {
				return fmt.Errorf("no raw or datagram ICMP socket available: %w", err)
			}
			s.dgram = newICMPDatagram(conn)
		} else {
			s.conn = conn
		}
	} else if strings.Contains(protocol, "tcp") || strings.Contains(protocol, "udp") {
		// TCP/UDP uses ordinary sockets. Optional echo uses only a ping socket,
		// even if the process happens to have raw-socket privileges.
		s.conn = nil
		if s.config.ICMPEcho {
			conn, echoErr := icmp.ListenPacket("udp4", "0.0.0.0")
			if echoErr != nil {
				return fmt.Errorf("ICMP_ECHO: guest ping unavailable: %w; permit the process group in the network namespace's net.ipv4.ping_group_range or set ICMP_ECHO=false for TCP/UDP-only operation", echoErr)
			}
			s.dgram = newICMPDatagram(conn)
		}
	} else {
		return fmt.Errorf("unsupported protocol: %s", protocol)
	}

	if err != nil {
		return fmt.Errorf("failed to create raw socket with protocol %s: %w", protocol, err)
	}

	if s.conn != nil {
		// Set a reasonable read deadline to prevent blocking indefinitely
		err = s.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		if err != nil {
			s.conn.Close()
			s.conn = nil
			return fmt.Errorf("failed to set read deadline: %w", err)
		}
	}

	var releaseRead func()
	if s.conn != nil || s.dgram != nil {
		releaseRead, err = s.ReservePacketBuffer(65536)
		if err != nil {
			if s.conn != nil {
				_ = s.conn.Close()
			}
			if s.dgram != nil {
				_ = s.dgram.conn.Close()
			}
			s.conn = nil
			s.dgram = nil
			return err
		}
	}
	s.running = true
	if s.conn != nil {
		s.wg.Add(1)
		go s.listenLoop(releaseRead)
	} else if s.dgram != nil {
		s.wg.Add(1)
		go s.dgram.listen(s, releaseRead)
	}

	// Initialize UDP/TCP slirp bridges
	s.tosCopy = s.config.Transport.CopyTOS
	s.ttlOverride = s.config.Transport.TTL
	s.udp = newUDPBridge(s)
	s.tcp = newTCPBridge(s)
	s.icmp = newICMPBridge(s)
	if s.config.IPv4Reassembly {
		s.fragments = newIPv4Fragments(s.buffers(), s.config.IPv4FragmentBufferCapBytes)
		s.wg.Add(1)
		go s.maintainIPv4Fragments()
	}
	s.udp.start()
	s.tcp.start()

	// No egress limiter configuration

	logging.Debugf("Socket interface started with IP: %s", s.config.IPAddress)
	return nil
}

// Stop requests shutdown and joins all accepted work. Call RequestStop from
// a delivery callback; waiting here inside that callback would join itself.
func (s *SocketInterface) Stop() error { return s.StopContext(context.Background()) }

// StopContext bounds the caller's wait, not the lifetime of accepted callbacks.
// On timeout cleanup continues; RequestStop's channel closes only after joining.
func (s *SocketInterface) StopContext(ctx context.Context) error {
	done := s.RequestStop()
	select {
	case <-done:
		return nil
	default:
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// RequestStop closes admission synchronously and starts exactly one finalizer.
// It is safe inside a delivery callback provided the callback does not wait for
// the returned completion channel (which includes that callback's return).
func (s *SocketInterface) RequestStop() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return s.stopDone
	}
	s.stopped = true
	s.running = false
	s.stopDone = make(chan struct{})
	if s.stopCh != nil {
		close(s.stopCh)
	}
	conn, dgram, udp, tcp := s.conn, s.dgram, s.udp, s.tcp
	go func() {
		if conn != nil {
			_ = conn.Close()
		}
		if dgram != nil {
			_ = dgram.conn.Close()
		}
		// Signal both bridges before joining either callback domain.
		if tcp != nil {
			tcp.requestStop()
		}
		if udp != nil {
			udp.requestStop()
		}
		if tcp != nil {
			tcp.stop()
		}
		if udp != nil {
			udp.stop()
		}
		s.wg.Wait()
		if s.fragments != nil {
			s.fragments.close()
		}
		if dgram != nil {
			dgram.clear()
		}
		close(s.stopDone)
	}()
	return s.stopDone
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

	data := core.BorrowPacketData(packet)
	original := data
	var err error
	if s.fragments != nil {
		var release func()
		data, release, err = s.fragments.add(data, time.Now())
		if release != nil {
			defer release()
		}
		if err == nil && data == nil {
			s.recordAcceptedPacketSize(int(original[2])<<8 | int(original[3]))
			return nil
		}
	} else {
		data, _, err = parseIPv4(data)
	}
	if err != nil {
		atomic.AddUint64(&s.metrics.Errors, 1)
		return err
	}
	// Validated original IP length excludes padding and reassembled size.
	wireSize := int(original[2])<<8 | int(original[3])

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
			return s.outboundPacketError("ICMP", wireSize, err)
		}
	case 6: // TCP protocol
		if s.tcp == nil {
			atomic.AddUint64(&s.metrics.Errors, 1)
			return fmt.Errorf("TCP bridge not initialized")
		}
		if err := s.tcp.HandleOutbound(data); err != nil {
			return s.outboundPacketError("TCP", wireSize, err)
		}
		break
	case 17: // UDP protocol
		// Use UDP slirp bridge to forward payloads
		if s.udp == nil {
			atomic.AddUint64(&s.metrics.Errors, 1)
			return fmt.Errorf("UDP bridge not initialized")
		}
		if err := s.udp.HandleOutbound(data); err != nil {
			return s.outboundPacketError("UDP", wireSize, err)
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
	s.recordAcceptedPacketSize(wireSize)
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
	udp, tcp, processor, fragments := s.udp, s.tcp, s.processor, s.fragments
	s.mu.Unlock()
	dm := SocketDetailedMetrics{
		Total:      loadSocketMetrics(&s.metrics),
		Admission:  s.admissionSnapshot(),
		PacketSize: map[string]uint64{"accepted_oversized": s.oversizedAccepted.Load(), "local_size_rejected": s.localSizeRejected.Load()},
	}
	if fragments != nil {
		dm.IPv4Fragments = fragments.snapshot()
	}
	if udp != nil {
		udp.flowsMu.Lock()
		active := uint64(len(udp.flows))
		udp.flowsMu.Unlock()
		dm.UDP.DeliveryRefused = udp.deliveryRefused.Load()
		dm.UDP.Counters = loadSocketMetrics(&udp.metrics)
		dm.UDP.ActiveFlows = active
		// Add UDP debug counters
		enq, proc := udp.txEnqueued.Load(), udp.txProcessed.Load()
		dm.UDPExt = map[string]uint64{"tx_enq": enq, "tx_proc": proc}
	}
	if tcp != nil {
		dm.TCP, dm.TCPExt = tcp.snapshotMetrics()
	}
	// FlowManager and egress limiter removed
	// Fallback removed
	// Include processor metrics if available
	if processor != nil {
		if m, ok := processor.(interface{ Metrics() map[string]uint64 }); ok {
			dm.Processor = make(map[string]uint64)
			for k, v := range m.Metrics() {
				dm.Processor[k] = v
			}
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

	count := 0
	for _, f := range tcp.flowSnapshot() {
		if tcp.removeFlowIf(f, nil) {
			count++
		}
	}
	return count
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

	tcp.rtoMu.Lock()
	flows := make([]*tcpFlow, 0, len(tcp.rtoActiveFlows))
	for _, f := range tcp.rtoActiveFlows {
		flows = append(flows, f)
	}
	tcp.rtoMu.Unlock()
	count := 0
	for _, f := range flows {
		if tcp.removeFlowIf(f, nil) {
			count++
		}
	}
	return count
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
				if errors.Is(err, net.ErrClosed) {
					return
				}
				if s.failureLog.Allow(time.Now()) {
					logging.Errorf("Failed to reset read deadline: %v", err)
				}
				atomic.AddUint64(&s.metrics.Errors, 1)
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
				if errors.Is(err, net.ErrClosed) {
					return
				}
				if s.failureLog.Allow(time.Now()) {
					logging.Errorf("Failed to read from socket: %v", err)
				}
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
func calculateChecksum(data []byte) uint16 { return packetwire.Checksum(data) }

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
		var src, dst [4]byte
		copy(src[:], peerIP.To4())
		copy(dst[:], myIP.To4())
		packetwire.IPv4Header(out, src, dst, 1, 0, 64, nextIPID(), 0)
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
