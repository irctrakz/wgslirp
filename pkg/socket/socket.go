package socket

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"strconv"

	"github.com/irctrakz/wgslirp/pkg/core"
	"github.com/irctrakz/wgslirp/pkg/logging"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// SocketInterface represents a socket interface for connecting to the host network
// It implements the core.SocketInterface interface and the SocketWriter interface
type SocketInterface struct {
	// Configuration
	config Config

	// Packet processor for handling packets from the socket
	processor core.PacketProcessor

	// Metrics
	metrics core.SocketMetrics

	// Raw socket connection
	conn net.PacketConn

	// Datagram socket FD for ICMP when raw socket unavailable (ping_group_range)
	dgramFd int

	// Control
	mu      sync.Mutex
	running bool
	stopCh  chan struct{}
	wg      sync.WaitGroup

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
	return &SocketInterface{
		config:   config,
		metrics:  core.SocketMetrics{},
		stopCh:   make(chan struct{}),
		dgramFd: -1, // Initialize to invalid
	}
}

// Start starts the socket interface
func (s *SocketInterface) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("socket interface already running")
	}

	if s.processor == nil {
		return fmt.Errorf("no packet processor set")
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
		// For ICMP, try to use the icmp package. This works in privileged mode ("ip4:icmp").
		// If it fails (e.g., no CAP_NET_RAW), try SOCK_DGRAM for ping_group_range support.
		s.conn, err = icmp.ListenPacket(protocol, "0.0.0.0") // Bind to all interfaces
		if err != nil {
			logging.Warnf("Failed to create raw ICMP socket (CAP_NET_RAW not available): %v", err)
			logging.Infof("Attempting to create datagram ICMP socket for ping_group_range support")
			// Try to create SOCK_DGRAM ICMP socket for ping_group_range
			s.dgramFd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_ICMP)
			if err != nil {
				logging.Warnf("Failed to create datagram ICMP socket: %v", err)
				logging.Warnf("ICMP functionality will be limited without CAP_NET_RAW or ping_group_range")
				s.dgramFd = -1
			} else {
				logging.Infof("Created datagram ICMP socket fd=%d for ping_group_range compatibility", s.dgramFd)
				// Bind to all interfaces
				addr := syscall.SockaddrInet4{}
				if err := syscall.Bind(s.dgramFd, &addr); err != nil {
					logging.Warnf("Failed to bind datagram ICMP socket: %v", err)
					syscall.Close(s.dgramFd)
					s.dgramFd = -1
				} else {
					logging.Infof("Successfully bound datagram ICMP socket")
				}
			}
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
			return fmt.Errorf("failed to set read deadline: %v", err)
		}
	}

	s.running = true
	if s.conn != nil {
		s.wg.Add(1)
		go s.listenLoop()
	} else if s.dgramFd >= 0 {
		// If we have datagram socket but no raw socket, start datagram listener
		s.wg.Add(1)
		go s.dgramListenLoop()
	}

    // SIMPLE_MODE bypasses FlowManager and egress limiter to reduce moving parts
    logging.Infof("Simple mode active: bypassing FlowManager and egress limiter; inline delivery to processor")

	// Initialize UDP/TCP slirp bridges
	// Header synthesis policy from env
	// COPY_TOS: default 0 (do not copy DSCP/ECN); set to 1 to preserve
	if v := strings.ToLower(strings.TrimSpace(os.Getenv("COPY_TOS"))); v == "1" || v == "true" || v == "yes" || v == "on" {
		s.tosCopy = true
	}
	// IP_TTL: default 64; set <=0 to use default 64
	s.ttlOverride = 64
	if v := strings.TrimSpace(os.Getenv("IP_TTL")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 255 {
			s.ttlOverride = n
		}
	}
	s.udp = newUDPBridge(s)
	s.tcp = newTCPBridge(s)

    // No egress limiter configuration

	logging.Debugf("Socket interface started with IP: %s", s.config.IPAddress)
	return nil
}

// Stop stops the socket interface
func (s *SocketInterface) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	close(s.stopCh)
	s.wg.Wait()

	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}

	if s.dgramFd >= 0 {
		syscall.Close(s.dgramFd)
		s.dgramFd = -1
	}

	if s.udp != nil {
		s.udp.stop()
		s.udp = nil
	}
	if s.tcp != nil {
		s.tcp.stop()
		s.tcp = nil
	}

    // No FlowManager

	s.running = false

	logging.Debugf("Socket interface stopped")
	return nil
}

// SetPacketProcessor sets the packet processor for handling packets from the socket
func (s *SocketInterface) SetPacketProcessor(processor core.PacketProcessor) {
	s.processor = processor
}

// WritePacket writes a packet to the host network
func (s *SocketInterface) WritePacket(packet core.Packet) error {
	s.mu.Lock()
	running := s.running
	s.mu.Unlock()

	if !running {
		return fmt.Errorf("socket interface not running")
	}

	// Get the packet data
	data := packet.Data()

	// Basic validation
	if len(data) < 20 {
		atomic.AddUint64(&s.metrics.Errors, 1)
		return fmt.Errorf("packet too short")
	}

	// Check IP version
	ver := data[0] >> 4
	if ver != 4 {
		atomic.AddUint64(&s.metrics.Errors, 1)
		return fmt.Errorf("unsupported IP version: %d", ver)
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
		if s.icmp == nil {
			s.icmp = newICMPBridge(s)
		}
		if err := s.icmp.HandleOutbound(data); err != nil {
			atomic.AddUint64(&s.metrics.Errors, 1)
			return fmt.Errorf("ICMP slirp error: %v", err)
		}
	case 6: // TCP protocol
		if s.tcp == nil {
			atomic.AddUint64(&s.metrics.Errors, 1)
			return fmt.Errorf("TCP bridge not initialized")
		}
		if err := s.tcp.HandleOutbound(data); err != nil {
			atomic.AddUint64(&s.metrics.Errors, 1)
			return fmt.Errorf("TCP slirp error: %v", err)
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
			return fmt.Errorf("UDP slirp error: %v", err)
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
	return s.metrics
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
	dm := SocketDetailedMetrics{
		Total: loadSocketMetrics(&s.metrics),
	}
	if s.udp != nil {
		s.udp.flowsMu.Lock()
		active := uint64(len(s.udp.flows))
		s.udp.flowsMu.Unlock()
		dm.UDP.Counters = loadSocketMetrics(&s.udp.metrics)
		dm.UDP.ActiveFlows = active
		// Add UDP debug counters
		enq, proc := getUDPTxDebug()
		dm.UDPExt = map[string]uint64{"tx_enq": enq, "tx_proc": proc}
	}
	if s.tcp != nil {
		s.tcp.mu.Lock()
		active := uint64(len(s.tcp.flows))
		// Compute ACK-idle flows under the same lock to get a consistent snapshot
		ackIdle := uint64(0)
		if s.tcp.ackIdleGate > 0 {
			for _, f := range s.tcp.flows {
				inFlight := int(f.serverNxt - f.sndUna)
				minInflight := s.tcp.ackIdleMinInflight
				if minInflight <= 0 {
					minInflight = f.mss
				}
				if inFlight >= minInflight {
					if time.Since(f.lastAckTime) >= s.tcp.ackIdleGate {
						ackIdle++
					}
				}
			}
		}
		s.tcp.mu.Unlock()
		dm.TCP.Counters = loadSocketMetrics(&s.tcp.metrics)
		dm.TCP.ActiveFlows = active
		// TCP extra debug counters
		s.tcp.rtoMu.Lock()
		activeRTOFlows := uint64(len(s.tcp.rtoActiveFlows))
		s.tcp.rtoMu.Unlock()
		// Compose TCPExt with RTO and ACK classification counters
		dm.TCPExt = map[string]uint64{
			"rto":               atomic.LoadUint64(&s.tcp.rtoCount),
			"active_rto_flows":  activeRTOFlows,
			"ack_advanced":      atomic.LoadUint64(&s.tcp.ackAdv),
			"ack_duplicate":     atomic.LoadUint64(&s.tcp.ackDup),
			"ack_window_update": atomic.LoadUint64(&s.tcp.ackWndOnly),
			"ack_idle_flows":    ackIdle,
			// Async dial and pending-buffer instrumentation
			"dial_start":        atomic.LoadUint64(&s.tcp.dialStart),
			"dial_ok":           atomic.LoadUint64(&s.tcp.dialOk),
			"dial_fail":         atomic.LoadUint64(&s.tcp.dialFail),
			"dial_inflight":     uint64(atomic.LoadInt64(&s.tcp.dialInflight)),
			"pend_enq":          atomic.LoadUint64(&s.tcp.pendEnq),
			"pend_flush":        atomic.LoadUint64(&s.tcp.pendFlush),
			"pend_drop":         atomic.LoadUint64(&s.tcp.pendDrop),
		}
	}
    // FlowManager and egress limiter removed
    // Fallback removed
	// Include processor metrics if available
	if s.processor != nil {
		if m, ok := s.processor.(interface{ Metrics() map[string]uint64 }); ok {
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

// dgramListenLoop listens for ICMP packets using SOCK_DGRAM (for ping_group_range compatibility)
func (s *SocketInterface) dgramListenLoop() {
	defer s.wg.Done()

	// Set receive timeout
	tv := syscall.Timeval{Sec: 5, Usec: 0} // 5 second timeout
	if err := syscall.SetsockoptTimeval(s.dgramFd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		logging.Errorf("Failed to set datagram socket timeout: %v", err)
		return
	}

	// Create a buffer for receiving packets
	buf := make([]byte, 65536)

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
			// Read a packet using SOCK_DGRAM
			n, fromAddr, err := syscall.Recvfrom(s.dgramFd, buf, 0)
			if err != nil {
				if errno, ok := err.(syscall.Errno); ok && (errno == syscall.EAGAIN || errno == syscall.EWOULDBLOCK) {
					// Timeout, continue
					continue
				}
				logging.Errorf("Failed to read from datagram socket: %v", err)
				atomic.AddUint64(&s.metrics.Errors, 1)
				time.Sleep(100 * time.Millisecond)
				continue
			}

			// Extract peer IP address
			fromSockaddr, ok := fromAddr.(*syscall.SockaddrInet4)
			if !ok {
				logging.Warnf("Unexpected sockaddr type: %T", fromAddr)
				continue
			}
			peerIP := net.IPv4(fromSockaddr.Addr[0], fromSockaddr.Addr[1], fromSockaddr.Addr[2], fromSockaddr.Addr[3])
			if peerIP.Equal(myIP) {
				// Skip our own packets
				continue
			}

			// Parse the ICMP message (datagram sockets receive ICMP payload without IP header)
			msg, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), buf[:n])
			if err != nil {
				logging.Errorf("Failed to parse ICMP message from datagram socket: %v", err)
				atomic.AddUint64(&s.metrics.Errors, 1)
				continue
			}

			// Log the ICMP message details
			logging.Debugf("SOCKET INCOMING (datagram): from=%v, type=%v, code=%v", peerIP, msg.Type, msg.Code)

			// For echo replies, extract more details
			if msg.Type == ipv4.ICMPTypeEchoReply {
				if echo, ok := msg.Body.(*icmp.Echo); ok {
					logging.Debugf("SOCKET INCOMING ICMP (datagram): type=0, code=0, id=%d, seq=%d",
						echo.ID, echo.Seq)
				}
			}

			// Construct a full IP packet with the ICMP message
			ipHeader := make([]byte, 20)
			ipHeader[0] = 0x45 // Version 4, header length 5 (20 bytes)
			ipHeader[1] = 0x00 // DSCP & ECN
			total := 20 + n
			ipHeader[2] = byte(total >> 8)   // Total length (high byte)
			ipHeader[3] = byte(total & 0xff) // Total length (low byte)
			// Identification
			{
				id := nextIPID()
				ipHeader[4] = byte(id >> 8)
				ipHeader[5] = byte(id)
			}
			ipHeader[6] = 0x00        // Flags & Fragment offset
			ipHeader[7] = 0x00        // Fragment offset
			ipHeader[8] = 64          // TTL
			ipHeader[9] = 1           // Protocol (ICMP)
			ipHeader[10] = 0x00       // Header checksum (will be calculated later)
			ipHeader[11] = 0x00       // Header checksum
			copy(ipHeader[12:16], peerIP.To4()) // Source IP (the peer)
			copy(ipHeader[16:20], myIP.To4())   // Destination IP (our IP)

			// Calculate IP header checksum
			checksum := calculateChecksum(ipHeader)
			ipHeader[10] = byte(checksum >> 8)
			ipHeader[11] = byte(checksum & 0xff)

			// Combine IP header and ICMP message
			fullPacket := append(ipHeader, buf[:n]...)

			// Update metrics
			atomic.AddUint64(&s.metrics.PacketsReceived, 1)
			atomic.AddUint64(&s.metrics.BytesReceived, uint64(len(fullPacket)))

			// Create a packet from the data
			packet := core.NewPacket(fullPacket)

			// Process the packet
			if s.processor != nil {
				if err := s.processor.ProcessPacket(packet); err != nil {
					logging.Errorf("Failed to process packet from datagram socket: %v", err)
					atomic.AddUint64(&s.metrics.Errors, 1)
					continue
				}
				logging.Debugf("Packet processed by processor from datagram socket: length=%d", len(fullPacket))
			} else {
				logging.Warnf("No packet processor set, packet not processed from datagram socket: length=%d", len(fullPacket))
			}

			logging.Debugf("Received packet of length %d from host network via datagram socket", len(fullPacket))
		}
	}
}

// listenLoop listens for packets from the host network
func (s *SocketInterface) listenLoop() {
	defer s.wg.Done()

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

			// Process the received packet based on the protocol
			var fullPacket []byte

			// Extract peer IP address
			peerIP := peer.(*net.IPAddr).IP
			if peerIP == nil || peerIP.Equal(myIP) {
				// Skip our own packets or invalid peer addresses
				continue
			}

			// Determine the protocol based on the socket configuration
			protocol := uint8(1) // Only ICMP supported for now

			// Process the received packet based on the protocol
			if protocol == 1 { // ICMP
				// Parse the ICMP message
				msg, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), buf[:n])
				if err != nil {
					logging.Errorf("Failed to parse ICMP message: %v", err)
					atomic.AddUint64(&s.metrics.Errors, 1)
					continue
				}

				// Log the ICMP message details (debug)
				logging.Debugf("SOCKET INCOMING: from=%v, type=%v, code=%v", peer, msg.Type, msg.Code)

				// For echo replies, extract more details
				if msg.Type == ipv4.ICMPTypeEchoReply {
					if echo, ok := msg.Body.(*icmp.Echo); ok {
						logging.Debugf("SOCKET INCOMING ICMP: type=0, code=0, id=%d, seq=%d",
							echo.ID, echo.Seq)
					}
				}

				// Construct a full IP packet with the ICMP message
				ipHeader := make([]byte, 20)
				ipHeader[0] = 0x45 // Version 4, header length 5 (20 bytes)
				ipHeader[1] = 0x00 // DSCP & ECN
				total := 20 + n
				ipHeader[2] = byte(total >> 8)   // Total length (high byte)
				ipHeader[3] = byte(total & 0xff) // Total length (low byte)
				// Identification
				{
					id := nextIPID()
					ipHeader[4] = byte(id >> 8)
					ipHeader[5] = byte(id)
				}
				ipHeader[6] = 0x00                  // Flags & Fragment offset
				ipHeader[7] = 0x00                  // Fragment offset
				ipHeader[8] = 64                    // TTL
				ipHeader[9] = protocol              // Protocol
				ipHeader[10] = 0x00                 // Header checksum (will be calculated later)
				ipHeader[11] = 0x00                 // Header checksum
				copy(ipHeader[12:16], peerIP.To4()) // Source IP (the peer)
				copy(ipHeader[16:20], myIP.To4())   // Destination IP (our IP)

				// Calculate IP header checksum
				checksum := calculateChecksum(ipHeader)
				ipHeader[10] = byte(checksum >> 8)
				ipHeader[11] = byte(checksum & 0xff)

				// Combine IP header and ICMP message
				fullPacket = append(ipHeader, buf[:n]...)
			} else {
				// For unknown protocols, log a warning and skip
				logging.Warnf("Received packet with unsupported protocol: %d", protocol)
				atomic.AddUint64(&s.metrics.Errors, 1)
				continue
			}

			// Update metrics
			atomic.AddUint64(&s.metrics.PacketsReceived, 1)
			atomic.AddUint64(&s.metrics.BytesReceived, uint64(len(fullPacket)))

			// Create a packet from the data
			packet := core.NewPacket(fullPacket)

			// Process the packet
			if s.processor != nil {
				if err := s.processor.ProcessPacket(packet); err != nil {
					logging.Errorf("Failed to process packet: %v", err)
					atomic.AddUint64(&s.metrics.Errors, 1)
					continue
				}
				logging.Debugf("Packet processed by processor: length=%d", len(fullPacket))
			} else {
				logging.Warnf("No packet processor set, packet not processed: length=%d", len(fullPacket))
			}

			logging.Debugf("Received packet of length %d from host network", len(fullPacket))
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
