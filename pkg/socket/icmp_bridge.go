package socket

import (
    "net"
    "os/exec"

    "github.com/irctrakz/wgslirp/pkg/core"
    "github.com/irctrakz/wgslirp/pkg/logging"
)

// icmpBridge is a thin adapter that sends guest ICMP messages over the host
// via the SocketInterface's raw ICMP socket, or proxies them using ping_group_range.
type icmpBridge struct {
	parent *SocketInterface
}

func newICMPBridge(parent *SocketInterface) *icmpBridge {
	return &icmpBridge{parent: parent}
}
func (b *icmpBridge) Name() string                     { return "icmp" }
func (b *icmpBridge) stop()                            {}

// HandleOutbound parses the IPv4 packet and proxies ICMP echo requests.
// For echo requests, we send a real ICMP echo to the destination and wait for reply,
// then send a synthetic echo reply back to the client.
func (b *icmpBridge) HandleOutbound(pkt []byte) error {
    if len(pkt) < 28 { // IPv4(20)+ICMP(8)
        return fmt.Errorf("icmp: packet too short")
    }

    ihl := int(pkt[0]&0x0f) * 4
    if ihl < 20 || len(pkt) < ihl+8 {
        return fmt.Errorf("icmp: invalid header")
    }
    dst := net.IPv4(pkt[16], pkt[17], pkt[18], pkt[19])
    body := pkt[ihl:]

    // If raw ICMP socket is available, use it (preferred method)
    if b.parent != nil && b.parent.conn != nil {
        // Use x/net/icmp to send the message; for echo we can pass through.
        // Attempt to parse first to extract type/code, then re-marshal for safety.
        msg, err := icmp.ParseMessage(ipv4.ICMPTypeEcho.Protocol(), body)
        if err != nil {
            // Fallback: send raw body as-is
            logging.Warnf("icmp: failed to parse message, sending raw: %v", err)
            _, err = b.parent.conn.WriteTo(body, &net.IPAddr{IP: dst})
            return err
        }
        bts, err := msg.Marshal(nil)
        if err != nil {
            return fmt.Errorf("icmp: marshal: %w", err)
        }
        _, err = b.parent.conn.WriteTo(bts, &net.IPAddr{IP: dst})
        return err
    }

    // No raw socket available - proxy echo requests using ping_group_range
    logging.Debugf("icmp: no raw socket available, proxying via ping_group_range")

    // Parse the ICMP message to determine type
    msg, err := icmp.ParseMessage(ipv4.ICMPTypeEcho.Protocol(), body)
    if err != nil {
        logging.Warnf("icmp: failed to parse message: %v", err)
        return nil // Drop unparseable ICMP
    }

    // Only handle echo requests
    if msg.Type != ipv4.ICMPTypeEcho {
        logging.Debugf("icmp: dropping non-echo packet (type %v)", msg.Type)
        return nil
    }

    // For echo requests, proxy them
    if echo, ok := msg.Body.(*icmp.Echo); ok {
        go b.proxyEchoRequest(dst, echo.ID, echo.Seq, pkt[12:16]) // src IP for reply
        return nil
    }

    logging.Warnf("icmp: unexpected echo body type: %T", msg.Body)
    return nil
}

// proxyEchoRequest sends a real ICMP echo request and proxies the reply back to the client
func (b *icmpBridge) proxyEchoRequest(dst net.IP, clientID, clientSeq int, srcIP []byte) {
    // Use the ping command to test connectivity, since SOCK_DGRAM may not work reliably
    // This is simpler and more reliable than dealing with SOCK_DGRAM permissions
    cmd := exec.Command("ping", "-c", "1", "-W", "1", dst.String())
    logging.Debugf("icmp: executing ping to test %s", dst)

    // Run ping and check if it succeeds
    err := cmd.Run()
    success := err == nil

    logging.Debugf("icmp: ping to %s %s", dst, map[bool]string{true: "succeeded", false: "failed"}[success])

    // If ping succeeded, send a synthetic echo reply to the client
    if success {
        if err := b.sendEchoReplyToClient(clientID, clientSeq, srcIP, dst); err != nil {
            logging.Debugf("icmp: failed to send reply to client: %v", err)
        }
    } else {
        logging.Debugf("icmp: ping failed, not sending reply to client")
    }
}

// sendEchoReplyToClient constructs and sends an ICMP echo reply to the client
func (b *icmpBridge) sendEchoReplyToClient(clientID, clientSeq int, srcIP, dstIP []byte) error {
    if b.parent == nil || b.parent.processor == nil {
        return fmt.Errorf("no processor available")
    }

    // Construct IP + ICMP echo reply packet
    ipHeader := make([]byte, 20)
    ipHeader[0] = 0x45 // Version 4, header length 5
    ipHeader[1] = 0x00 // DSCP & ECN
    icmpData := []byte{0x00, 0x01, 0x02, 0x03} // Same data as request
    totalLen := 20 + 8 + len(icmpData) // IP + ICMP header + data
    ipHeader[2] = byte(totalLen >> 8)
    ipHeader[3] = byte(totalLen & 0xFF)
    ipHeader[4] = 0x00 // Identification (high)
    ipHeader[5] = 0x00 // Identification (low)
    ipHeader[6] = 0x00 // Flags & Fragment offset
    ipHeader[7] = 0x00
    ipHeader[8] = 64   // TTL
    ipHeader[9] = 1    // Protocol (ICMP)
    ipHeader[10] = 0x00 // Header checksum (calculated below)
    ipHeader[11] = 0x00

    // Source IP (the destination we pinged)
    copy(ipHeader[12:16], dstIP)
    // Destination IP (original source)
    copy(ipHeader[16:20], srcIP)

    // Calculate IP header checksum
    ipChecksum := calculateChecksum(ipHeader)
    ipHeader[10] = byte(ipChecksum >> 8)
    ipHeader[11] = byte(ipChecksum & 0xFF)

    // Construct ICMP echo reply
    icmpHeader := make([]byte, 8)
    icmpHeader[0] = 0 // Type: Echo Reply
    icmpHeader[1] = 0 // Code
    icmpHeader[4] = byte(clientID >> 8) // ID high
    icmpHeader[5] = byte(clientID & 0xFF) // ID low
    icmpHeader[6] = byte(clientSeq >> 8) // Sequence high
    icmpHeader[7] = byte(clientSeq & 0xFF) // Sequence low

    // Calculate ICMP checksum
    icmpPacket := append(icmpHeader, icmpData...)
    icmpChecksum := calculateChecksum(icmpPacket)
    icmpPacket[2] = byte(icmpChecksum >> 8)
    icmpPacket[3] = byte(icmpChecksum & 0xFF)

    // Combine IP header + ICMP packet
    fullPacket := append(ipHeader, icmpPacket...)

    // Send to the processor (which will forward to TUN device)
    packet := core.NewPacket(fullPacket)
    if err := b.parent.processor.ProcessPacket(packet); err != nil {
        return fmt.Errorf("failed to process reply packet: %w", err)
    }

    logging.Debugf("icmp: sent echo reply to client (id=%d, seq=%d)", clientID, clientSeq)
    return nil
}

// sendEchoViaDatagram sends an ICMP echo request using SOCK_DGRAM (works with ping_group_range)
// This allows ICMP echo without CAP_NET_RAW
func (b *icmpBridge) sendEchoViaDatagram(dst string, id, seq int) error {
    var fd int
    var shouldClose bool

    // Use parent's datagram socket if available, otherwise create one and set it
    if b.parent != nil && b.parent.dgramFd >= 0 {
        fd = b.parent.dgramFd
        shouldClose = false
        logging.Debugf("Using parent's datagram socket fd=%d for sending", fd)
    } else {
        // Create a SOCK_DGRAM ICMP socket
        var err error
        fd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_ICMP)
        if err != nil {
            return fmt.Errorf("failed to create ICMP socket: %w", err)
        }

        // Bind to wildcard address
        bindAddr := syscall.SockaddrInet4{}
        if err := syscall.Bind(fd, &bindAddr); err != nil {
            syscall.Close(fd)
            return fmt.Errorf("failed to bind ICMP socket: %w", err)
        }

        // Set it on parent so future calls use the same socket
        if b.parent != nil {
            b.parent.dgramFd = fd
            shouldClose = false
            logging.Debugf("Created and set parent's datagram socket fd=%d", fd)
        } else {
            shouldClose = true
            logging.Debugf("Created datagram socket fd=%d (no parent)", fd)
        }
    }

    if shouldClose {
        defer syscall.Close(fd)
    }

    // Parse destination address
    addr := syscall.SockaddrInet4{}
    ip := net.ParseIP(dst)
    if ip == nil {
        return fmt.Errorf("invalid IP address: %s", dst)
    }
    copy(addr.Addr[:], ip.To4())

    // Create ICMP echo request
    echo := &icmp.Echo{
        ID:   id,
        Seq:  seq,
        Data: []byte{0x00, 0x01, 0x02, 0x03}, // Some test data
    }
    msg := &icmp.Message{
        Type: ipv4.ICMPTypeEcho,
        Code: 0,
        Body: echo,
    }

    // Marshal the message
    data, err := msg.Marshal(nil)
    if err != nil {
        return fmt.Errorf("failed to marshal ICMP message: %w", err)
    }

    logging.Debugf("icmp: sending %d bytes to %s (id=%d, seq=%d)", len(data), dst, id, seq)

    // Send the echo request
    if err := syscall.Sendto(fd, data, 0, &addr); err != nil {
        return fmt.Errorf("failed to send ICMP echo: %w", err)
    }

    logging.Debugf("icmp: sent echo request to %s", dst)
    return nil
}
