package socket

import (
    "fmt"
    "net"
    "syscall"

    "github.com/irctrakz/wgslirp/pkg/logging"
    "golang.org/x/net/icmp"
    "golang.org/x/net/ipv4"
)

// icmpBridge is a thin adapter that sends guest ICMP messages over the host
// via the SocketInterface's raw ICMP socket.
type icmpBridge struct {
    parent *SocketInterface
}

func newICMPBridge(parent *SocketInterface) *icmpBridge { return &icmpBridge{parent: parent} }
func (b *icmpBridge) Name() string                     { return "icmp" }
func (b *icmpBridge) stop()                            {}

// HandleOutbound parses the IPv4 packet and sends the ICMP body using the raw
// socket. Replies are handled by SocketInterface.listenLoop.
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

    // No raw socket available - try ping_group_range approach for echo requests
    logging.Debugf("icmp: no raw socket available, attempting ping_group_range method")

    // Parse the ICMP message to determine type
    msg, err := icmp.ParseMessage(ipv4.ICMPTypeEcho.Protocol(), body)
    if err != nil {
        logging.Warnf("icmp: failed to parse message and no raw socket available: %v", err)
        return nil // Drop non-echo ICMP when no raw socket
    }

    // Only handle echo requests when using ping_group_range method
    if msg.Type != ipv4.ICMPTypeEcho {
        logging.Debugf("icmp: dropping non-echo packet (type %v) without raw socket", msg.Type)
        return nil
    }

    // For echo requests, use datagram socket when ping_group_range allows it
    if echo, ok := msg.Body.(*icmp.Echo); ok {
        return b.sendEchoViaDatagram(dst.String(), echo.ID, echo.Seq)
    }

    logging.Warnf("icmp: unexpected echo body type: %T", msg.Body)
    return nil
}

// sendEchoViaDatagram sends an ICMP echo request using SOCK_DGRAM (works with ping_group_range)
// This allows ICMP echo without CAP_NET_RAW
func (b *icmpBridge) sendEchoViaDatagram(dst string, id, seq int) error {
    var fd int
    var shouldClose bool

    // Use parent's datagram socket if available, otherwise create our own
    if b.parent != nil && b.parent.dgramFd >= 0 {
        fd = b.parent.dgramFd
        shouldClose = false
    } else {
        // Create a SOCK_DGRAM ICMP socket (works with ping_group_range)
        var err error
        fd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_ICMP)
        if err != nil {
            return fmt.Errorf("failed to create ICMP socket: %w", err)
        }
        shouldClose = true
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
        Data: []byte{}, // Empty data for now
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

    // Send the echo request
    if err := syscall.Sendto(fd, data, 0, &addr); err != nil {
        return fmt.Errorf("failed to send ICMP echo: %w", err)
    }

    logging.Debugf("icmp: sent echo request to %s (id=%d, seq=%d)", dst, id, seq)
    return nil
}
