package socket

import (
	"fmt"
	"net"

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
func (b *icmpBridge) Name() string                      { return "icmp" }
func (b *icmpBridge) stop()                             {}

// HandleOutbound parses the IPv4 packet and sends the ICMP body using the raw
// socket. Replies are handled by SocketInterface.listenLoop.
func (b *icmpBridge) HandleOutbound(pkt []byte) error {
	pkt, ihl, err := parseTransport(pkt, 1)
	if err != nil {
		return err
	}
	// If no raw ICMP socket is available (e.g., in containers without CAP_NET_RAW),
	// silently drop ICMP rather than failing the write path. This avoids noisy
	// errors while keeping TCP/UDP traffic flowing.
	if b.parent == nil || b.parent.conn == nil {
		logging.Debugf("icmp: dropping packet (no raw socket available)")
		return nil
	}
	dst := net.IPv4(pkt[16], pkt[17], pkt[18], pkt[19])
	body := pkt[ihl:]

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
