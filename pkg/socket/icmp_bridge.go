package socket

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"syscall"
	"time"

	"github.com/irctrakz/wgslirp/pkg/logging"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// icmpBridge is a thin adapter that sends guest ICMP messages over the host
// via the SocketInterface's raw ICMP socket, or proxies them using ping_group_range.
type icmpBridge struct {
	parent *SocketInterface
}

func newICMPBridge(parent *SocketInterface) *icmpBridge {
	return &icmpBridge{parent: parent}
}
func (b *icmpBridge) Name() string { return "icmp" }
func (b *icmpBridge) stop()        {}

type pendingDgramEcho struct {
	id     int
	dstIP  [4]byte
	expiry time.Time
}

// HandleOutbound parses the IPv4 packet and sends it through the raw ICMP
// socket when available. Linux ping sockets handle echo requests when raw
// sockets are unavailable and ping_group_range permits them.
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

	// No raw socket available - ping sockets only support echo traffic.
	logging.Debugf("icmp: no raw socket available, trying datagram echo socket")

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

	if b.parent == nil || b.parent.dgramFd < 0 {
		logging.Debugf("icmp: dropping echo packet (no datagram socket available)")
		return nil
	}

	// Datagram ICMP sockets let the kernel choose the real echo ID. Record the
	// guest ID before sending so the read loop can restore it for the guest.
	if echo, ok := msg.Body.(*icmp.Echo); ok {
		return b.sendDatagramEcho(dst, pkt[12:16], echo, body)
	}

	logging.Warnf("icmp: unexpected echo body type: %T", msg.Body)
	return nil
}

func (b *icmpBridge) sendDatagramEcho(dst net.IP, guestSrc []byte, echo *icmp.Echo, body []byte) error {
	dst4 := dst.To4()
	if dst4 == nil || len(guestSrc) != net.IPv4len {
		return fmt.Errorf("icmp: invalid IPv4 datagram echo address")
	}

	var guestIP [4]byte
	copy(guestIP[:], guestSrc)

	key := dgramEchoKey(dst4, echo.Seq, echo.Data)
	b.parent.addPendingDgramEcho(key, pendingDgramEcho{
		id:     echo.ID,
		dstIP:  guestIP,
		expiry: time.Now().Add(5 * time.Second),
	})

	addr := &syscall.SockaddrInet4{}
	copy(addr.Addr[:], dst4)
	if err := syscall.Sendto(b.parent.dgramFd, body, 0, addr); err != nil {
		b.parent.takePendingDgramEcho(key)
		return fmt.Errorf("icmp: send datagram echo: %w", err)
	}

	return nil
}

func dgramEchoKey(ip net.IP, seq int, data []byte) string {
	return ip.String() + ":" + strconv.Itoa(seq) + ":" + string(data)
}

func rewriteDgramEchoReply(msg *icmp.Message, peerIP net.IP, pending pendingDgramEcho) ([]byte, error) {
	echo, ok := msg.Body.(*icmp.Echo)
	if !ok {
		return nil, fmt.Errorf("icmp: unexpected datagram echo reply body %T", msg.Body)
	}

	reply := &icmp.Message{
		Type: msg.Type,
		Code: msg.Code,
		Body: &icmp.Echo{
			ID:   pending.id,
			Seq:  echo.Seq,
			Data: echo.Data,
		},
	}
	body, err := reply.Marshal(nil)
	if err != nil {
		return nil, fmt.Errorf("icmp: marshal datagram echo reply: %w", err)
	}

	return buildIPv4ICMP(peerIP.To4(), pending.dstIP[:], body), nil
}

func buildIPv4ICMP(srcIP, dstIP, body []byte) []byte {
	ipHeader := make([]byte, 20)
	ipHeader[0] = 0x45
	binary.BigEndian.PutUint16(ipHeader[2:4], uint16(len(ipHeader)+len(body)))
	{
		id := nextIPID()
		binary.BigEndian.PutUint16(ipHeader[4:6], id)
	}
	ipHeader[8] = 64
	ipHeader[9] = 1
	copy(ipHeader[12:16], srcIP)
	copy(ipHeader[16:20], dstIP)
	binary.BigEndian.PutUint16(ipHeader[10:12], calculateChecksum(ipHeader))

	return append(ipHeader, body...)
}
