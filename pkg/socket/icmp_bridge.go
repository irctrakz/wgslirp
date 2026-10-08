package socket

import (
	"fmt"
	"net"
	"time"

	"github.com/irctrakz/wgslirp/pkg/core"
	"github.com/irctrakz/wgslirp/pkg/logging"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// icmpBridge sends guest ICMP messages through the raw socket, or echo requests
// through a ping socket when raw ICMP is unavailable.
type icmpBridge struct {
	parent *SocketInterface
}

func newICMPBridge(parent *SocketInterface) *icmpBridge { return &icmpBridge{parent: parent} }
func (b *icmpBridge) Name() string                      { return "icmp" }
func (b *icmpBridge) stop()                             {}

// HandleOutbound validates the IPv4 packet before dispatching to the selected
// ICMP transport. Each transport's reader handles replies and packet ownership.
func (b *icmpBridge) HandleOutbound(pkt []byte) error {
	pkt, ihl, err := parseTransport(pkt, 1)
	if err != nil {
		return err
	}
	if b.parent == nil {
		return nil
	}
	dst := net.IPv4(pkt[16], pkt[17], pkt[18], pkt[19])
	body := pkt[ihl:]
	if b.parent.conn == nil {
		if b.parent.dgram != nil {
			return b.parent.dgram.send(b.parent, pkt[12:16], dst, body)
		}
		logging.Debugf("icmp: dropping packet (no ICMP socket available)")
		return nil
	}

	packet, err := b.parent.marshalICMPPacket(body)
	if err != nil {
		return err
	}
	defer core.ReleasePacket(packet)
	_, err = b.parent.conn.WriteTo(core.BorrowPacketData(packet), &net.IPAddr{IP: dst})
	return err
}

// marshalICMPPacket accounts parsing, the marshaled body and the final wire
// packet separately. Message.Marshal also copies the body using append, whose
// spare capacity is not an exact wire-size allocation; build that header here.
func (s *SocketInterface) marshalICMPPacket(body []byte) (core.Packet, error) {
	if len(body) > 65515 {
		return nil, fmt.Errorf("ICMP body exceeds IPv4 length")
	}
	releaseParse, err := s.ReservePacketBuffer(len(body))
	if err != nil {
		return nil, err
	}
	defer releaseParse()
	msg, err := icmp.ParseMessage(ipv4.ICMPTypeEcho.Protocol(), body)
	if err != nil {
		if s.failureLog.Allow(time.Now()) {
			logging.Warnf("icmp: failed to parse message, sending raw: %v", err)
		}
		packet := s.buffers().buildPacket(len(body), false, func() []byte {
			data := make([]byte, len(body))
			copy(data, body)
			return data
		})
		if packet == nil {
			return nil, ErrBufferLimit
		}
		return packet, nil
	}
	bodySize := msg.Body.Len(1)
	if bodySize < 0 || bodySize > 65511 {
		return nil, fmt.Errorf("marshaled ICMP body exceeds IPv4 length")
	}
	releaseBody, err := s.ReservePacketBuffer(bodySize)
	if err != nil {
		return nil, err
	}
	defer releaseBody()
	encoded, err := msg.Body.Marshal(1)
	if err != nil {
		return nil, fmt.Errorf("icmp: marshal: %w", err)
	}
	packet := s.buffers().buildPacket(4+len(encoded), false, func() []byte {
		data := make([]byte, 4+len(encoded))
		data[0], data[1] = byte(msg.Type.(ipv4.ICMPType)), byte(msg.Code)
		copy(data[4:], encoded)
		checksum := calculateChecksum(data)
		data[2], data[3] = byte(checksum>>8), byte(checksum)
		return data
	})
	if packet == nil {
		return nil, ErrBufferLimit
	}
	return packet, nil
}
