package socket

import "github.com/irctrakz/wgslirp/pkg/core"

// packetDelivery borrows no storage: success transfers ownership; failure releases.
type packetDelivery func(core.Packet) bool

func (s *SocketInterface) packetDelivery() packetDelivery {
	return func(p core.Packet) bool { return deliverPacket(s.processor, p) }
}
