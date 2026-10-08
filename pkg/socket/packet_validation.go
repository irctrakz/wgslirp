package socket

import "github.com/irctrakz/wgslirp/internal/packetwire"

// Preserve the socket error identities and wrapping contract for callers.
var (
	ErrMalformedPacket      = packetwire.ErrMalformedPacket
	ErrUnsupportedIPOptions = packetwire.ErrUnsupportedIPOptions
	ErrInvalidChecksum      = packetwire.ErrInvalidChecksum
	ErrUnsupportedFragment  = packetwire.ErrUnsupportedFragment
)

func parseIPv4(packet []byte) ([]byte, int, error) {
	return packetwire.ParseIPv4(packet)
}

func parseTransport(packet []byte, protocol byte) ([]byte, int, error) {
	return packetwire.ParseTransport(packet, protocol)
}
