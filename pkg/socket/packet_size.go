package socket

import (
	"errors"
	"fmt"
	"sync/atomic"
	"syscall"

	"github.com/irctrakz/wgslirp/pkg/logging"
)

func (s *SocketInterface) recordAcceptedPacketSize(size int) {
	if size > s.config.MTU {
		s.oversizedAccepted.Add(1)
		logging.Debugf("Guest packet accepted above configured MTU: size=%d mtu=%d; remote delivery not confirmed", size, s.config.MTU)
	}
}

// The caller logs returned failures through the existing TUN error path. Only
// an actual size rejection carries MTU advice; exceeding config.MTU is harmless
// by itself. Keep the OS error identity and avoid a second warning for it.
func (s *SocketInterface) outboundPacketError(protocol string, size int, err error) error {
	if !errors.Is(err, ErrTCPTeardown) {
		atomic.AddUint64(&s.metrics.Errors, 1)
	}
	if errors.Is(err, syscall.EMSGSIZE) {
		s.localSizeRejected.Add(1)
		return fmt.Errorf("%s slirp error: local host rejected packet for size (guest_frame_bytes=%d): %w; reduce datagram size or check host path MTU", protocol, size, err)
	}
	return fmt.Errorf("%s slirp error: %w", protocol, err)
}
