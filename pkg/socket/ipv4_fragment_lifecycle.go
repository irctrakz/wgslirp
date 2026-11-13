package socket

import (
	"encoding/binary"
	"time"

	"github.com/irctrakz/wgslirp/internal/packetwire"
)

func (s *SocketInterface) maintainIPv4Fragments() {
	defer s.wg.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case now := <-ticker.C:
			s.expireIPv4Fragments(now)
		}
	}
}

func (s *SocketInterface) expireIPv4Fragments(now time.Time) {
	for _, d := range s.fragments.expire(now) {
		// Feedback borrows the original first-fragment header/payload while its
		// reservation remains live. It is emitted outside the cache lock.
		if d.first {
			s.sendFragmentTimeout(d.data[:28])
		}
		s.fragments.release(d)
	}
}

func (s *SocketInterface) sendFragmentTimeout(original []byte) {
	// No errors in response to multicast/broadcast, invalid source, or ICMP
	// errors. For fragmented ICMP, only echo requests receive timeout feedback.
	if original[12] == 0 || original[12] >= 224 || original[16] >= 224 ||
		(original[9] == 1 && original[20] != 8) {
		return
	}
	var src, dst [4]byte
	copy(src[:], original[16:20])
	copy(dst[:], original[12:16])
	p := s.buffers().buildPacket(56, false, func() []byte {
		out := make([]byte, 56)
		out[20], out[21] = 11, 1 // Time Exceeded: fragment reassembly timeout
		copy(out[28:], original)
		binary.BigEndian.PutUint16(out[22:24], packetwire.Checksum(out[20:]))
		packetwire.IPv4Header(out, src, dst, 1, 0, 64, 0, 0)
		return out
	})
	s.packetDelivery()(p)
}
