package socket

// Idle storage is bounded independently of live per-socket reservations.
// Four classes of 32 entries retain at most 960 KiB process-wide. Full pools
// discard returned buffers; GC is not needed to enforce this retention limit.
const (
	// IPv4 TCP headers, including all options, fit in 80 bytes. Keep tiny
	// control packets exact-sized; channel reuse is slower for ACK-sized storage.
	packetPoolMinSize = 512
	pktSmall          = 2048
	pktMed            = 4096
	pktLarge          = 8192
	pktXL             = 16384
	packetPoolEntries = 32
)

var (
	poolSmall = make(chan []byte, packetPoolEntries)
	poolMed   = make(chan []byte, packetPoolEntries)
	poolLarge = make(chan []byte, packetPoolEntries)
	poolXL    = make(chan []byte, packetPoolEntries)
)

func packetCapacity(n int) int {
	switch {
	case n <= pktSmall:
		return pktSmall
	case n <= pktMed:
		return pktMed
	case n <= pktLarge:
		return pktLarge
	case n <= pktXL:
		return pktXL
	default:
		return n
	}
}
func packetPool(capacity int) chan []byte {
	switch capacity {
	case pktSmall:
		return poolSmall
	case pktMed:
		return poolMed
	case pktLarge:
		return poolLarge
	case pktXL:
		return poolXL
	default:
		return nil
	}
}
func pktGet(n int) []byte {
	capacity := packetCapacity(n)
	select {
	case b := <-packetPool(capacity):
		b = b[:n]
		clear(b) // old checksum, urgent-pointer and option bytes must not leak
		return b
	default:
		return make([]byte, n, capacity)
	}
}
func pktPut(b []byte) {
	select {
	case packetPool(cap(b)) <- b[:cap(b)]:
	default:
	}
}
func pktShouldPut(b []byte) bool { return packetPool(cap(b)) != nil }

// PktPut relinquishes exclusive ownership of a buffer to the bounded cache.
// The caller must not use or return the buffer again.
func PktPut(b []byte) { pktPut(b) }

// PktShouldPut reports capacity eligibility, not allocation provenance.
func PktShouldPut(b []byte) bool { return pktShouldPut(b) }
