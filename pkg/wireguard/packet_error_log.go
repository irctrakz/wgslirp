package wireguard

import (
	"errors"
	"sync"

	"github.com/irctrakz/wgslirp/internal/packetwire"
	"github.com/irctrakz/wgslirp/pkg/socket"
)

const packetErrorLogInterval = 30 // seconds

// Fixed categories prevent arbitrary error text/flow addresses from creating an
// unbounded log cache. Unexpected errors retain the original immediate logging.
var packetErrorReasons = [...]struct {
	err  error
	name string
}{
	{packetwire.ErrUnsupportedFragment, "unsupported_ipv4_fragment"},
	{socket.ErrFlowLimit, "flow_limit"},
	{socket.ErrDialLimit, "pending_dial_limit"},
	{socket.ErrBufferLimit, "aggregate_buffer_limit"},
	{ErrQueueFull, "tun_queue_full"},
}

type packetErrorLog struct {
	mu         sync.Mutex
	seen       [len(packetErrorReasons)]bool
	suppressed [len(packetErrorReasons)]uint64
	emit       func(string, ...any)
}

func (l *packetErrorLog) Errorf(format string, args ...any) {
	category := -1
	if format == "Failed to write packets to TUN device: %v" && len(args) == 1 {
		if err, ok := args[0].(error); ok {
			for i, reason := range packetErrorReasons {
				if errors.Is(err, reason.err) {
					category = i
					break
				}
			}
		}
	}
	if category < 0 {
		l.emit(format, args...)
		return
	}
	l.mu.Lock()
	first := !l.seen[category]
	l.seen[category] = true
	if !first {
		l.suppressed[category]++
	}
	l.mu.Unlock()
	if first {
		l.emit(format, args...)
	}
}

// Flush also handles quiet tails: a burst need not continue for its suppressed
// count to become visible. Emission holds no state lock.
func (l *packetErrorLog) Flush() {
	l.mu.Lock()
	counts := l.suppressed
	l.seen = [len(packetErrorReasons)]bool{}
	l.suppressed = [len(packetErrorReasons)]uint64{}
	l.mu.Unlock()
	for i, count := range counts {
		if count != 0 {
			l.emit("Repeated TUN packet failures: reason=%s suppressed=%d", packetErrorReasons[i].name, count)
		}
	}
}
