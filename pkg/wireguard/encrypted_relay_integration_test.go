//go:build integration && (soak || wan) && linux

package wireguard

import (
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A single relay worker owns at most 64 datagrams of at most 2048 bytes.
// It delays ciphertext in userspace; no netem, raw sockets or kernel privileges.
type encryptedWAN struct {
	conn                         *net.UDPConn
	done                         chan struct{}
	dropNext                     atomic.Bool
	dropped, reordered, overflow atomic.Uint64
	dropBurst                    atomic.Int64
	delayNext                    atomic.Bool
	mu                           sync.Mutex
	delays                       [2][]time.Duration
}

func newEncryptedWAN(t *testing.T, serverPort int) *encryptedWAN {
	return newEncryptedRelay(t, serverPort, 2*time.Millisecond, true)
}

// Fixed-delay profiles measure actual residence time in each direction.
// The legacy periodic reordering policy remains exclusive to soak fixtures.
func newEncryptedRelay(t *testing.T, serverPort int, base time.Duration, periodic bool) *encryptedWAN {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	w := &encryptedWAN{conn: conn, done: make(chan struct{})}
	t.Cleanup(func() { conn.Close(); <-w.done })
	go func() {
		defer close(w.done)
		server := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: serverPort}
		var guest *net.UDPAddr
		type pending struct {
			data      []byte
			to        *net.UDPAddr
			due       time.Time
			order     uint64
			arrived   time.Time
			direction int
		}
		queue := make([]pending, 0, 64)
		var order, last uint64
		var buf [2048]byte
		for {
			now := time.Now()
			for i := 0; i < len(queue); {
				p := queue[i]
				if now.Before(p.due) {
					i++
					continue
				}
				if _, err := conn.WriteToUDP(p.data, p.to); err != nil {
					return
				}
				w.mu.Lock()
				if len(w.delays[p.direction]) < 4096 {
					w.delays[p.direction] = append(w.delays[p.direction], time.Since(p.arrived))
				} else {
					w.overflow.Add(1)
				}
				w.mu.Unlock()
				if p.order > 0 {
					if p.order < last {
						w.reordered.Add(1)
					}
					if p.order > last {
						last = p.order
					}
				}
				queue = append(queue[:i], queue[i+1:]...)
			}
			conn.SetReadDeadline(time.Now().Add(time.Millisecond))
			n, from, err := conn.ReadFromUDP(buf[:])
			if err != nil {
				if e, ok := err.(net.Error); ok && e.Timeout() {
					continue
				}
				return
			}
			to := server
			index := uint64(0)
			delay := base
			direction := 0
			if from.Port == serverPort {
				direction = 1
				if guest == nil {
					continue
				}
				to = guest
				if n >= 4 && binary.LittleEndian.Uint32(buf[:4]) == 4 {
					if n > 1000 && w.dropBurst.Load() > 0 {
						w.dropBurst.Add(-1)
						w.dropped.Add(1)
						continue
					}
					if n > 1000 && w.dropNext.Swap(false) {
						w.dropped.Add(1)
						continue
					}
					order++
					index = order
					if periodic && order%3 == 0 {
						delay = 20 * time.Millisecond
					}
					if n > 1000 && w.delayNext.Swap(false) {
						delay += 150 * time.Millisecond
					}
				}
			} else {
				guest = from
			}
			if len(queue) == 64 || n == len(buf) {
				w.overflow.Add(1)
				continue
			}
			arrived := time.Now()
			queue = append(queue, pending{data: append([]byte(nil), buf[:n]...), to: to, due: arrived.Add(delay), order: index, arrived: arrived, direction: direction})
		}
	}()
	return w
}
