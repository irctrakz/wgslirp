//go:build integration && soak && linux

package wireguard

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"runtime"
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
}

func newEncryptedWAN(t *testing.T, serverPort int) *encryptedWAN {
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
			data  []byte
			to    *net.UDPAddr
			due   time.Time
			order uint64
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
			delay := 2 * time.Millisecond
			if from.Port == serverPort {
				if guest == nil {
					continue
				}
				to = guest
				if n >= 4 && binary.LittleEndian.Uint32(buf[:4]) == 4 {
					if n > 1000 && w.dropNext.Swap(false) {
						w.dropped.Add(1)
						continue
					}
					order++
					index = order
					if order%3 == 0 {
						delay = 20 * time.Millisecond
					}
				}
			} else {
				guest = from
			}
			if len(queue) == 64 || n == len(buf) {
				w.overflow.Add(1)
				continue
			}
			queue = append(queue, pending{append([]byte(nil), buf[:n]...), to, time.Now().Add(delay), index})
		}
	}()
	return w
}

// Initial finite soak: one persistent TCP stream plus UDP, 30 seconds or 32
// rounds, at most 160 KiB application payload per direction. Each I/O has a
// five-second deadline; the separate test tag keeps this out of ordinary CI.
func TestEncryptedWANSoak(t *testing.T) { runEncryptedWAN(t, false) }

// This diagnostic stops at the same guard. GC is used only to measure retained
// heap, never to rescue the soak or continue sending traffic after a refusal.
func TestEncryptedWANMemoryDiagnostic(t *testing.T) { runEncryptedWAN(t, true) }

func runEncryptedWAN(t *testing.T, diagnostic bool) {
	var wan *encryptedWAN
	s, tun, responses := encryptedTestLink(t, func(port int) string { wan = newEncryptedWAN(t, port); return wan.conn.LocalAddr().String() })
	send := func(p []byte) {
		t.Helper()
		if err := tun.InjectToPeer(p); err != nil {
			t.Fatal(err)
		}
	}
	receive := func(proto byte) []byte {
		t.Helper()
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		for {
			select {
			case p := <-responses:
				if len(p) >= 28 && p[9] == proto {
					return p
				}
			case <-timer.C:
				t.Fatal("encrypted soak reply deadline")
				return nil
			}
		}
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udp.Close() })
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	listener.SetDeadline(time.Now().Add(5 * time.Second))
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	send(encryptedPacket(6, port, 100, 0, 2, nil))
	conn, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	syn := receive(6)
	if len(syn) < 40 || syn[33]&0x12 != 0x12 {
		t.Fatal("missing SYN ACK")
	}
	seq, ack := uint32(101), binary.BigEndian.Uint32(syn[24:28])+1
	send(encryptedPacket(6, port, seq, ack, 0x10, nil))
	var initial runtime.MemStats
	runtime.ReadMemStats(&initial)
	t.Logf("SOAK_BASELINE heap=%d goroutines=%d cpus=%d", initial.HeapAlloc, runtime.NumGoroutine(), runtime.NumCPU())
	diagnose := func(m runtime.MemStats, rounds int) {
		before := m
		runtime.GC()
		runtime.ReadMemStats(&m)
		dm := s.DetailedMetrics()
		t.Logf("MEMORY_DIAGNOSTIC rounds=%d heap_before=%d heap_after_gc=%d baseline=%d gc_before=%d gc_after=%d goroutines=%d reserved=%d dropped=%d reordered=%d rto=%d", rounds, before.HeapAlloc, m.HeapAlloc, initial.HeapAlloc, before.NumGC, m.NumGC, runtime.NumGoroutine(), dm.TCPExt["socket_buffer_bytes"], wan.dropped.Load(), wan.reordered.Load(), dm.TCPExt["rto"])
	}
	start := time.Now()
	rounds := 0
	var heapPeak uint64
	for rounds < 32 && time.Since(start) < 30*time.Second {
		payload := bytes.Repeat([]byte{byte(rounds)}, 1024)
		udp.SetDeadline(time.Now().Add(5 * time.Second))
		send(encryptedPacket(17, uint16(udp.LocalAddr().(*net.UDPAddr).Port), 0, 0, 0, payload))
		var buf [1024]byte
		n, from, err := udp.ReadFromUDP(buf[:])
		if err != nil || !bytes.Equal(buf[:n], payload) {
			t.Fatalf("UDP host: %v", err)
		}
		if _, err := udp.WriteToUDP(buf[:n], from); err != nil {
			t.Fatal(err)
		}
		if p := receive(17); !bytes.Equal(p[28:], payload) {
			t.Fatal("UDP guest mismatch")
		}
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		send(encryptedPacket(6, port, seq, ack, 0x18, payload))
		seq += uint32(len(payload))
		if _, err := io.ReadFull(conn, buf[:]); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(buf[:], payload) {
			t.Fatal("TCP host mismatch")
		}
		reply := bytes.Repeat(payload, 4)
		if rounds%8 == 0 {
			wan.dropNext.Store(true)
		}
		if _, err := conn.Write(reply); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, 0, len(reply))
		pending := make(map[uint32][]byte)
		for attempts := 0; attempts < 64 && len(got) < len(reply); attempts++ {
			p := receive(6)
			if len(p) < 40 || p[33]&4 != 0 {
				t.Fatal("invalid TCP response")
			}
			h := 20 + int(p[32]>>4)*4
			if h > len(p) {
				t.Fatal("TCP header")
			}
			position := binary.BigEndian.Uint32(p[24:28])
			if len(p) > h && int32(position-ack) >= 0 {
				if uint64(position-ack)+uint64(len(p)-h) > uint64(len(reply)-len(got)) || len(pending) >= 8 {
					t.Fatal("guest reassembly bound")
				}
				pending[position] = append([]byte(nil), p[h:]...)
			}
			for {
				data, ok := pending[ack]
				if !ok {
					break
				}
				delete(pending, ack)
				got = append(got, data...)
				ack += uint32(len(data))
			}
			send(encryptedPacket(6, port, seq, ack, 0x10, nil))
		}
		if !bytes.Equal(got, reply) {
			t.Fatal("TCP guest mismatch")
		}
		rounds++
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		if m.HeapAlloc > heapPeak {
			heapPeak = m.HeapAlloc
		}
		if m.HeapAlloc > 64<<20 || runtime.NumGoroutine() > 256 {
			if diagnostic {
				diagnose(m, rounds)
				if err := s.Stop(); err != nil {
					t.Fatal(err)
				}
				dm := s.DetailedMetrics()
				if dm.TCP.ActiveFlows != 0 || dm.UDP.ActiveFlows != 0 || dm.TCPExt["socket_buffer_bytes"] != 0 {
					t.Fatal("diagnostic cleanup retained flows or reservations")
				}
				return
			}
			t.Fatalf("soak memory/worker abort threshold: heap=%d goroutines=%d rounds=%d", m.HeapAlloc, runtime.NumGoroutine(), rounds)
		}
		dm := s.DetailedMetrics()
		if dm.TCPExt["socket_buffer_bytes"] > dm.TCPExt["socket_buffer_limit"] || wan.overflow.Load() != 0 {
			t.Fatal("bounded workload overflow")
		}
		time.Sleep(time.Second)
	}
	if rounds < 16 || wan.dropped.Load() == 0 || wan.reordered.Load() == 0 {
		t.Fatalf("insufficient workload: rounds=%d dropped=%d reordered=%d", rounds, wan.dropped.Load(), wan.reordered.Load())
	}
	if diagnostic {
		var final runtime.MemStats
		runtime.ReadMemStats(&final)
		diagnose(final, rounds)
	}
	rto := s.DetailedMetrics().TCPExt["rto"]
	if s.DetailedMetrics().TCPExt["ack_duplicate"] == 0 {
		t.Fatal("no duplicate ACK recovery observed under injected loss")
	}
	send(encryptedPacket(6, port, seq, ack, 0x14, nil))
	if err := s.Stop(); err != nil {
		t.Fatal(err)
	}
	dm := s.DetailedMetrics()
	if dm.TCP.ActiveFlows != 0 || dm.UDP.ActiveFlows != 0 || dm.TCPExt["socket_buffer_bytes"] != 0 {
		t.Fatal("flows or reservations survived shutdown")
	}
	t.Logf("ENCRYPTED_SOAK rounds=%d elapsed=%s dropped=%d reordered=%d queue_overflow=%d heap_peak=%d rto=%d final_reserved=%d", rounds, time.Since(start), wan.dropped.Load(), wan.reordered.Load(), wan.overflow.Load(), heapPeak, rto, dm.TCPExt["socket_buffer_bytes"])
}
