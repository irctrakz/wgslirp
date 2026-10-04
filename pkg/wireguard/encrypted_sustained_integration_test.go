//go:build integration && sustained && linux

package wireguard

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/irctrakz/wgslirp/pkg/core"
	"github.com/irctrakz/wgslirp/pkg/socket"
)

// Loss is applied to classified plaintext after actual WireGuard decryption.
// Embedding the socket preserves the same shared buffer-reservation interface.
// WritePacket borrows synchronously, including when a packet is discarded.
type sustainedIngress struct {
	*socket.SocketInterface
	mu                             sync.Mutex
	profile                        string
	rng                            [2]uint32
	seen, dropped, streak, longest [2]uint64 // data, pure ACK
	acceptedACK                    atomic.Uint32
	ackInitialized                 bool
}

func (w *sustainedIngress) setProfile(profile string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.profile = profile
	w.rng = [2]uint32{0x12345678, 0x87654321}
	w.seen, w.dropped, w.streak, w.longest = [2]uint64{}, [2]uint64{}, [2]uint64{}, [2]uint64{}
}

func (w *sustainedIngress) WritePacket(packet core.Packet) error {
	p := core.BorrowPacketData(packet)
	eligible, class := false, 0
	if len(p) >= 40 && p[0] == 0x45 && p[9] == 6 && p[33]&7 == 0 {
		h := 20 + int(p[32]>>4)*4
		if h >= 40 && h <= len(p) && p[33]&0x10 != 0 {
			eligible = true
			if h == len(p) {
				class = 1
			}
		}
	}
	drop := false
	if eligible {
		w.mu.Lock()
		if w.profile != "" {
			w.seen[class]++
			switch w.profile {
			case "seeded":
				x := w.rng[class]
				x ^= x << 13
				x ^= x >> 17
				x ^= x << 5
				w.rng[class] = x
				drop = x%100 < 8
			case "bursts":
				period := uint64(32)
				if class == 1 {
					// Do not align ACK loss with the 32-segment reply window pattern.
					period = 31
				}
				drop = (w.seen[class]-1)%period < 2
			}
			if drop {
				w.dropped[class]++
				w.streak[class]++
				if w.streak[class] > w.longest[class] {
					w.longest[class] = w.streak[class]
				}
			} else {
				w.streak[class] = 0
			}
		}
		w.mu.Unlock()
	}
	if drop {
		return nil
	}
	if err := w.SocketInterface.WritePacket(packet); err != nil {
		return err
	}
	if eligible {
		ack := binary.BigEndian.Uint32(p[28:32])
		w.mu.Lock()
		if !w.ackInitialized || int32(ack-w.acceptedACK.Load()) > 0 {
			w.acceptedACK.Store(ack)
			w.ackInitialized = true
		}
		w.mu.Unlock()
	}
	return nil
}

func TestEncryptedSustainedLoss(t *testing.T) {
	baseline := runtime.NumGoroutine()
	if !t.Run("traffic", runEncryptedSustained) {
		return
	}
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > baseline+4 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if runtime.NumGoroutine() > baseline+4 {
		t.Fatal("workers survived cleanup")
	}
	t.Log("SUSTAINED_ACCEPTED profiles=3 rounds=384 application_bytes=16515072")
}

func runEncryptedSustained(t *testing.T) {
	var ingress *sustainedIngress
	s, tun, responses := encryptedTestLinkWithIngress(t, func(port int) string { return fmt.Sprintf("127.0.0.1:%d", port) }, func(s *socket.SocketInterface) core.PacketWriter {
		ingress = &sustainedIngress{SocketInterface: s}
		return ingress
	})
	var initial runtime.MemStats
	runtime.ReadMemStats(&initial)
	var heapPeak, rssPeak uint64
	phaseStart := time.Now()
	sample := func() {
		t.Helper()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		raw, err := os.ReadFile("/proc/self/statm")
		if err != nil {
			t.Fatal(err)
		}
		fields := strings.Fields(string(raw))
		if len(fields) < 2 {
			t.Fatal("missing RSS")
		}
		pages, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		rss := pages * uint64(os.Getpagesize())
		if m.HeapAlloc > heapPeak {
			heapPeak = m.HeapAlloc
		}
		if rss > rssPeak {
			rssPeak = rss
		}
		if m.HeapAlloc > 192<<20 || rss > 384<<20 || runtime.NumGoroutine() > 512 || m.NumForcedGC != initial.NumForcedGC {
			t.Fatalf("resource/GC bound: heap=%d rss=%d workers=%d forced_gc=%d", m.HeapAlloc, rss, runtime.NumGoroutine(), m.NumForcedGC-initial.NumForcedGC)
		}
		if time.Since(phaseStart) > 90*time.Second {
			t.Fatal("phase exceeded 90 seconds")
		}
		dm := s.DetailedMetrics()
		if dm.TCPExt["socket_buffer_bytes"] > dm.TCPExt["socket_buffer_limit"] {
			t.Fatal("socket buffer bound")
		}
	}
	send := func(p []byte) {
		t.Helper()
		if err := tun.InjectToPeer(p); err != nil {
			t.Fatal(err)
		}
	}
	receive := func(timeout time.Duration) []byte {
		t.Helper()
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		select {
		case p := <-responses:
			return p
		case <-timer.C:
			return nil
		}
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	_ = listener.SetDeadline(time.Now().Add(3 * time.Second))
	send(encryptedPacket(6, port, 100, 0, 2, nil))
	host, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { host.Close() })
	syn := receive(3 * time.Second)
	if len(syn) < 40 || syn[9] != 6 || syn[33]&0x12 != 0x12 {
		t.Fatal("missing SYN ACK")
	}
	seq, ack := uint32(101), binary.BigEndian.Uint32(syn[24:28])+1
	send(encryptedPacket(6, port, seq, ack, 0x10, nil))
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udp.Close() })
	udpPort := uint16(udp.LocalAddr().(*net.UDPAddr).Port)
	for profileIndex, profile := range []string{"baseline", "seeded", "bursts"} {
		ingress.setProfile(profile)
		phaseStart = time.Now()
		beforeRTO := s.DetailedMetrics().TCPExt["rto"]
		guestRetries := 0
		for round := 0; round < 128; round++ {
			roundStart := time.Now()
			// Unique round bytes make duplicate application delivery detectable.
			request := make([]byte, 8<<10)
			for i := range request {
				request[i] = byte(i*31 + round + profileIndex*131)
			}
			_ = host.SetDeadline(time.Now().Add(3 * time.Second))
			for offset := 0; offset < len(request); offset += 1024 {
				packet := encryptedPacket(6, port, seq, ack, 0x18, request[offset:offset+1024])
				next := seq + 1024
				accepted := false
				for attempt := 0; attempt < 4 && !accepted; attempt++ {
					if attempt > 0 {
						guestRetries++
					}
					send(packet)
					until := time.Now().Add(250 * time.Millisecond)
					for time.Now().Before(until) {
						p := receive(time.Until(until))
						if p == nil {
							break
						}
						if len(p) < 40 || p[9] != 6 || p[33]&5 != 0 {
							t.Fatal("unexpected upload reply")
						}
						if binary.BigEndian.Uint32(p[28:32]) == next {
							accepted = true
							break
						}
					}
					sample()
				}
				if !accepted {
					t.Fatalf("upload retry bound: profile=%s round=%d", profile, round)
				}
				seq = next
			}
			gotRequest := make([]byte, len(request))
			if _, err := io.ReadFull(host, gotRequest); err != nil || !bytes.Equal(gotRequest, request) {
				t.Fatalf("host request bytes: %v", err)
			}
			reply := bytes.Repeat(request, 4)
			_ = host.SetDeadline(time.Now().Add(3 * time.Second))
			if n, err := host.Write(reply); err != nil || n != len(reply) {
				t.Fatalf("host reply: n=%d err=%v", n, err)
			}
			startACK := ack
			got := make([]byte, 0, len(reply))
			pending := make(map[uint32][]byte)
			until := time.Now().Add(5 * time.Second)
			// Wait for the final ACK to reach the bridge, not merely to be injected.
			// Missing ACKs must cause real server retransmission and another guest ACK.
			for attempts := 0; len(got) < len(reply) || ingress.acceptedACK.Load() != ack; attempts++ {
				if attempts >= 512 || time.Now().After(until) {
					t.Fatalf("reply/ACK recovery bound: profile=%s round=%d got=%d accepted=%d ack=%d", profile, round, len(got), ingress.acceptedACK.Load(), ack)
				}
				p := receive(25 * time.Millisecond)
				sample()
				if p == nil {
					continue
				}
				if len(p) < 40 || p[9] != 6 || p[33]&5 != 0 {
					t.Fatal("unexpected download reply")
				}
				h := 20 + int(p[32]>>4)*4
				if h < 40 || h > len(p) {
					t.Fatal("TCP header")
				}
				if len(p) == h {
					continue
				}
				position := binary.BigEndian.Uint32(p[24:28])
				data := p[h:]
				if int32(position-startACK) < 0 && int32(position+uint32(len(data))-startACK) <= 0 {
					// A retransmission from the previous round may still be in flight.
					send(encryptedPacket(6, port, seq, ack, 0x10, nil))
					continue
				}
				offset := position - startACK
				if uint64(offset)+uint64(len(data)) > uint64(len(reply)) {
					t.Fatal("download outside expected bytes")
				}
				if !bytes.Equal(data, reply[int(offset):int(offset)+len(data)]) {
					t.Fatal("download byte mismatch")
				}
				if int32(position-ack) >= 0 {
					if len(pending) >= 8 {
						t.Fatal("guest reassembly bound")
					}
					pending[position] = append([]byte(nil), data...)
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
				t.Fatal("complete reply mismatch")
			}
			payload := request[:1024]
			_ = udp.SetDeadline(time.Now().Add(3 * time.Second))
			send(encryptedPacket(17, udpPort, 0, 0, 0, payload))
			var buf [1024]byte
			n, from, err := udp.ReadFromUDP(buf[:])
			if err != nil || !bytes.Equal(buf[:n], payload) {
				t.Fatalf("UDP host: %v", err)
			}
			if _, err := udp.WriteToUDP(buf[:n], from); err != nil {
				t.Fatal(err)
			}
			udpDeadline := time.Now().Add(3 * time.Second)
			for {
				p := receive(time.Until(udpDeadline))
				if p == nil {
					t.Fatal("UDP reply deadline")
				}
				if len(p) >= 28 && p[9] == 17 {
					if !bytes.Equal(p[28:], payload) {
						t.Fatal("UDP guest mismatch")
					}
					break
				}
				if time.Now().After(udpDeadline) {
					t.Fatal("UDP reply starvation")
				}
			}
			sample()
			if wait := 400*time.Millisecond - time.Since(roundStart); wait > 0 {
				time.Sleep(wait)
			}
			if (round+1)%32 == 0 {
				t.Logf("SUSTAINED_PROGRESS profile=%s rounds=%d elapsed_ms=%d", profile, round+1, time.Since(phaseStart).Milliseconds())
			}
		}
		ingress.mu.Lock()
		seen, dropped, longest := ingress.seen, ingress.dropped, ingress.longest
		ingress.mu.Unlock()
		rto := s.DetailedMetrics().TCPExt["rto"] - beforeRTO
		if seen[0] != uint64(128*8+guestRetries) {
			t.Fatalf("uplink accounting mismatch: seen=%d retransmissions=%d", seen[0], guestRetries)
		}
		if profile == "baseline" && (dropped[0] != 0 || dropped[1] != 0 || guestRetries != 0) {
			t.Fatal("baseline unexpectedly lost traffic")
		}
		if profile != "baseline" && (dropped[0] < 8 || dropped[1] < 8 || guestRetries < 8 || rto == 0) {
			t.Fatalf("insufficient loss evidence: data=%d ACK=%d retries=%d rto=%d", dropped[0], dropped[1], guestRetries, rto)
		}
		if profile == "bursts" && (longest[0] != 2 || longest[1] != 2) {
			t.Fatalf("missing two-packet bursts: %v", longest)
		}
		if time.Since(phaseStart) < 50*time.Second {
			t.Fatal("insufficient sustained duration")
		}
		t.Logf("SUSTAINED_PROFILE profile=%s rounds=128 uplink_bytes=1048576 downlink_bytes=4194304 udp_each_direction=131072 data_seen=%d data_dropped=%d ack_seen=%d ack_dropped=%d data_max_burst=%d ack_max_burst=%d guest_retries=%d server_rto=%d elapsed_ms=%d", profile, seen[0], dropped[0], seen[1], dropped[1], longest[0], longest[1], guestRetries, rto, time.Since(phaseStart).Milliseconds())
	}
	ingress.setProfile("")
	send(encryptedPacket(6, port, seq, ack, 4, nil))
	if err := s.Stop(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for s.DetailedMetrics().TCPExt["socket_buffer_bytes"] != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	m := s.DetailedMetrics()
	if m.TCP.ActiveFlows != 0 || m.UDP.ActiveFlows != 0 || m.TCPExt["socket_buffer_bytes"] != 0 || m.TCPExt["dial_reserved"] != 0 || m.TCP.DeliveryRefused != 0 {
		t.Fatalf("unclean final metrics: %+v", m)
	}
	var final runtime.MemStats
	runtime.ReadMemStats(&final)
	if final.NumGC-initial.NumGC < 2 {
		t.Fatal("fewer than two natural collections observed")
	}
	sample()
	t.Logf("SUSTAINED_RESOURCES heap_peak=%d rss_peak=%d natural_gc=%d buffer_peak=%d", heapPeak, rssPeak, final.NumGC-initial.NumGC, m.TCPExt["socket_buffer_peak"])
}
