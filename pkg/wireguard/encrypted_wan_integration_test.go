//go:build integration && wan && linux

package wireguard

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Independent guest encoder extension for SACK negotiation and blocks.
func encryptedPacketOptions(port uint16, seq, ack uint32, flags byte, opts []byte) []byte {
	p := encryptedPacket(6, port, seq, ack, flags, nil)
	p = append(p, opts...)
	p[32] = byte((20+len(opts))/4) << 4
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	p[10], p[11], p[36], p[37] = 0, 0, 0, 0
	binary.BigEndian.PutUint16(p[10:12], encryptedChecksum(p[:20]))
	pseudo := append([]byte(nil), p[12:20]...)
	pseudo = append(pseudo, 0, 6, 0, byte(len(p)-20))
	pseudo = append(pseudo, p[20:]...)
	binary.BigEndian.PutUint16(p[36:38], encryptedChecksum(pseudo))
	return p
}

func TestEncryptedWANRecovery(t *testing.T) {
	baseline := runtime.NumGoroutine()
	for _, delay := range []time.Duration{20 * time.Millisecond, 60 * time.Millisecond} {
		if !t.Run(fmt.Sprint(delay), func(t *testing.T) { runEncryptedRecovery(t, delay) }) {
			return
		}
		deadline := time.Now().Add(5 * time.Second)
		for runtime.NumGoroutine() > baseline+4 && time.Now().Before(deadline) {
			time.Sleep(50 * time.Millisecond)
		}
		if runtime.NumGoroutine() > baseline+4 {
			t.Fatal("workers survived device/relay cleanup")
		}
	}
	t.Log("WAN_ACCEPTED profiles=2")
}

func runEncryptedRecovery(t *testing.T, delay time.Duration) {
	started := time.Now()
	var wan *encryptedWAN
	s, tun, responses := encryptedTestLink(t, func(port int) string {
		wan = newEncryptedRelay(t, port, delay, false)
		return wan.conn.LocalAddr().String()
	})
	var heapPeak, rssPeak uint64
	sample := func() {
		t.Helper()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		data, err := os.ReadFile("/proc/self/statm")
		if err != nil {
			t.Fatal(err)
		}
		fields := strings.Fields(string(data))
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
		if m.HeapAlloc > 192<<20 || rss > 384<<20 || runtime.NumGoroutine() > 512 || time.Since(started) > 45*time.Second {
			t.Fatalf("resource/deadline ceiling: heap=%d rss=%d workers=%d", m.HeapAlloc, rss, runtime.NumGoroutine())
		}
		dm := s.DetailedMetrics()
		if dm.TCPExt["socket_buffer_bytes"] > dm.TCPExt["socket_buffer_limit"] || wan.overflow.Load() != 0 {
			t.Fatal("buffer/relay bound exceeded")
		}
	}
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
				t.Fatalf("encrypted response deadline: protocol=%d", proto)
			}
		}
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udp.Close() })
	var rtts []time.Duration
	for i := 0; i < 9; i++ {
		payload := bytes.Repeat([]byte{byte(i)}, 256)
		begin := time.Now()
		_ = udp.SetDeadline(begin.Add(5 * time.Second))
		send(encryptedPacket(17, uint16(udp.LocalAddr().(*net.UDPAddr).Port), 0, 0, 0, payload))
		var buf [256]byte
		n, from, err := udp.ReadFromUDP(buf[:])
		if err != nil || !bytes.Equal(buf[:n], payload) {
			t.Fatalf("UDP host: %v", err)
		}
		if _, err = udp.WriteToUDP(buf[:n], from); err != nil {
			t.Fatal(err)
		}
		if p := receive(17); !bytes.Equal(p[28:], payload) {
			t.Fatal("UDP guest mismatch")
		}
		if i > 0 {
			rtts = append(rtts, time.Since(begin))
		}
		sample()
	}
	sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
	if rtts[0] < 2*delay || rtts[len(rtts)-1] > 2*delay+250*time.Millisecond {
		t.Fatalf("uncalibrated UDP RTT: %v", rtts)
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	_ = listener.SetDeadline(time.Now().Add(5 * time.Second))
	send(encryptedPacketOptions(port, 100, 0, 2, []byte{4, 2, 1, 1}))
	host, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { host.Close() })
	syn := receive(6)
	if len(syn) < 40 || syn[33]&0x12 != 0x12 {
		t.Fatal("missing SYN ACK")
	}
	seq, ack := uint32(101), binary.BigEndian.Uint32(syn[24:28])+1
	send(encryptedPacket(6, port, seq, ack, 0x10, nil))
	// Exercise the forward path with exact bytes before impaired replies.
	request := bytes.Repeat([]byte{0xa5}, 1024)
	_ = host.SetDeadline(time.Now().Add(5 * time.Second))
	send(encryptedPacket(6, port, seq, ack, 0x18, request))
	gotRequest := make([]byte, len(request))
	if _, err := io.ReadFull(host, gotRequest); err != nil || !bytes.Equal(gotRequest, request) {
		t.Fatalf("TCP request: %v", err)
	}
	seq += uint32(len(request))
	for _, phase := range []string{"burst-loss", "reorder", "renege"} {
		size := 4096
		if phase == "burst-loss" {
			size = 1024
			wan.dropBurst.Store(2)
		}
		if phase == "reorder" {
			wan.delayNext.Store(true)
		}
		if phase == "renege" {
			wan.dropBurst.Store(1)
		}
		beforeRTO := s.DetailedMetrics().TCPExt["rto"]
		beforeReorder := wan.reordered.Load()
		payload := make([]byte, size)
		for i := range payload {
			payload[i] = byte(i*31 + size/1024)
		}
		_ = host.SetDeadline(time.Now().Add(5 * time.Second))
		if n, err := host.Write(payload); err != nil || n != len(payload) {
			t.Fatalf("TCP write: %v", err)
		}
		base := ack
		got := make([]byte, 0, size)
		pending := make(map[uint32][]byte)
		reneged := make(map[uint32]int)
		recovered := 0
		for attempts := 0; len(got) < size && attempts < 64; attempts++ {
			p := receive(6)
			if len(p) < 40 || p[33]&5 != 0 {
				t.Fatal("invalid TCP response")
			}
			h := 20 + int(p[32]>>4)*4
			if h < 40 || h > len(p) {
				t.Fatal("invalid TCP header")
			}
			if len(p) == h {
				continue
			} // Do not generate ACK loops for pure ACKs.
			position := binary.BigEndian.Uint32(p[24:28])
			data := p[h:]
			if position-base > uint32(size) || uint64(position-base)+uint64(len(data)) > uint64(size) {
				t.Fatal("TCP response outside bounded reply")
			}
			if phase == "renege" && ack == base && position != base {
				if _, seen := reneged[position]; seen {
					continue
				}
				// Report receipt, then deliberately discard: cumulative ACK is unchanged.
				opts := []byte{1, 1, 5, 10, 0, 0, 0, 0, 0, 0, 0, 0}
				binary.BigEndian.PutUint32(opts[4:8], position)
				binary.BigEndian.PutUint32(opts[8:12], position+uint32(len(data)))
				send(encryptedPacketOptions(port, seq, ack, 0x10, opts))
				reneged[position] = len(data)
				continue
			}
			if int32(position-ack) >= 0 {
				if len(pending) >= 8 {
					t.Fatal("guest reassembly bound")
				}
				pending[position] = append([]byte(nil), data...)
				if _, ok := reneged[position]; ok {
					recovered++
					delete(reneged, position)
				}
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
			sample()
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("TCP exact payload mismatch: phase=%s received=%d want=%d pending=%d reneged=%d rto=%d", phase, len(got), size, len(pending), len(reneged), s.DetailedMetrics().TCPExt["rto"]-beforeRTO)
		}
		rto := s.DetailedMetrics().TCPExt["rto"] - beforeRTO
		if phase == "burst-loss" && (rto < 2 || wan.dropped.Load() != 2) {
			t.Fatalf("missing consecutive-drop RTO recovery: rto=%d dropped=%d", rto, wan.dropped.Load())
		}
		if phase == "reorder" && wan.reordered.Load() == beforeReorder {
			t.Fatal("no observed ciphertext reordering")
		}
		if phase == "renege" && (recovered == 0 || len(reneged) != 0 || rto == 0 || wan.dropped.Load() != 3) {
			t.Fatalf("missing reneging recovery: recovered=%d pending=%d rto=%d", recovered, len(reneged), rto)
		}
		t.Logf("WAN_PHASE delay=%s phase=%s bytes=%d rto=%d reneged_recovered=%d", delay, phase, size, rto, recovered)
	}
	wan.mu.Lock()
	for direction, values := range wan.delays {
		values = append([]time.Duration(nil), values...)
		sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
		if len(values) < 8 || values[0] < delay || values[len(values)-1] > delay+400*time.Millisecond {
			wan.mu.Unlock()
			t.Fatalf("relay calibration failed: direction=%d samples=%d", direction, len(values))
		}
		t.Logf("WAN_DELAY direction=%d samples=%d min_us=%d p50_us=%d max_us=%d", direction, len(values), values[0].Microseconds(), values[len(values)/2].Microseconds(), values[len(values)-1].Microseconds())
	}
	wan.mu.Unlock()
	if err := s.Stop(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for s.DetailedMetrics().TCPExt["socket_buffer_bytes"] != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	m := s.DetailedMetrics()
	if m.TCP.ActiveFlows != 0 || m.UDP.ActiveFlows != 0 || m.TCPExt["socket_buffer_bytes"] != 0 || m.TCPExt["dial_reserved"] != 0 || m.TCP.DeliveryRefused != 0 {
		t.Fatal("unclean final metrics")
	}
	sample()
	t.Logf("WAN_PROFILE delay=%s udp_rtt_min_us=%d udp_rtt_max_us=%d dropped=%d reordered=%d heap_peak=%d rss_peak=%d elapsed_ms=%d", delay, rtts[0].Microseconds(), rtts[len(rtts)-1].Microseconds(), wan.dropped.Load(), wan.reordered.Load(), heapPeak, rssPeak, time.Since(started).Milliseconds())
}
