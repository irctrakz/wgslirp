//go:build integration && mixed && fragments && linux

package wireguard

import (
	"bytes"
	"crypto/sha256"
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

	"github.com/irctrakz/wgslirp/pkg/socket"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// One WireGuard reader owns scratch/pending/ID. Only statistics cross threads.
// The independent guest TCP stack retransmits after the two deliberate losses.
type fragmentGuestTUN struct {
	tun.Device
	scratch             [65535]byte
	pending             [][]byte
	id                  uint16
	fragmented, dropped atomic.Uint64
}

func (f *fragmentGuestTUN) Read(buffers [][]byte, sizes []int, offset int) (int, error) {
	for len(f.pending) == 0 {
		n, err := f.Device.Read([][]byte{f.scratch[:]}, sizes[:1], 0)
		if err != nil {
			return 0, err
		}
		if n == 0 {
			continue
		}
		p := f.scratch[:sizes[0]]
		if len(p) > 1200 && p[0] == 0x45 && p[9] == 6 {
			f.id++
			f.pending = encryptedFragments(p, f.id, 1176) // 1200-byte IP fragments
			f.fragmented.Add(1)
			if f.dropped.Load() < 2 {
				// Drop the last emitted range, leaving an incomplete assembly.
				f.pending[len(f.pending)-1] = nil
				f.pending = f.pending[:len(f.pending)-1]
				f.dropped.Add(1)
			}
		} else {
			f.pending = [][]byte{append([]byte(nil), p...)}
		}
	}
	p := f.pending[0]
	if len(p) > len(buffers[0])-offset {
		return 0, fmt.Errorf("fragment test buffer too small")
	}
	copy(buffers[0][offset:], p)
	sizes[0] = len(p)
	f.pending[0] = nil
	f.pending = f.pending[1:]
	return 1, nil
}

type fragmentResourceSamples struct {
	mu                sync.Mutex
	initial           runtime.MemStats
	heapPeak, rssPeak uint64
	err               error
}

func (m *fragmentResourceSamples) sample(s *socket.SocketInterface) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	var current runtime.MemStats
	runtime.ReadMemStats(&current)
	raw, err := os.ReadFile("/proc/self/statm")
	fields := strings.Fields(string(raw))
	if err != nil || len(fields) < 2 {
		m.err = fmt.Errorf("RSS sample: %v", err)
		return m.err
	}
	pages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		m.err = err
		return err
	}
	rss := pages * uint64(os.Getpagesize())
	if current.HeapAlloc > m.heapPeak {
		m.heapPeak = current.HeapAlloc
	}
	if rss > m.rssPeak {
		m.rssPeak = rss
	}
	heapCap, rssCap := uint64(192<<20), uint64(384<<20)
	if os.Getenv("MODE") == "race" {
		heapCap, rssCap = 256<<20, 768<<20
	}
	if current.HeapAlloc > heapCap || rss > rssCap || runtime.NumGoroutine() > 512 || current.NumForcedGC != m.initial.NumForcedGC {
		m.err = fmt.Errorf("fragment resource bound: heap=%d rss=%d workers=%d forced_gc=%d", current.HeapAlloc, rss, runtime.NumGoroutine(), current.NumForcedGC-m.initial.NumForcedGC)
	}
	if s != nil {
		dm := s.DetailedMetrics()
		f := dm.IPv4Fragments
		if f["live"] > 32 || f["reserved_bytes"] > 32*(65535+4096) || dm.TCPExt["socket_buffer_bytes"] > dm.TCPExt["socket_buffer_limit"] {
			m.err = fmt.Errorf("fragment reservation bound: %v", f)
		}
	}
	return m.err
}

func TestEncryptedFragments(t *testing.T) {
	baseline := runtime.NumGoroutine()
	samples := &fragmentResourceSamples{}
	runtime.ReadMemStats(&samples.initial)
	if !t.Run("mixed", func(t *testing.T) {
		var wrapper *fragmentGuestTUN
		stop, done := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(done)
			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-stop:
					return
				case <-ticker.C:
					_ = samples.sample(nil)
				}
			}
		}()
		t.Cleanup(func() { close(stop); <-done })
		runEncryptedMixedWithLink(t, func(t *testing.T) (*socket.SocketInterface, *netstack.Net) {
			return mixedTestLinkWithOptions(t, true, func(d tun.Device) tun.Device {
				wrapper = &fragmentGuestTUN{Device: d}
				return wrapper
			})
		})
		if wrapper.fragmented.Load() < 100 || wrapper.dropped.Load() != 2 {
			t.Fatal("fragment/loss injection missing")
		}
		if err := samples.sample(nil); err != nil {
			t.Fatal(err)
		}
		t.Logf("FRAGMENT_MIXED_OK fragmented=%d dropped=2 short_requests=128 bulk_bytes_each_direction=8388608 udp_round_trips=512", wrapper.fragmented.Load())
	}) {
		return
	}
	if !t.Run("datagrams_and_expiry", func(t *testing.T) { runFragmentDatagrams(t, samples) }) {
		return
	}
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > baseline+4 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if runtime.NumGoroutine() > baseline+4 {
		t.Fatal("fragment workers survived cleanup")
	}
	var final runtime.MemStats
	runtime.ReadMemStats(&final)
	t.Logf("FRAGMENTS_ACCEPTED heap_peak=%d rss_peak=%d allocation_bytes=%d allocation_objects=%d natural_gc=%d forced_gc=%d", samples.heapPeak, samples.rssPeak, final.TotalAlloc-samples.initial.TotalAlloc, final.Mallocs-samples.initial.Mallocs, final.NumGC-samples.initial.NumGC, final.NumForcedGC-samples.initial.NumForcedGC)
}

func fragmentUDP(port uint16, source byte, payload []byte) []byte {
	p := encryptedPacket(17, port, 0, 0, 0, payload)
	p[15] = source
	binary.BigEndian.PutUint16(p[20:22], 40000+uint16(source))
	p[10], p[11], p[26], p[27] = 0, 0, 0, 0
	binary.BigEndian.PutUint16(p[10:12], encryptedChecksum(p[:20]))
	pseudo := append([]byte(nil), p[12:20]...)
	pseudo = append(pseudo, 0, 17, byte((len(p)-20)>>8), byte(len(p)-20))
	pseudo = append(pseudo, p[20:]...)
	checksum := encryptedChecksum(pseudo)
	if checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(p[26:28], checksum)
	return p
}

func runFragmentDatagrams(t *testing.T, samples *fragmentResourceSamples) {
	s, guest, responses := encryptedTestLinkWithSources(t, func(port int) string { return fmt.Sprintf("127.0.0.1:%d", port) }, nil, func(c *socket.Config) { c.IPv4Reassembly = true }, "10.0.0.0/24", 256)
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udp.Close() })
	port := uint16(udp.LocalAddr().(*net.UDPAddr).Port)
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	tcpPort := uint16(listener.Addr().(*net.TCPAddr).Port)
	var id uint16
	send := func(p []byte) {
		t.Helper()
		if err := guest.InjectToPeer(p); err != nil {
			t.Fatal(err)
		}
	}
	receiveTCP := func() []byte {
		t.Helper()
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		for {
			select {
			case p := <-responses:
				if len(p) >= 40 && p[9] == 6 {
					return p
				}
			case <-timer.C:
				t.Fatal("ordinary TCP reply deadline")
			}
		}
	}
	_ = listener.SetDeadline(time.Now().Add(5 * time.Second))
	send(encryptedPacket(6, tcpPort, 100, 0, 2, nil))
	conn, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	syn := receiveTCP()
	if syn[33]&0x12 != 0x12 {
		t.Fatal("ordinary TCP SYN ACK missing")
	}
	seq, ack := uint32(101), binary.BigEndian.Uint32(syn[24:28])+1
	send(encryptedPacket(6, tcpPort, seq, ack, 0x10, nil))
	encoded := func(source byte, size, mtu int) ([][]byte, []byte) {
		id++
		payload := make([]byte, size)
		for i := range payload {
			payload[i] = byte(i*31 + int(id))
		}
		return encryptedFragments(fragmentUDP(port, source, payload), id, (mtu-20)&^7), payload
	}
	verify := func(source byte, payload []byte) {
		t.Helper()
		_ = udp.SetDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 65507)
		n, addr, err := udp.ReadFromUDP(buf)
		if err != nil || !bytes.Equal(buf[:n], payload) {
			t.Fatalf("fragment UDP host mismatch: %v", err)
		}
		hash := sha256.Sum256(payload)
		if _, err := udp.WriteToUDP(hash[:], addr); err != nil {
			t.Fatal(err)
		}
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		for {
			select {
			case p := <-responses:
				if len(p) >= 28 && p[9] == 17 && p[19] == source {
					if !bytes.Equal(p[28:], hash[:]) {
						t.Fatal("fragment UDP encrypted digest mismatch")
					}
					if err := samples.sample(s); err != nil {
						t.Fatal(err)
					}
					return
				}
			case <-timer.C:
				t.Fatal("fragment UDP reply deadline")
			}
		}
	}
	wait := func(predicate func(map[string]uint64) bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for !predicate(s.DetailedMetrics().IPv4Fragments) {
			if time.Now().After(deadline) {
				t.Fatal("fragment processing deadline", s.DetailedMetrics().IPv4Fragments)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	ordinary := func() {
		payload := bytes.Repeat([]byte{0xa5}, 1024)
		send(fragmentUDP(port, 50, payload))
		verify(50, payload)
		body := bytes.Repeat([]byte{0x5a}, 128)
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		send(encryptedPacket(6, tcpPort, seq, ack, 0x18, body))
		seq += uint32(len(body))
		buf := make([]byte, len(body))
		if _, err := io.ReadFull(conn, buf); err != nil || !bytes.Equal(buf, body) {
			t.Fatalf("ordinary TCP host mismatch: %v", err)
		}
		if _, err := conn.Write(body); err != nil {
			t.Fatal(err)
		}
		var got []byte
		for attempts := 0; attempts < 16 && len(got) < len(body); attempts++ {
			p := receiveTCP()
			h := 20 + int(p[32]>>4)*4
			if h > len(p) || p[33]&4 != 0 {
				t.Fatal("ordinary TCP invalid response")
			}
			if binary.BigEndian.Uint32(p[24:28]) == ack {
				got = append(got, p[h:]...)
				ack += uint32(len(p) - h)
			}
			send(encryptedPacket(6, tcpPort, seq, ack, 0x10, nil))
		}
		if !bytes.Equal(got, body) {
			t.Fatal("ordinary TCP guest mismatch")
		}
	}
	expire := func(count uint64) {
		t.Helper()
		before := s.DetailedMetrics().IPv4Fragments
		deadline := time.Now().Add(65 * time.Second)
		rounds := 0
		for s.DetailedMetrics().IPv4Fragments["expired"] < before["expired"]+count {
			if time.Now().After(deadline) {
				t.Fatal("real fragment expiry deadline")
			}
			ordinary()
			rounds++
			time.Sleep(250 * time.Millisecond)
		}
		wait(func(f map[string]uint64) bool { return f["live"] == 0 && f["reserved_bytes"] == 0 })
		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)
		t.Logf("FRAGMENT_RECOVERY expired=%d ordinary_rounds=%d heap=%d total_alloc=%d natural_gc=%d", count, rounds, mem.HeapAlloc, mem.TotalAlloc-samples.initial.TotalAlloc, mem.NumGC-samples.initial.NumGC)
	}
	var late [][]byte
	for _, mtu := range []int{1200, 1380} {
		for _, size := range []int{8192, 16384, 65507} {
			for round := 0; round < 8; round++ {
				frames, payload := encoded(40, size, mtu)
				for _, p := range frames {
					if len(p) > mtu {
						t.Fatal("MTU fixture exceeded bound")
					}
					send(p)
				}
				verify(40, payload)
				late = frames
			}
		}
	}
	// Replaying a tail after dispatch starts a bounded incomplete assembly. Its
	// exact duplicate cannot extend expiry. A separate dropped UDP range must
	// deliver no partial host datagram, and can be retried after real expiry.
	send(late[len(late)-1])
	send(late[len(late)-1])
	lost, payload := encoded(41, 8192, 1200)
	for i, p := range lost {
		if i != 3 {
			send(p)
		}
	}
	wait(func(f map[string]uint64) bool { return f["cached"] == 2 })
	_ = udp.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	var probe [1]byte
	if _, _, err := udp.ReadFromUDP(probe[:]); err == nil {
		t.Fatal("lost UDP range forwarded a partial datagram")
	} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatal(err)
	}
	expire(2)
	for _, p := range lost {
		send(p)
	}
	verify(41, payload)
	for cycle := 0; cycle < 2; cycle++ {
		before := s.DetailedMetrics().IPv4Fragments
		var completion [][]byte
		var completionPayload []byte
		for source := byte(20); source < 24; source++ {
			for slot := 0; slot < 8; slot++ {
				frames, body := encoded(source, 8192, 1200)
				send(frames[0])
				if source == 20 && slot == 0 {
					completion, completionPayload = frames, body
				}
			}
		}
		wait(func(f map[string]uint64) bool { return f["cached"] == 32 })
		if s.DetailedMetrics().IPv4Fragments["reserved_bytes"] != 32*(65535+4096) {
			t.Fatal("global quota storage mismatch")
		}
		own, _ := encoded(20, 8192, 1200)
		send(own[0])
		other, otherPayload := encoded(24, 8192, 1380)
		send(other[0])
		wait(func(f map[string]uint64) bool {
			return f["source_limit"] == before["source_limit"]+1 && f["global_limit"] == before["global_limit"]+1
		})
		ordinary()
		for _, p := range completion[1:] {
			send(p)
		}
		verify(20, completionPayload)
		wait(func(f map[string]uint64) bool { return f["cached"] == 31 })
		send(other[0]) // A previously refused source takes the released slot.
		wait(func(f map[string]uint64) bool { return f["cached"] == 32 })
		send(own[0]) // Source 20 is below its own cap; the global cap wins now.
		wait(func(f map[string]uint64) bool { return f["global_limit"] == before["global_limit"]+2 })
		expire(32)
		for _, p := range other {
			send(p)
		}
		verify(24, otherPayload)
	}
	f := s.DetailedMetrics().IPv4Fragments
	if f["live_peak"] != 32 || f["source_peak"] != 8 || f["source_limit"] != 2 || f["global_limit"] != 4 || f["expired"] != 66 {
		t.Fatal("fragment quota/recovery counters", f)
	}
	if err := s.Stop(); err != nil {
		t.Fatal(err)
	}
	if s.DetailedMetrics().TCPExt["socket_buffer_bytes"] != 0 {
		t.Fatal("fragment shutdown retained aggregate storage")
	}
	for idle := 0; idle < 3; idle++ {
		time.Sleep(time.Second)
		if err := samples.sample(s); err != nil {
			t.Fatal(err)
		}
		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)
		t.Logf("FRAGMENT_IDLE second=%d heap=%d natural_gc=%d reservations=0", idle+1, mem.HeapAlloc, mem.NumGC-samples.initial.NumGC)
	}
	t.Logf("FRAGMENT_DATAGRAMS_OK mtu=1200,1380 sizes=8192,16384,65507 sources=7 expired=66 source_limit=2 global_limit=4 live_peak=32 source_peak=8 duplicates=%d", f["duplicates"])
}
