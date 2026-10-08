//go:build integration && capacity && linux

package wireguard

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/irctrakz/wgslirp/pkg/socket"
)

// Explicitly selected finite profile: sequential churn, full default capacity,
// and real TIME-WAIT expiry. No production timer overrides or forced GC.
func TestEncryptedChurnCapacity(t *testing.T) {
	baseline := runtime.NumGoroutine()
	if !t.Run("workload", runEncryptedCapacity) {
		return
	}
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > baseline+4 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > baseline+4 {
		t.Fatalf("workers survived cleanup: baseline=%d final=%d", baseline, n)
	}
}

func runEncryptedCapacity(t *testing.T) {
	started := time.Now()
	capacity := socket.DefaultConfig().MaxTCPFlows
	s, tun, responses := encryptedTestLink(t, func(port int) string { return fmt.Sprintf("127.0.0.1:%d", port) })
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	hostPort := uint16(listener.Addr().(*net.TCPAddr).Port)
	var heapPeak, rssPeak uint64
	phase := "churn"
	lastReport := time.Time{}
	sample := func() {
		t.Helper()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		stat, err := os.ReadFile("/proc/self/statm")
		if err != nil {
			t.Fatal(err)
		}
		fields := strings.Fields(string(stat))
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
		if time.Since(lastReport) >= 10*time.Second {
			t.Logf("CAPACITY_MEMORY phase=%s elapsed_ms=%d heap=%d heap_sys=%d stack=%d rss=%d rss_limit=%d workers=%d", phase, time.Since(started).Milliseconds(), m.HeapAlloc, m.HeapSys, m.StackInuse, rss, capacityRSSLimit, runtime.NumGoroutine())
			lastReport = time.Now()
		}
		if m.HeapAlloc > 192<<20 || rss > capacityRSSLimit || runtime.NumGoroutine() > 1024 {
			if dir := os.Getenv("WGSLIRP_FRAGMENT_PROFILE_DIR"); dir != "" {
				f, err := os.Create(filepath.Join(dir, "capacity-breach.pprof"))
				if err != nil {
					t.Errorf("create capacity profile: %v", err)
				} else {
					if err := pprof.WriteHeapProfile(f); err != nil {
						t.Errorf("write capacity profile: %v", err)
					}
					if err := f.Close(); err != nil {
						t.Errorf("close capacity profile: %v", err)
					}
				}
			}
			t.Fatalf("resource ceiling: heap=%d rss=%d rss_limit=%d workers=%d", m.HeapAlloc, rss, capacityRSSLimit, runtime.NumGoroutine())
		}
		if time.Since(started) > 6*time.Minute {
			t.Fatal("workload deadline")
		}
	}
	send := func(port uint16, seq, ack uint32, flags byte, payload []byte) {
		t.Helper()
		p := encryptedPacket(6, hostPort, seq, ack, flags, payload)
		binary.BigEndian.PutUint16(p[20:22], port)
		p[36], p[37] = 0, 0
		pseudo := append([]byte(nil), p[12:20]...)
		length := len(p) - 20
		pseudo = append(pseudo, 0, 6, byte(length>>8), byte(length))
		pseudo = append(pseudo, p[20:]...)
		binary.BigEndian.PutUint16(p[36:38], encryptedChecksum(pseudo))
		if err := tun.InjectToPeer(p); err != nil {
			t.Fatal(err)
		}
	}
	receive := func(port uint16, match func([]byte) bool) []byte {
		t.Helper()
		timer := time.NewTimer(3 * time.Second)
		defer timer.Stop()
		for {
			select {
			case p := <-responses:
				if len(p) >= 40 && p[9] == 6 && binary.BigEndian.Uint16(p[22:24]) == port && match(p) {
					return p
				}
			case <-timer.C:
				t.Fatalf("encrypted response deadline: guest port=%d", port)
			}
		}
	}
	waitFlows := func(want uint64) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for s.DetailedMetrics().TCP.ActiveFlows != want {
			if time.Now().After(deadline) {
				t.Fatalf("flow count=%d want=%d", s.DetailedMetrics().TCP.ActiveFlows, want)
			}
			time.Sleep(time.Millisecond)
		}
	}
	type connection struct {
		port     uint16
		host     *net.TCPConn
		seq, ack uint32
	}
	connect := func(port uint16) (connection, time.Duration) {
		t.Helper()
		begin := time.Now()
		send(port, 100, 0, 2, nil)
		p := receive(port, func(p []byte) bool { return p[33]&0x12 == 0x12 || p[33]&4 != 0 })
		elapsed := time.Since(begin)
		if p[33]&4 != 0 {
			t.Fatal("unexpected admission refusal")
		}
		_ = listener.SetDeadline(time.Now().Add(3 * time.Second))
		host, err := listener.AcceptTCP()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { host.Close() })
		c := connection{port: port, host: host, seq: 101, ack: binary.BigEndian.Uint32(p[24:28]) + 1}
		send(c.port, c.seq, c.ack, 0x10, nil)
		return c, elapsed
	}
	exchange := func(c *connection) {
		t.Helper()
		payload := bytes.Repeat([]byte{byte(c.port), byte(c.port >> 8)}, 512)
		_ = c.host.SetDeadline(time.Now().Add(3 * time.Second))
		send(c.port, c.seq, c.ack, 0x18, payload)
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(c.host, got); err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("host payload: %v", err)
		}
		c.seq += uint32(len(payload))
		if n, err := c.host.Write(payload); err != nil || n != len(payload) {
			t.Fatalf("host echo: n=%d err=%v", n, err)
		}
		got = got[:0]
		for len(got) < len(payload) {
			p := receive(c.port, func(p []byte) bool { return len(p) > 20+int(p[32]>>4)*4 || p[33]&5 != 0 })
			h := 20 + int(p[32]>>4)*4
			if h < 40 || h > len(p) || p[33]&5 != 0 || binary.BigEndian.Uint32(p[24:28]) != c.ack {
				t.Fatal("unexpected response sequence/flags")
			}
			got = append(got, p[h:]...)
			c.ack += uint32(len(p) - h)
			send(c.port, c.seq, c.ack, 0x10, nil)
		}
		if !bytes.Equal(got, payload) {
			t.Fatal("guest payload mismatch")
		}
	}
	var latencies []time.Duration
	for i := 0; i < 264; i++ {
		c, latency := connect(uint16(40000 + i))
		if i == 0 {
			t.Logf("COLD_SYN_ACK_US=%d", latency.Microseconds())
		}
		if i >= 8 {
			latencies = append(latencies, latency)
		}
		exchange(&c)
		send(c.port, c.seq, c.ack, 4, nil)
		waitFlows(0)
		c.host.Close()
		sample()
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	pct := func(p int) time.Duration { return latencies[(len(latencies)*p+99)/100-1] }
	if pct(95) > 250*time.Millisecond || latencies[len(latencies)-1] > time.Second {
		t.Fatal("warm handshake latency ceiling")
	}
	t.Logf("HANDSHAKES samples=%d p50_us=%d p95_us=%d p99_us=%d max_us=%d", len(latencies), pct(50).Microseconds(), pct(95).Microseconds(), pct(99).Microseconds(), latencies[len(latencies)-1].Microseconds())
	var live []connection
	phase = "fill"
	for i := 0; i < capacity; i++ {
		c, _ := connect(uint16(41000 + i))
		exchange(&c)
		live = append(live, c)
		waitFlows(uint64(i + 1))
		sample()
	}
	refuse := func(port uint16) {
		t.Helper()
		before := s.DetailedMetrics().Admission["tcp_flow_limit"]
		send(port, 100, 0, 2, nil)
		p := receive(port, func(p []byte) bool { return p[33]&0x16 != 0 })
		if p[33]&0x14 != 0x14 || s.DetailedMetrics().Admission["tcp_flow_limit"] != before+1 {
			t.Fatal("capacity refusal not signaled/accounted")
		}
		waitFlows(uint64(capacity))
	}
	refuse(42000)
	exchange(&live[0]) // Rejection cannot break an admitted connection.
	firstClose := time.Now()
	for i := range live {
		c := &live[i]
		_ = c.host.SetDeadline(time.Now().Add(3 * time.Second))
		if err := c.host.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		p := receive(c.port, func(p []byte) bool { return p[33]&5 != 0 })
		if p[33]&5 != 1 || binary.BigEndian.Uint32(p[24:28]) != c.ack {
			t.Fatal("missing ordered host FIN")
		}
		c.ack++
		send(c.port, c.seq, c.ack, 0x11, nil)
		c.seq++
		receive(c.port, func(p []byte) bool { return p[33]&0x10 != 0 && binary.BigEndian.Uint32(p[28:32]) == c.seq })
		var one [1]byte
		if n, err := c.host.Read(one[:]); n != 0 || err != io.EOF {
			t.Fatalf("host FIN completion: n=%d err=%v", n, err)
		}
		c.host.Close()
	}
	lastClose := time.Now()
	phase = "time_wait"
	refuse(42001)
	// The ordinary two-minute idle lifetime must not truncate four-minute TIME-WAIT.
	for time.Since(firstClose) < 239*time.Second {
		if s.DetailedMetrics().TCP.ActiveFlows != uint64(capacity) {
			t.Fatal("TIME-WAIT released capacity early")
		}
		sample()
		time.Sleep(time.Second)
	}
	deadline := lastClose.Add(245 * time.Second)
	for s.DetailedMetrics().TCP.ActiveFlows != 0 {
		if time.Now().After(deadline) {
			t.Fatal("TIME-WAIT failed to release capacity")
		}
		sample()
		time.Sleep(100 * time.Millisecond)
	}
	if time.Since(firstClose) < 240*time.Second {
		t.Fatal("TIME-WAIT duration was shortened")
	}
	c, _ := connect(42002)
	phase = "recovered"
	exchange(&c)
	send(c.port, c.seq, c.ack, 4, nil)
	waitFlows(0)
	c.host.Close()
	s.Stop()
	deadline = time.Now().Add(3 * time.Second)
	for s.DetailedMetrics().TCPExt["socket_buffer_bytes"] != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	m := s.DetailedMetrics()
	wantConnections := uint64(264 + capacity + 1)
	if m.TCP.Counters.ConnectionsCreated != wantConnections || m.TCP.Counters.ConnectionsClosed != wantConnections || m.Admission["tcp_flow_limit"] != 2 {
		t.Fatalf("unexpected lifecycle totals: %+v", m)
	}
	if m.TCP.ActiveFlows != 0 || m.TCPExt["dial_reserved"] != 0 || m.TCPExt["socket_buffer_bytes"] != 0 || m.TCP.DeliveryRefused != 0 {
		t.Fatalf("unclean final metrics: %+v", m)
	}
	sample()
	t.Logf("CAPACITY_ACCEPTED churn=264 cap=%d refusals=%d time_wait_ms=%d recovered=1 heap_peak=%d rss_peak=%d buffer_peak=%d elapsed_ms=%d", capacity, m.Admission["tcp_flow_limit"], time.Since(firstClose).Milliseconds(), heapPeak, rssPeak, m.TCPExt["socket_buffer_peak"], time.Since(started).Milliseconds())
}
