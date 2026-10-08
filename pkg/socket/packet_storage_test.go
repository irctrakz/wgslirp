package socket

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"testing"

	"github.com/irctrakz/wgslirp/pkg/core"
)

type packetConsumer func(core.Packet) error

func (f packetConsumer) ProcessPacket(p core.Packet) error { return f(p) }

func TestSynthesisReservationAndDeliveryOwnership(t *testing.T) {
	original := poolPolicy.Load()
	defer poolPolicy.Store(original)
	for _, pooling := range []uint32{0, 1} {
		poolPolicy.Store(&PoolConfig{Enabled: pooling == 1})
		for _, payloadSize := range []int{3, 472} {
			payload := bytes.Repeat([]byte{5, 6, 7}, (payloadSize+2)/3)[:payloadSize]
			capacity := 40 + payloadSize
			if pooling == 1 {
				capacity = pktSmall
			}
			budget := &resourceBudget{limit: capacity + 128}
			bridge := &tcpBridge{buffers: budget}
			p := bridge.buildIPv4TCP([4]byte{}, [4]byte{}, 1, 2, 3, 4, 0x10, payload)
			if p == nil {
				t.Fatal("first reservation failed")
			}
			assertBudget(t, budget, uint64(capacity+128))
			built := false
			if budget.buildPacket(1, false, func() []byte { built = true; return []byte{1} }) != nil || built {
				t.Fatal("builder ran before admission")
			}
			data := core.BorrowPacketData(p)
			if calculateChecksum(data[:20]) != 0 || tcpChecksum(data[20:], [4]byte{}, [4]byte{}) != 0 {
				t.Fatal("invalid synthesized checksum")
			}
			var retained core.Packet
			if !deliverPacket(packetConsumer(func(p core.Packet) error { retained = p; return nil }), p) {
				t.Fatal("delivery failed")
			}
			assertBudget(t, budget, uint64(capacity+128))
			core.ReleasePacket(retained)
			core.ReleasePacket(retained)
			assertBudget(t, budget, 0)
			for _, consumer := range []core.PacketProcessor{nil, packetConsumer(func(p core.Packet) error { return errors.New("reject") }), packetConsumer(func(p core.Packet) error { core.ReleasePacket(p); return errors.New("consumed") })} {
				p = bridge.buildIPv4TCP([4]byte{}, [4]byte{}, 1, 2, 3, 4, 0x10, nil)
				if deliverPacket(consumer, p) {
					t.Fatal("rejection accepted")
				}
				assertBudget(t, budget, 0)
			}
		}
	}
}

func TestPacketStorageBoundaries(t *testing.T) {
	original := poolPolicy.Load()
	defer poolPolicy.Store(original)
	for _, enabled := range []bool{false, true} {
		poolPolicy.Store(&PoolConfig{Enabled: enabled})
		for _, size := range []int{40, 80, 511, 512, 2048, 2049, 4096, 4097, 8192, 8193, 16384, 16385} {
			want := size
			if enabled {
				switch {
				case size <= 2048:
					want = 2048
				case size <= 4096:
					want = 4096
				case size <= 8192:
					want = 8192
				case size <= 16384:
					want = 16384
				}
			}
			budget := &resourceBudget{limit: want + bufferEntryAllowance}
			packet := budget.buildPacket(size, true, func() []byte { return bufMaybePool(size) })
			if packet == nil {
				t.Fatalf("admission failed: enabled=%t size=%d", enabled, size)
			}
			if cap(core.BorrowPacketData(packet)) != want {
				t.Fatalf("storage capacity mismatch: enabled=%t size=%d", enabled, size)
			}
			assertBudget(t, budget, uint64(want+bufferEntryAllowance))
			core.ReleasePacket(packet)
			core.ReleasePacket(packet)
			assertBudget(t, budget, 0)
		}
	}
}

func TestTinyPacketFreezesPoolingPolicy(t *testing.T) {
	original := poolPolicy.Swap(nil)
	defer poolPolicy.Store(original)
	buf := bufMaybePool(40)
	if cap(buf) != pktSmall {
		t.Fatal("default tiny packet must use the smallest pool class")
	}
	pktPut(buf)
	if ConfigurePooling(PoolConfig{}) == nil {
		t.Fatal("first tiny allocation did not freeze startup policy")
	}
}

func TestPacketPoolBoundAndCleanReuse(t *testing.T) {
	for _, capacity := range []int{pktSmall, pktMed, pktLarge, pktXL} {
		pool := packetPool(capacity)
		for len(pool) > 0 {
			<-pool
		}
		for i := 0; i < packetPoolEntries+10; i++ {
			pktPut(bytes.Repeat([]byte{0xff}, capacity))
		}
		if len(pool) != packetPoolEntries {
			t.Fatal("pool retention exceeded limit")
		}
		b := pktGet(capacity)
		if !bytes.Equal(b, make([]byte, capacity)) {
			t.Fatal("stale pool bytes exposed")
		}
	}
}

func TestUDPFragmentSynthesisBudgetAndChecksums(t *testing.T) {
	payload := bytes.Repeat([]byte{0x67}, 3000)
	fullCharge := 28 + len(payload) + 128
	s := NewSocketInterface(Config{SocketBufferCapBytes: fullCharge + 600 + 128})
	b := newUDPBridge(s)
	defer b.stop()
	f := &udpFlow{srcIP: [4]byte{10, 0, 0, 2}, dstIP: [4]byte{1, 1, 1, 1}, srcPort: 123, dstPort: 456}
	var packets [][]byte
	s.processor = packetConsumer(func(p core.Packet) error {
		defer core.ReleasePacket(p)
		data := core.BorrowPacketData(p)
		if len(data) > 600 || calculateChecksum(data[:20]) != 0 {
			t.Fatal("invalid fragment")
		}
		packets = append(packets, append([]byte(nil), data...))
		return nil
	})
	b.deliverDatagram(f, payload, 0, 64, 600)
	assertBudget(t, b.buffers, 0)
	var datagram []byte
	for _, p := range packets {
		datagram = append(datagram, p[20:]...)
	}
	if len(datagram) < 8 || !bytes.Equal(datagram[8:], payload) || udpChecksum(datagram, f.dstIP, f.srcIP) != 0 {
		t.Fatal("invalid reassembled UDP")
	}
	// A retained first fragment prevents further allocation; only that accepted
	// packet remains charged after the full-datagram scratch is released.
	var retained core.Packet
	s.processor = packetConsumer(func(p core.Packet) error {
		if retained != nil {
			t.Fatal("budget bypass")
		}
		retained = p
		return nil
	})
	b.deliverDatagram(f, payload, 0, 64, 600)
	if retained == nil {
		t.Fatal("no fragment delivered")
	}
	assertBudget(t, b.buffers, uint64(retained.Length()+128))
	core.ReleasePacket(retained)
	assertBudget(t, b.buffers, 0)
}

func TestICMPSynthesisReservations(t *testing.T) {
	s := NewSocketInterface(Config{SocketBufferCapBytes: 4096})
	s.processor = &captureProcessor{}
	body := []byte{0, 0, 0, 0, 0, 1, 0, 2, 3, 4}
	if err := s.processICMPReply(body, net.IPv4(1, 1, 1, 1), net.IPv4(10, 0, 0, 2)); err != nil {
		t.Fatal(err)
	}
	assertBudget(t, s.buffers(), 0)
	s = NewSocketInterface(Config{SocketBufferCapBytes: 1})
	if err := s.processICMPReply(body, net.IPv4(1, 1, 1, 1), net.IPv4(10, 0, 0, 2)); !errors.Is(err, ErrBufferLimit) {
		t.Fatal(err)
	}
	assertBudget(t, s.buffers(), 0)
}

func TestSYNACKRefusalRemovesCandidate(t *testing.T) {
	for _, limit := range []int{1, 4096} {
		b, f, _ := concurrentFlow(t)
		b.buffers.limit = limit
		b.parent.processor = packetConsumer(func(core.Packet) error { return errors.New("queue full") })
		f.stateMu.Lock()
		packet := b.buildIPv4TCP(f.dstIP, f.srcIP, f.dstPort, f.srcPort, 0, 1, 0x12, nil)
		err := b.sendSYNACKLocked(f, packet)
		closed := f.closed
		f.stateMu.Unlock()
		if err == nil || !closed {
			t.Fatal("refused SYN-ACK left candidate alive")
		}
		if limit == 1 && !errors.Is(err, ErrBufferLimit) {
			t.Fatal(err)
		}
		assertBudget(t, b.buffers, 0)
		b.stop()
	}
}

func TestICMPMarshalAccountsAllLiveCopies(t *testing.T) {
	body := make([]byte, 1032)
	body[0] = 8
	for i := 8; i < len(body); i++ {
		body[i] = byte(i)
	}
	s := NewSocketInterface(Config{SocketBufferCapBytes: 2*len(body) + 3*128})
	if packet, err := s.marshalICMPPacket(body); packet != nil || !errors.Is(err, ErrBufferLimit) {
		t.Fatal("three live copies fit in a two-copy budget")
	}
	assertBudget(t, s.buffers(), 0)
	s = NewSocketInterface(Config{SocketBufferCapBytes: 4096})
	packet, err := s.marshalICMPPacket(body)
	if err != nil {
		t.Fatal(err)
	}
	wire := core.BorrowPacketData(packet)
	if len(wire) != len(body) || calculateChecksum(wire) != 0 || !bytes.Equal(wire[4:], body[4:]) {
		t.Fatal("ICMP marshal changed payload/checksum")
	}
	assertBudget(t, s.buffers(), uint64(len(body)+128))
	core.ReleasePacket(packet)
	assertBudget(t, s.buffers(), 0)
}

func storageMemory() (uint64, string) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	status, _ := os.ReadFile("/proc/self/status")
	rss := "unavailable"
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			rss = strings.TrimSpace(line)
		}
	}
	return m.HeapAlloc, rss
}

// This finite fixture measures recovery of packet storage under contention.
// Explicit GC/scavenging separates retained storage from allocator caching; it
// does not claim natural RSS decay or representative production throughput.
func TestPacketStorageSaturationRecovery(t *testing.T) {
	budget := &resourceBudget{limit: 2 << 20}
	debug.FreeOSMemory()
	baseline, rssBefore := storageMemory()
	for round := 0; round < 8; round++ {
		held := make(chan core.Packet, 512)
		var workers sync.WaitGroup
		for i := 0; i < 16; i++ {
			workers.Add(1)
			go func() {
				defer workers.Done()
				for j := 0; j < 32; j++ {
					p := budget.buildPacket(8192, false, func() []byte {
						data := make([]byte, 8192)
						for i := range data {
							data[i] = byte(i)
						}
						return data
					})
					if p != nil {
						held <- p
					}
				}
			}()
		}
		workers.Wait()
		close(held)
		used, peak, limit, refused := budget.snapshot()
		if used == 0 || peak > limit || refused == 0 {
			t.Fatal("fixture did not saturate within bounds")
		}
		for p := range held {
			core.ReleasePacket(p)
		}
		assertBudget(t, budget, 0)
	}
	debug.FreeOSMemory()
	after, rssAfter := storageMemory()
	if after > baseline+(4<<20) {
		t.Fatalf("retained heap grew: before=%d after=%d", baseline, after)
	}
	_, peak, _, refused := budget.snapshot()
	t.Log(fmt.Sprintf("storage recovery: rounds=8 workers=16 attempts=4096 budget=2097152 peak=%d refused=%d heap_before=%d heap_after=%d rss_before=%q rss_after=%q", peak, refused, baseline, after, rssBefore, rssAfter))
}
