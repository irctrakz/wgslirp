package socket

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/irctrakz/wgslirp/internal/packetwire"
	"github.com/irctrakz/wgslirp/pkg/core"
)

// Independent fragment encoder; never uses the reassembler or packet builder.
func fragmentFixture(proto byte, id uint16, start int, more bool, data []byte) []byte {
	p := make([]byte, 20+len(data))
	p[0], p[8], p[9] = 0x45, 64, proto
	copy(p[12:16], []byte{10, 0, 0, 2})
	copy(p[16:20], []byte{127, 0, 0, 1})
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	binary.BigEndian.PutUint16(p[4:6], id)
	flags := uint16(start / 8)
	if more {
		flags |= 0x2000
	}
	binary.BigEndian.PutUint16(p[6:8], flags)
	copy(p[20:], data)
	fragmentChecksum(p)
	return p
}

func fragmentChecksum(p []byte) {
	p[10], p[11] = 0, 0
	binary.BigEndian.PutUint16(p[10:12], packetwire.Checksum(p[:20]))
}

func TestIPv4FragmentsOwnershipOrderingAndDuplicate(t *testing.T) {
	for _, proto := range []byte{1, 6, 17} {
		t.Run(string(rune('A'+proto)), func(t *testing.T) {
			budget := &resourceBudget{limit: 2 * ipv4FragmentCharge}
			r := newIPv4Fragments(budget, 2*ipv4FragmentCharge)
			defer r.close()
			now := time.Now()
			data := []byte("abcdefghijklmnopqr")
			last := fragmentFixture(proto, 1, 16, false, data[16:])
			if out, _, err := r.add(last, now); out != nil || err != nil {
				t.Fatal(out, err)
			}
			// Retained bytes must survive reuse of the caller's borrowed storage.
			last[20] = '!'
			middle := fragmentFixture(proto, 1, 8, true, data[8:16])
			r.add(middle, now)
			r.add(middle, now.Add(time.Second))
			out, release, err := r.add(fragmentFixture(proto, 1, 0, true, data[:8]), now.Add(2*time.Second))
			if err != nil || !bytes.Equal(out[20:], data) || packetwire.Checksum(out[:20]) != 0 || binary.BigEndian.Uint16(out[6:8]) != 0 {
				t.Fatal("assembly", err, out)
			}
			assertBudget(t, budget, ipv4FragmentCharge)
			if r.snapshot()["duplicates"] != 1 || r.snapshot()["completed"] != 1 || r.snapshot()["live"] != 1 {
				t.Fatal(r.snapshot())
			}
			r.close() // Detached completion stays reserved even when the cache closes.
			assertBudget(t, budget, ipv4FragmentCharge)
			r.limit = ipv4FragmentCharge
			if _, _, err := r.add(fragmentFixture(proto, 2, 0, true, data[:8]), now); !errors.Is(err, ErrIPv4FragmentLimit) {
				t.Fatal("dispatch reservation did not enforce admission", err)
			}
			release()
			release()
			assertBudget(t, budget, 0)
		})
	}
}

func TestIPv4FragmentsRejectAndReleaseConflicts(t *testing.T) {
	for _, kind := range []string{"overlap", "different duplicate", "final length", "DSCP", "ECN"} {
		t.Run(kind, func(t *testing.T) {
			budget := &resourceBudget{limit: 2 * ipv4FragmentCharge}
			r := newIPv4Fragments(budget, 2*ipv4FragmentCharge)
			defer r.close()
			now := time.Now()
			first := fragmentFixture(17, 1, 0, true, make([]byte, 16))
			r.add(first, now)
			p := fragmentFixture(17, 1, 8, true, make([]byte, 8))
			switch kind {
			case "different duplicate":
				p = append([]byte(nil), first...)
				p[20] = 1
			case "final length":
				p = fragmentFixture(17, 1, 8, false, make([]byte, 8))
			case "DSCP":
				p = fragmentFixture(17, 1, 16, false, make([]byte, 8))
				p[1] = 4
			case "ECN":
				p = fragmentFixture(17, 1, 16, false, make([]byte, 8))
				p[1] = 3
			}
			fragmentChecksum(p)
			if out, _, err := r.add(p, now); out != nil || !errors.Is(err, ErrMalformedPacket) {
				t.Fatal("accepted conflict", err)
			}
			assertBudget(t, budget, 0)
			if r.snapshot()["live"] != 0 {
				t.Fatal(r.snapshot())
			}
		})
	}
}

func TestIPv4FragmentsBoundsAndAdmission(t *testing.T) {
	for _, kind := range []string{"alignment", "overflow", "DF", "checksum", "empty", "options", "source", "global", "aggregate", "ranges", "datagrams"} {
		t.Run(kind, func(t *testing.T) {
			budget := &resourceBudget{limit: 100 * ipv4FragmentCharge}
			r := newIPv4Fragments(budget, 100*ipv4FragmentCharge)
			defer r.close()
			now := time.Now()
			p := fragmentFixture(17, 1, 0, true, make([]byte, 8))
			want := ErrMalformedPacket
			switch kind {
			case "alignment":
				p = fragmentFixture(17, 1, 0, true, make([]byte, 9))
			case "overflow":
				p = fragmentFixture(17, 1, 65528, false, make([]byte, 8))
			case "DF":
				p[6] |= 0x40
				fragmentChecksum(p)
			case "checksum":
				p[10] ^= 1
			case "empty":
				p = fragmentFixture(17, 1, 8, false, nil)
			case "options":
				p[0] = 0x46
				p[10], p[11] = 0, 0
				binary.BigEndian.PutUint16(p[10:12], packetwire.Checksum(p[:24]))
				want = ErrUnsupportedIPOptions
			case "source":
				for i := 0; i < ipv4FragmentSources; i++ {
					r.add(fragmentFixture(17, uint16(i+2), 0, true, make([]byte, 8)), now)
				}
				want = ErrIPv4FragmentLimit
			case "global":
				r.limit = ipv4FragmentCharge - 1
				want = ErrIPv4FragmentLimit
			case "aggregate":
				budget.limit = ipv4FragmentCharge - 1
				want = ErrBufferLimit
			case "ranges":
				for i := 0; i < ipv4FragmentRanges; i++ {
					r.add(fragmentFixture(17, 1, i*8, true, make([]byte, 8)), now)
				}
				p = fragmentFixture(17, 1, ipv4FragmentRanges*8, true, make([]byte, 8))
			case "datagrams":
				for i := 0; i < ipv4FragmentDatagrams; i++ {
					q := fragmentFixture(17, uint16(i+2), 0, true, make([]byte, 8))
					q[15] = byte(i + 10)
					fragmentChecksum(q)
					r.add(q, now)
				}
				want = ErrIPv4FragmentLimit
			}
			if _, _, err := r.add(p, now); !errors.Is(err, want) {
				t.Fatal(kind, err)
			}
			if metric := map[string]string{"source": "source_limit", "datagrams": "global_limit", "global": "storage_limit", "aggregate": "aggregate_limit"}[kind]; metric != "" && r.snapshot()[metric] != 1 {
				t.Fatal("admission counter attribution", kind, r.snapshot())
			}
			r.close()
			assertBudget(t, budget, 0)
		})
	}
}

func TestIPv4FragmentsMaximumDatagram(t *testing.T) {
	budget := &resourceBudget{limit: ipv4FragmentCharge}
	r := newIPv4Fragments(budget, ipv4FragmentCharge)
	defer r.close()
	body := make([]byte, 65515)
	for i := range body {
		body[i] = byte(i)
	}
	for offset := 0; offset < len(body); offset += 512 {
		end := minInt(offset+512, len(body))
		out, release, err := r.add(fragmentFixture(17, 7, offset, end < len(body), body[offset:end]), time.Unix(1, 0))
		if err != nil {
			t.Fatal(err)
		}
		if end == len(body) {
			if len(out) != 65535 || !bytes.Equal(out[20:], body) {
				t.Fatal("maximum datagram mismatch")
			}
			release()
		} else if out != nil {
			t.Fatal("completed with a gap")
		}
	}
	assertBudget(t, budget, 0)
}

func TestIPv4FragmentsStorageTiers(t *testing.T) {
	// The fixed metadata reservation must cover inline bytes/ranges plus an
	// allowance for map entries, even while a full-size buffer is owned too.
	if size := unsafe.Sizeof(fragmentDatagram{}); size > 4096-512 {
		t.Fatalf("assembly metadata %d exceeds reserved allowance", size)
	}
	for _, size := range []int{ipv4FragmentInline - 20, ipv4FragmentInline - 19, 8192, 65515} {
		for _, reverse := range []bool{false, true} {
			budget := &resourceBudget{limit: ipv4FragmentCharge}
			r := newIPv4Fragments(budget, ipv4FragmentCharge)
			body := make([]byte, size)
			for i := range body {
				body[i] = byte(i)
			}
			var packets [][]byte
			for offset := 0; offset < size; offset += 1176 {
				end := minInt(offset+1176, size)
				packets = append(packets, fragmentFixture(17, 1, offset, end < size, body[offset:end]))
			}
			if reverse {
				for i, j := 0, len(packets)-1; i < j; i, j = i+1, j-1 {
					packets[i], packets[j] = packets[j], packets[i]
				}
			}
			var completed []byte
			var done func()
			for i, p := range packets {
				out, release, err := r.add(p, time.Unix(1, 0))
				if err != nil {
					t.Fatal(size, reverse, err)
				}
				assertBudget(t, budget, ipv4FragmentCharge)
				if out != nil {
					completed, done = out, release
				} else {
					// Replayed ranges must compare retained bytes across either
					// tier without promotion, allocation or another reservation.
					if _, _, err := r.add(p, time.Unix(2, 0)); err != nil {
						t.Fatal("duplicate", i, err)
					}
				}
				// The reassembler borrows input only for add, including ranges
				// later copied from inline storage during promotion.
				for j := 20; j < len(p); j++ {
					p[j] ^= 0xff
				}
			}
			if len(completed) != 20+size || !bytes.Equal(completed[20:], body) || packetwire.Checksum(completed[:20]) != 0 {
				t.Fatal("storage tier corrupted packet", size, reverse)
			}
			wantCap := ipv4FragmentInline
			if size+20 > ipv4FragmentInline {
				wantCap = 65535
			}
			if cap(completed) != wantCap {
				t.Fatal("unexpected storage tier", size, cap(completed))
			}
			r.close() // Dispatch still owns storage and its fixed reservation.
			assertBudget(t, budget, ipv4FragmentCharge)
			done()
			done()
			assertBudget(t, budget, 0)
		}
	}
}

func TestIPv4FragmentsPromotedStorageDisposal(t *testing.T) {
	for _, expire := range []bool{false, true} {
		budget := &resourceBudget{limit: ipv4FragmentCharge}
		r := newIPv4Fragments(budget, ipv4FragmentCharge)
		now := time.Unix(1, 0)
		p := fragmentFixture(17, 1, 4096, true, make([]byte, 8))
		if _, _, err := r.add(p, now); err != nil {
			t.Fatal(err)
		}
		if expire {
			for _, d := range r.expire(now.Add(ipv4FragmentLifetime)) {
				assertBudget(t, budget, ipv4FragmentCharge)
				r.release(d)
			}
		} else {
			p[20] = 1
			if _, _, err := r.add(p, now); !errors.Is(err, ErrMalformedPacket) {
				t.Fatal("conflicting full-storage duplicate accepted", err)
			}
		}
		assertBudget(t, budget, 0)
		if r.snapshot()["live"] != 0 {
			t.Fatal("promoted storage retained ownership")
		}
		r.close()
	}
}

func TestIPv4FragmentConfigurationAndShutdown(t *testing.T) {
	if !DefaultConfig().IPv4Reassembly {
		t.Fatal("default configuration must enable bounded reassembly")
	}
	if (Config{}).Effective().IPv4Reassembly {
		t.Fatal("zero-value library configuration must preserve explicit false")
	}
	base := DefaultConfig()
	for _, value := range []string{"true", "false", "invalid"} {
		cfg, err := ConfigFromEnv(base, func(key string) (string, bool) { return value, key == "IPV4_REASSEMBLY" })
		if value == "invalid" {
			if err == nil {
				t.Fatal("invalid boolean accepted")
			}
			continue
		}
		if err != nil || cfg.IPv4Reassembly != (value == "true") {
			t.Fatal(cfg, err)
		}
	}
	base.IPv4Reassembly = true
	base.IPv4FragmentBufferCapBytes = ipv4FragmentCharge - 1
	if err := base.Validate(); err == nil {
		t.Fatal("unusable fragment budget accepted")
	}
	base.IPv4FragmentBufferCapBytes = 0
	base.Protocol = "ip4:tcp"
	s := NewSocketInterface(base)
	s.SetPacketProcessor(&captureProcessor{})
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Stop() })
	first := fragmentFixture(17, 1, 0, true, make([]byte, 8))
	if err := s.WritePacket(core.NewPacket(first)); err != nil {
		t.Fatal(err)
	}
	if s.DetailedMetrics().IPv4Fragments["cached"] != 1 {
		t.Fatal("fragment not retained")
	}
	// A malformed UDP completion must release the dispatch reservation too.
	if err := s.WritePacket(core.NewPacket(fragmentFixture(17, 1, 8, false, []byte{1}))); !errors.Is(err, ErrMalformedPacket) {
		t.Fatal(err)
	}
	if s.DetailedMetrics().IPv4Fragments["reserved_bytes"] != 0 {
		t.Fatal("invalid transport retained a fragment reservation")
	}
	if err := s.WritePacket(core.NewPacket(first)); err != nil {
		t.Fatal(err)
	}
	s.Stop()
	assertBudget(t, s.buffers(), 0)
	if s.DetailedMetrics().IPv4Fragments["live"] != 0 {
		t.Fatal("shutdown retained fragment ownership")
	}
}

func TestIPv4FragmentsTimeoutSuppression(t *testing.T) {
	for _, kind := range []string{"no first", "multicast", "invalid source", "ICMP error"} {
		t.Run(kind, func(t *testing.T) {
			b, _, capture := concurrentFlow(t)
			r := newIPv4Fragments(b.buffers, DefaultIPv4FragmentBufferCap)
			b.parent.fragments = r
			defer r.close()
			p := fragmentFixture(17, 1, 0, true, make([]byte, 8))
			switch kind {
			case "no first":
				p = fragmentFixture(17, 1, 8, false, []byte{1})
			case "multicast":
				p[16] = 224
			case "invalid source":
				p[12] = 0
			case "ICMP error":
				p[9], p[20] = 1, 3
			}
			fragmentChecksum(p)
			now := time.Unix(1, 0)
			if _, _, err := r.add(p, now); err != nil {
				t.Fatal(err)
			}
			b.parent.expireIPv4Fragments(now.Add(ipv4FragmentLifetime))
			if len(capture.snapshot()) != 0 {
				t.Fatal("unsuitable timeout feedback emitted")
			}
			assertBudget(t, b.buffers, 0)
		})
	}
}

func TestIPv4FragmentsTimeoutDeliveryOutsideCacheLock(t *testing.T) {
	b, _, _ := concurrentFlow(t)
	r := newIPv4Fragments(b.buffers, DefaultIPv4FragmentBufferCap)
	b.parent.fragments = r
	defer r.close()
	delivered := false
	b.parent.processor = packetConsumer(func(p core.Packet) error {
		// A callback may inspect diagnostics. It must never inherit the cache lock.
		if r.snapshot()["live"] != 1 {
			t.Error("timeout released before delivery")
		}
		delivered = true
		core.ReleasePacket(p)
		return nil
	})
	now := time.Unix(1, 0)
	if _, _, err := r.add(fragmentFixture(17, 1, 0, true, make([]byte, 8)), now); err != nil {
		t.Fatal(err)
	}
	b.parent.expireIPv4Fragments(now.Add(ipv4FragmentLifetime))
	if !delivered {
		t.Fatal("timeout feedback missing")
	}
	assertBudget(t, b.buffers, 0)
}

func TestIPv4FragmentsExpiryFeedbackAndECN(t *testing.T) {
	b, f, capture := concurrentFlow(t)
	_ = f
	r := newIPv4Fragments(b.buffers, DefaultIPv4FragmentBufferCap)
	b.parent.fragments = r
	defer r.close()
	now := time.Now()
	p := fragmentFixture(17, 1, 0, true, make([]byte, 8))
	r.add(p, now)
	r.add(p, now.Add(59*time.Second))
	b.parent.expireIPv4Fragments(now.Add(60 * time.Second))
	packets := capture.snapshot()
	if len(packets) != 1 || packets[0][20] != 11 || packets[0][21] != 1 || !bytes.Equal(packets[0][28:], p) {
		t.Fatal("timeout feedback", packets)
	}
	assertBudget(t, b.buffers, 0)
	first := fragmentFixture(17, 2, 0, true, make([]byte, 8))
	first[1] = 2
	fragmentChecksum(first)
	r.add(first, now)
	last := fragmentFixture(17, 2, 8, false, make([]byte, 1))
	last[1] = 3
	fragmentChecksum(last)
	out, release, err := r.add(last, now)
	if err != nil || out[1]&3 != 3 {
		t.Fatal("lost CE", err)
	}
	release()
	// Protocol is part of the key; equal IDs from different transports cannot mix.
	r.add(fragmentFixture(6, 3, 0, true, make([]byte, 8)), now)
	r.add(fragmentFixture(17, 3, 8, false, make([]byte, 1)), now)
	if r.snapshot()["cached"] != 2 {
		t.Fatal("protocol collision")
	}
}

func TestIPv4FragmentsConcurrentShutdownAndSnapshots(t *testing.T) {
	budget := &resourceBudget{limit: DefaultIPv4FragmentBufferCap}
	r := newIPv4Fragments(budget, DefaultIPv4FragmentBufferCap)
	var workers sync.WaitGroup
	for i := 0; i < 16; i++ {
		workers.Add(1)
		go func(id int) {
			defer workers.Done()
			for j := 0; j < 32; j++ {
				p := fragmentFixture(17, uint16(id*32+j), 0, true, make([]byte, 8))
				p[15] = byte(id + 2)
				fragmentChecksum(p)
				r.add(p, time.Now())
				r.snapshot()
				r.close()
			}
		}(i)
	}
	workers.Wait()
	r.close()
	r.close()
	assertBudget(t, budget, 0)
}

func FuzzIPv4FragmentReassembly(f *testing.F) {
	f.Add(fragmentFixture(17, 1, 0, true, make([]byte, 8)), fragmentFixture(17, 1, 8, false, []byte{1}))
	f.Fuzz(func(t *testing.T, a, b []byte) {
		budget := &resourceBudget{limit: 2 * ipv4FragmentCharge}
		r := newIPv4Fragments(budget, 2*ipv4FragmentCharge)
		for _, p := range [][]byte{a, b} {
			out, release, err := r.add(p, time.Unix(1, 0))
			if err == nil && out != nil {
				if _, _, err := packetwire.ParseIPv4(out); err != nil {
					t.Fatal(err)
				}
			}
			if release != nil {
				release()
				release()
			}
		}
		r.close()
		assertBudget(t, budget, 0)
	})
}
