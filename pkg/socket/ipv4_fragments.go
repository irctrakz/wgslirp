package socket

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"github.com/irctrakz/wgslirp/internal/packetwire"
)

const (
	DefaultIPv4FragmentBufferCap = 4 * 1024 * 1024
	ipv4FragmentDatagrams        = 32
	ipv4FragmentSources          = 8 // live datagrams per source, including dispatch
	ipv4FragmentRanges           = 128
	ipv4FragmentLifetime         = 60 * time.Second
	ipv4FragmentInline           = 2048
	// Full wire allocation plus inline storage, compact ranges and map allowance.
	// Reserve both tiers up front so promotion never needs new admission or an
	// unaccounted transient copy. Completion reuses the active storage tier.
	ipv4FragmentCharge = 65535 + 4096
)

var ErrIPv4FragmentLimit = fmt.Errorf("%w: IPv4 fragment storage limit", ErrBufferLimit)

type fragmentKey struct {
	src, dst [4]byte
	id       uint16
	protocol byte
}

type fragmentRange struct {
	start, end uint16
	more       bool
}

type fragmentDatagram struct {
	key                 fragmentKey
	data                []byte
	inline              [ipv4FragmentInline]byte
	ranges              [ipv4FragmentRanges]fragmentRange
	count, covered, end int
	first               bool
	dscp, ecn           byte
	deadline            time.Time
}

// The mutex protects cache membership, live dispatch reservations and counters.
// It may acquire the aggregate budget lock, never a flow lock or callback.
type ipv4Fragments struct {
	mu                                                     sync.Mutex
	budget                                                 *resourceBudget
	limit, used, live                                      int
	entries                                                map[fragmentKey]*fragmentDatagram
	sources                                                map[[4]byte]int
	received, completed, duplicates, rejected, expired     uint64
	sourceLimit, globalLimit, storageLimit, aggregateLimit uint64
	livePeak, sourcePeak                                   uint64
}

func newIPv4Fragments(budget *resourceBudget, limit int) *ipv4Fragments {
	return &ipv4Fragments{budget: budget, limit: limit, entries: make(map[fragmentKey]*fragmentDatagram), sources: make(map[[4]byte]int)}
}

// add borrows packet only during this call. nil output means a valid fragment
// was retained. Completed output owns its reservation until release is called.
// now is supplied by the owner so expiry and insertion are independently testable.
func (r *ipv4Fragments) add(packet []byte, now time.Time) ([]byte, func(), error) {
	fragment := len(packet) >= 8 && binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0
	if fragment {
		r.mu.Lock()
		r.received++
		r.mu.Unlock()
	}
	rejectHeader := func(err error) ([]byte, func(), error) {
		if fragment {
			r.mu.Lock()
			r.rejected++
			r.mu.Unlock()
		}
		return nil, nil, err
	}
	p, _, err := packetwire.ParseIPv4Header(packet)
	if err != nil {
		return rejectHeader(err)
	}
	flags := binary.BigEndian.Uint16(p[6:8])
	if flags&0x3fff == 0 {
		return p, func() {}, nil
	}
	if p[9] != 1 && p[9] != 6 && p[9] != 17 {
		return rejectHeader(ErrUnsupportedFragment)
	}
	start, size := int(flags&0x1fff)*8, len(p)-20
	more := flags&0x2000 != 0
	if flags&0x4000 != 0 || size == 0 || start+size > 65515 || (more && size%8 != 0) {
		return rejectHeader(fmt.Errorf("%w: IPv4 fragment bounds/flags", ErrMalformedPacket))
	}
	k := fragmentKey{id: binary.BigEndian.Uint16(p[4:6]), protocol: p[9]}
	copy(k.src[:], p[12:16])
	copy(k.dst[:], p[16:20])
	r.mu.Lock()
	defer r.mu.Unlock()
	d := r.entries[k]
	if d != nil && !now.Before(d.deadline) {
		r.rejected++
		// Maintenance owns timeout feedback and disposal, including fragment zero.
		return nil, nil, fmt.Errorf("%w: expired IPv4 assembly", ErrMalformedPacket)
	}
	if d == nil {
		limited := false
		switch {
		case r.sources[k.src] >= ipv4FragmentSources:
			r.sourceLimit++
			limited = true
		case r.live >= ipv4FragmentDatagrams:
			r.globalLimit++
			limited = true
		case ipv4FragmentCharge > r.limit-r.used:
			r.storageLimit++
			limited = true
		}
		if limited {
			r.rejected++
			return nil, nil, ErrIPv4FragmentLimit
		}
		if !r.budget.acquire(ipv4FragmentCharge) {
			r.aggregateLimit++
			r.rejected++
			return nil, nil, ErrBufferLimit
		}
		d = &fragmentDatagram{key: k, end: -1, dscp: p[1] & 0xfc, deadline: now.Add(ipv4FragmentLifetime)}
		d.data = d.inline[:]
		r.entries[k] = d
		r.live++
		r.used += ipv4FragmentCharge
		r.sources[k.src]++
		if uint64(r.live) > r.livePeak {
			r.livePeak = uint64(r.live)
		}
		if uint64(r.sources[k.src]) > r.sourcePeak {
			r.sourcePeak = uint64(r.sources[k.src])
		}
	}
	fail := func(reason string) ([]byte, func(), error) {
		r.rejected++
		delete(r.entries, k)
		r.releaseLocked(d)
		return nil, nil, fmt.Errorf("%w: IPv4 fragment %s", ErrMalformedPacket, reason)
	}
	ecn := d.ecn | 1<<(p[1]&3)
	// Never invent congestion capability or lose a CE indication. Mixed ECT
	// codepoints without CE are rejected conservatively (RFC 3168 section 5.3).
	if d.dscp != p[1]&0xfc || (ecn&1 != 0 && ecn != 1) || (ecn == 6) {
		return fail("inconsistent DSCP/ECN")
	}
	end := start + size
	if d.end >= 0 && (end > d.end || (!more && end != d.end) || (more && end >= d.end)) {
		return fail("inconsistent final length")
	}
	for i := 0; i < d.count; i++ {
		span := d.ranges[i]
		spanStart, spanEnd := int(span.start), int(span.end)
		if spanStart == start && spanEnd == end && span.more == more && bytes.Equal(d.data[20+start:20+end], p[20:]) {
			d.ecn = ecn
			r.duplicates++
			return nil, nil, nil
		}
		if start < spanEnd && end > spanStart {
			return fail("overlap")
		}
		if !more && spanEnd >= end {
			return fail("conflicting final fragment")
		}
	}
	if d.count == ipv4FragmentRanges {
		return fail("range limit")
	}
	if 20+end > len(d.data) {
		// At most one promotion. Both allocations remain covered by the fixed
		// reservation, including while the old inline bytes are copied.
		data := make([]byte, 65535)
		copy(data, d.data)
		d.data = data
	}
	copy(d.data[20+start:20+end], p[20:])
	d.ranges[d.count] = fragmentRange{uint16(start), uint16(end), more}
	d.count++
	d.covered += size
	d.ecn = ecn
	if start == 0 {
		copy(d.data[:20], p[:20])
		d.first = true
	}
	if !more {
		d.end = end
	}
	if !d.first || d.end < 0 || d.covered != d.end {
		return nil, nil, nil
	}
	delete(r.entries, k)
	r.completed++
	out := d.data[:20+d.end]
	if d.ecn&8 != 0 {
		out[1] = d.dscp | 3
	}
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	binary.BigEndian.PutUint16(out[6:8], 0)
	out[10], out[11] = 0, 0
	binary.BigEndian.PutUint16(out[10:12], packetwire.Checksum(out[:20]))
	var once sync.Once
	return out, func() { once.Do(func() { r.mu.Lock(); defer r.mu.Unlock(); r.releaseLocked(d) }) }, nil
}

func (r *ipv4Fragments) releaseLocked(d *fragmentDatagram) {
	r.used -= ipv4FragmentCharge
	r.live--
	r.sources[d.key.src]--
	if r.sources[d.key.src] == 0 {
		delete(r.sources, d.key.src)
	}
	r.budget.release(ipv4FragmentCharge)
}

// expire detaches ownership under the cache lock; delivery/release occurs outside
// it. The owner joins maintenance before close, which releases only cached entries.
func (r *ipv4Fragments) expire(now time.Time) []*fragmentDatagram {
	r.mu.Lock()
	defer r.mu.Unlock()
	var expired []*fragmentDatagram
	for k, d := range r.entries {
		if !now.Before(d.deadline) {
			delete(r.entries, k)
			r.expired++
			expired = append(expired, d)
		}
	}
	return expired
}

func (r *ipv4Fragments) release(d *fragmentDatagram) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.releaseLocked(d)
}

func (r *ipv4Fragments) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, d := range r.entries {
		delete(r.entries, k)
		r.releaseLocked(d)
	}
}

func (r *ipv4Fragments) snapshot() map[string]uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return map[string]uint64{"received": r.received, "completed": r.completed, "duplicates": r.duplicates, "rejected": r.rejected, "expired": r.expired, "cached": uint64(len(r.entries)), "live": uint64(r.live), "reserved_bytes": uint64(r.used), "limit_bytes": uint64(r.limit), "source_limit": r.sourceLimit, "global_limit": r.globalLimit, "storage_limit": r.storageLimit, "aggregate_limit": r.aggregateLimit, "live_peak": r.livePeak, "source_peak": r.sourcePeak}
}
