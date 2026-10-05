package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/irctrakz/wgslirp/pkg/logging"
	"github.com/irctrakz/wgslirp/pkg/socket"
	wg "github.com/irctrakz/wgslirp/pkg/wireguard"
)

type metricsSnapshot struct {
	SchemaVersion uint64            `json:"schema_version"`
	WGAvailable   bool              `json:"wg_available"`
	Admission     map[string]uint64 `json:"admission"`
	IPv4Fragments map[string]uint64 `json:"ipv4_fragments,omitempty"`
	Timestamp     string            `json:"ts"`
	Total         map[string]uint64 `json:"total"`
	TCP           map[string]uint64 `json:"tcp"`
	UDP           map[string]uint64 `json:"udp"`
	TCPExt        map[string]uint64 `json:"tcp_ext"`
	TCPActive     uint64            `json:"tcp_active"`
	UDPActive     uint64            `json:"udp_active"`
	WG            map[string]uint64 `json:"wg"`
	Flow          map[string]uint64 `json:"flow"`
	Proc          map[string]uint64 `json:"proc"`
	RT            map[string]uint64 `json:"rt"`
	EgressLim     map[string]uint64 `json:"egress_limiter"`
	FlowLim       map[string]uint64 `json:"flow_limiter"`
	Srv           map[string]uint64 `json:"srv_limits"`
	// Fallback removed
}

func metricsInterval(iv string) (time.Duration, error) {
	iv = strings.TrimSpace(iv)
	if iv == "" {
		iv = "30s"
	}
	d, err := time.ParseDuration(iv)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("invalid METRICS_INTERVAL: must be a positive duration")
	}
	return d, nil
}

func runMetricsReporter(ctx context.Context, d time.Duration, si *socket.SocketInterface, tun *wg.WGTun, dev wg.DeviceHandle, format string) {
	ticker := time.NewTicker(d)
	defer ticker.Stop()
	r := &metricsReporter{}
	for {
		r.dump(si, tun, dev, format)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

type socketMetricsSource interface {
	DetailedMetrics() socket.SocketDetailedMetrics
}
type tunMetricsSource interface{ Metrics() wg.TUNMetrics }
type deviceStateSource interface{ IpcGet() (string, error) }

// Interval state belongs to a reporter, never to the process or a bridge.
type metricsReporter struct {
	mu      sync.Mutex
	lastRTO uint64
}

func (r *metricsReporter) rtoDelta(current uint64) uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	delta := current
	if current >= r.lastRTO {
		delta = current - r.lastRTO
	}
	r.lastRTO = current
	return delta
}

// One-shot reporting has no prior interval. Periodic reporting retains its own instance.
func dumpMetrics(si socketMetricsSource, tun tunMetricsSource, dev deviceStateSource, format string) {
	(&metricsReporter{}).dump(si, tun, dev, format)
}
func (r *metricsReporter) dump(si socketMetricsSource, tun tunMetricsSource, dev deviceStateSource, format string) {
	snap, hstat := r.snapshot(si, tun, dev)
	r.emit(snap, hstat, format)
}

func (r *metricsReporter) snapshot(si socketMetricsSource, tun tunMetricsSource, dev deviceStateSource) (metricsSnapshot, map[string]uint64) {
	dm := si.DetailedMetrics()
	wgM := tun.Metrics()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	// Optional: handshake status from WG device
	hstat := map[string]uint64{}
	wgAvailable := false
	if dev != nil {
		if state, err := dev.IpcGet(); err == nil {
			hstat = summarizeWGHandshakes(state)
			wgAvailable = true
		}
	}
	// Compute per-interval RTO delta
	rtoCur := uint64(0)
	if dm.TCPExt != nil {
		if v, ok := dm.TCPExt["rto"]; ok {
			rtoCur = v
		}
	}
	rtoDelta := r.rtoDelta(rtoCur)

	snap := metricsSnapshot{
		SchemaVersion: 1, WGAvailable: wgAvailable,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Total: map[string]uint64{
			"conns_created": dm.Total.ConnectionsCreated,
			"conns_closed":  dm.Total.ConnectionsClosed,
			"pkts_sent":     dm.Total.PacketsSent,
			"pkts_recv":     dm.Total.PacketsReceived,
			"bytes_sent":    dm.Total.BytesSent,
			"bytes_recv":    dm.Total.BytesReceived,
			"errors":        dm.Total.Errors,
		},
		TCP: map[string]uint64{
			"pkts_sent":        dm.TCP.Counters.PacketsSent,
			"pkts_recv":        dm.TCP.Counters.PacketsReceived,
			"bytes_sent":       dm.TCP.Counters.BytesSent,
			"bytes_recv":       dm.TCP.Counters.BytesReceived,
			"errors":           dm.TCP.Counters.Errors,
			"delivery_refused": dm.TCP.DeliveryRefused,
		},
		UDP: func() map[string]uint64 {
			m := map[string]uint64{
				"pkts_sent":        dm.UDP.Counters.PacketsSent,
				"pkts_recv":        dm.UDP.Counters.PacketsReceived,
				"bytes_sent":       dm.UDP.Counters.BytesSent,
				"bytes_recv":       dm.UDP.Counters.BytesReceived,
				"errors":           dm.UDP.Counters.Errors,
				"delivery_refused": dm.UDP.DeliveryRefused,
			}
			if dm.UDPExt != nil {
				if v, ok := dm.UDPExt["tx_enq"]; ok {
					m["tx_enq"] = v
				}
				if v, ok := dm.UDPExt["tx_proc"]; ok {
					m["tx_proc"] = v
				}
			}
			return m
		}(),
		TCPExt: func() map[string]uint64 {
			m := map[string]uint64{}
			if dm.TCPExt != nil {
				for k, v := range dm.TCPExt {
					m[k] = v
				}
			}
			m["rto_delta"] = rtoDelta
			return m
		}(),
		Admission:     dm.Admission,
		IPv4Fragments: dm.IPv4Fragments,
		TCPActive:     dm.TCP.ActiveFlows,
		UDPActive:     dm.UDP.ActiveFlows,
		WG: map[string]uint64{
			"plaintext_from_wg": wgM.PlaintextFromWG,
			"plaintext_to_wg":   wgM.PlaintextToWG,
			"queue_drops":       wgM.QueueDrops,
		},
		// Handshake summary (if available)
		// keys: peers, fresh, stale, oldest_sec, newest_sec
		// 0-values if not available
		// Included in both JSON and text formats

		// Flow removed
		Proc: dm.Processor,
		RT: map[string]uint64{
			"heap_alloc":    ms.HeapAlloc,
			"heap_inuse":    ms.HeapInuse,
			"heap_idle":     ms.HeapIdle,
			"heap_released": ms.HeapReleased,
			"sys":           ms.Sys,
			"num_gc":        uint64(ms.NumGC),
			"goroutines":    uint64(runtime.NumGoroutine()),
		},
		// Limiters removed
		Srv: buildServerLimits(dm),
		// Fallback removed
	}

	return snap, hstat
}

func (r *metricsReporter) emit(snap metricsSnapshot, hstat map[string]uint64, format string) {
	switch format {
	case "json":
		// Attach handshake summary under top-level key to avoid breaking existing parsers
		if hstat != nil {
			// embed by marshalling a combined struct
			type full struct {
				metricsSnapshot
				WGHS map[string]uint64 `json:"wg_hs"`
			}
			fb := full{metricsSnapshot: snap, WGHS: hstat}
			b, _ := json.Marshal(fb)
			logging.Infof("metrics: %s", string(b))
			return
		}
		b, _ := json.Marshal(snap)
		logging.Infof("metrics: %s", string(b))
	default:
		logging.Infof("metrics schema_version=%d wg_available=%t", snap.SchemaVersion, snap.WGAvailable)
		logging.Infof("admission: %s", admissionText(snap.Admission))
		if snap.IPv4Fragments != nil {
			f := snap.IPv4Fragments
			logging.Infof("ipv4_fragments: received=%d completed=%d duplicates=%d rejected=%d expired=%d cached=%d live=%d reserved_bytes=%d limit_bytes=%d", f["received"], f["completed"], f["duplicates"], f["rejected"], f["expired"], f["cached"], f["live"], f["reserved_bytes"], f["limit_bytes"])
		}
		qfd := uint64(0)
		if v, ok := snap.Proc["queueFullDrops"]; ok {
			qfd = v
		}
		per := uint64(0)
		if v, ok := snap.Proc["pooled_early_releases"]; ok {
			per = v
		}
		sp := uint64(0)
		if v, ok := snap.Proc["short_packets"]; ok {
			sp = v
		}
		wgfull := uint64(0)
		if v, ok := snap.Proc["wg_queue_full"]; ok {
			wgfull = v
		}
		// Async dial + pending counters
		ds := snap.TCPExt["dial_start"]
		dok := snap.TCPExt["dial_ok"]
		dfail := snap.TCPExt["dial_fail"]
		dinfl := snap.TCPExt["dial_inflight"]
		penq := snap.TCPExt["pend_enq"]
		pfl := snap.TCPExt["pend_flush"]
		pdrop := snap.TCPExt["pend_drop"]
		// ACK-idle flows currently gated
		ackIdle := snap.TCPExt["ack_idle_flows"]
		// Handshake summary in text: peers=fresh/stale oldest=newest=secs
		hsPeers, hsFresh, hsStale, hsOld, hsNew := hstat["peers"], hstat["fresh"], hstat["stale"], hstat["oldest_sec"], hstat["newest_sec"]
		logging.Infof("metrics: ts=%s total: sent=%d/%d recv=%d/%d err=%d | tcp: sent=%d/%d recv=%d/%d act=%d rto=%d dR=%d ackidle=%d async: dial=%d/%d/%d infl=%d pend=%d/%d/%d | udp: sent=%d/%d recv=%d/%d act=%d enq=%d proc=%d | wg: from=%d to=%d drops=%d hs: peers=%d %d/%d oldest=%ds newest=%ds | srv: fds=%s/%s eph=%s/%s ct=%s/%s | proc: qfd=%d per=%d sp=%d wgfull=%d | rt: heap=%dMi inuse=%dMi gor=%d gc=%d",
			snap.Timestamp,
			snap.Total["pkts_sent"], snap.Total["bytes_sent"],
			snap.Total["pkts_recv"], snap.Total["bytes_recv"],
			snap.Total["errors"],
			snap.TCP["pkts_sent"], snap.TCP["bytes_sent"],
			snap.TCP["pkts_recv"], snap.TCP["bytes_recv"],
			snap.TCPActive, snap.TCPExt["rto"], snap.TCPExt["rto_delta"], ackIdle,
			ds, dok, dfail, dinfl, penq, pfl, pdrop,
			snap.UDP["pkts_sent"], snap.UDP["bytes_sent"],
			snap.UDP["pkts_recv"], snap.UDP["bytes_recv"],
			snap.UDPActive, snap.UDP["tx_enq"], snap.UDP["tx_proc"],
			snap.WG["plaintext_from_wg"], snap.WG["plaintext_to_wg"], snap.WG["queue_drops"],
			hsPeers, hsFresh, hsStale, hsOld, hsNew,

			metricText(snap.Srv, "open_fds"), metricText(snap.Srv, "nofile_soft"),
			metricText(snap.Srv, "eph_used_est"), metricText(snap.Srv, "eph_size"),
			metricText(snap.Srv, "ct_used"), metricText(snap.Srv, "ct_max"),
			qfd, per, sp, wgfull,
			snap.RT["heap_alloc"]/(1024*1024), snap.RT["heap_inuse"]/(1024*1024), snap.RT["goroutines"], snap.RT["num_gc"],
		)
	}
}

// summarizeWGHandshakes parses the wg device IpcGet state and returns summary counters:
// peers, fresh, stale, oldest_sec, newest_sec.
func summarizeWGHandshakes(state string) map[string]uint64 {
	return wg.HandshakeSummary(wg.ParsePeerState(state), time.Now())
}

// buildServerLimits collects best-effort server-side limits/usage that can throttle traffic.
func buildServerLimits(dm socket.SocketDetailedMetrics) map[string]uint64 {
	out := map[string]uint64{}
	// File descriptors: soft/hard and current usage
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err == nil {
		out["nofile_soft"] = rl.Cur
		out["nofile_hard"] = rl.Max
	}
	if ents, err := os.ReadDir("/proc/self/fd"); err == nil {
		out["open_fds"] = uint64(len(ents))
		if soft, ok := out["nofile_soft"]; ok && soft > 0 {
			out["fd_util_pct"] = (out["open_fds"] * 100) / soft
		}
	}
	// Ephemeral port range and estimated usage by this process
	low, high, ok := readPortRange("/proc/sys/net/ipv4/ip_local_port_range")
	if ok {
		out["eph_low"] = low
		out["eph_high"] = high
		if high > low {
			size := (high - low + 1)
			used := dm.TCP.ActiveFlows + dm.UDP.ActiveFlows
			out["eph_size"] = size
			out["eph_used_est"] = used
			out["eph_util_pct"] = (used * 100) / size
		}
	}
	// Conntrack usage (host-wide) if visible in this namespace
	if maxv, ok := readUint("/proc/sys/net/netfilter/nf_conntrack_max"); ok {
		out["ct_max"] = maxv
		if used, ok2 := countLines("/proc/net/nf_conntrack"); ok2 {
			out["ct_used"] = used
			if maxv > 0 {
				out["ct_util_pct"] = (used * 100) / maxv
			}
		}
	}
	// Socket buffer maxima (FYI); values are bytes
	if v, ok := readUint("/proc/sys/net/core/rmem_max"); ok {
		out["rmem_max"] = v
	}
	if v, ok := readUint("/proc/sys/net/core/wmem_max"); ok {
		out["wmem_max"] = v
	}
	// TCP memory thresholds (pages) -> convert to bytes
	if a, ok := readUintTriplet("/proc/sys/net/ipv4/tcp_mem"); ok {
		pg := uint64(os.Getpagesize())
		out["tcp_mem_low_bytes"], out["tcp_mem_pressure_bytes"], out["tcp_mem_high_bytes"] = a[0]*pg, a[1]*pg, a[2]*pg
	}
	// UDP memory thresholds (pages)
	if a, ok := readUintTriplet("/proc/sys/net/ipv4/udp_mem"); ok {
		pg := uint64(os.Getpagesize())
		out["udp_mem_low_bytes"], out["udp_mem_pressure_bytes"], out["udp_mem_high_bytes"] = a[0]*pg, a[1]*pg, a[2]*pg
	}
	// TCP rmem/wmem defaults (min, default, max)
	if a, ok := readUintTriplet("/proc/sys/net/ipv4/tcp_rmem"); ok {
		out["tcp_rmem_min"], out["tcp_rmem_def"], out["tcp_rmem_max"] = a[0], a[1], a[2]
	}
	if a, ok := readUintTriplet("/proc/sys/net/ipv4/tcp_wmem"); ok {
		out["tcp_wmem_min"], out["tcp_wmem_def"], out["tcp_wmem_max"] = a[0], a[1], a[2]
	}
	return out
}

func readUint(path string) (uint64, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	s := strings.TrimSpace(string(b))
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func readUintTriplet(path string) ([3]uint64, bool) {
	var res [3]uint64
	b, err := os.ReadFile(path)
	if err != nil {
		return res, false
	}
	f := strings.Fields(string(b))
	if len(f) < 3 {
		return res, false
	}
	for i := 0; i < 3; i++ {
		v, err := strconv.ParseUint(f[i], 10, 64)
		if err != nil {
			return res, false
		}
		res[i] = v
	}
	return res, true
}

func readPortRange(path string) (low, high uint64, ok bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, false
	}
	f := strings.Fields(string(b))
	if len(f) < 2 {
		return 0, 0, false
	}
	lo, err1 := strconv.ParseUint(f[0], 10, 64)
	hi, err2 := strconv.ParseUint(f[1], 10, 64)
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return lo, hi, true
}

func countLines(path string) (uint64, bool) {
	f, err := os.Open(path)
	if err != nil {
		return 0, false
	}
	defer f.Close()
	r := bufio.NewReader(f)
	var n uint64 = 0
	for {
		line, err := r.ReadString('\n')
		if err == nil {
			n++
			continue
		}
		if err == io.EOF {
			if len(line) > 0 {
				n++
			}
			break
		}
		return 0, false
	}
	return n, true
}

// Fixed order and names make the text form usable without per-peer cardinality.
func admissionText(m map[string]uint64) string {
	return fmt.Sprintf("tcp_flow_limit=%d udp_flow_limit=%d pending_dial_limit=%d tcp_pending_limit=%d tcp_reassembly_limit=%d aggregate_buffer_limit=%d invalid_buffer_request=%d tcp_retransmit_waits=%d",
		m["tcp_flow_limit"], m["udp_flow_limit"], m["pending_dial_limit"], m["tcp_pending_limit"], m["tcp_reassembly_limit"], m["aggregate_buffer_limit"], m["invalid_buffer_request"], m["tcp_retransmit_waits"])
}

func metricText(values map[string]uint64, key string) string {
	if v, ok := values[key]; ok {
		return strconv.FormatUint(v, 10)
	}
	return "unavailable"
}
