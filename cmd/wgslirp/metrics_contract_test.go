package main

import (
	"errors"
	"github.com/irctrakz/wgslirp/pkg/core"
	"github.com/irctrakz/wgslirp/pkg/socket"
	wg "github.com/irctrakz/wgslirp/pkg/wireguard"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestReporterDeltasIndependentAndResetSafe(t *testing.T) {
	a, b := &metricsReporter{}, &metricsReporter{}
	for _, sample := range []struct{ cur, want uint64 }{{9, 9}, {12, 3}, {2, 2}, {2, 0}, {4, 2}} {
		if got := a.rtoDelta(sample.cur); got != sample.want {
			t.Fatal(got, sample)
		}
	}
	if b.rtoDelta(12) != 12 {
		t.Fatal("reporters shared history")
	}
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 100; j++ {
				a.rtoDelta(uint64(j))
			}
		}()
	}
	workers.Wait()
}
func TestUnavailableStatisticsAndFinalLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stat")
	if _, ok := readUint(path); ok {
		t.Fatal("missing statistic available")
	}
	if metricText(nil, "missing") != "unavailable" || metricText(map[string]uint64{"zero": 0}, "zero") != "0" {
		t.Fatal("missing confused with zero")
	}
	if err := os.WriteFile(path, []byte("one\ntwo"), 0600); err != nil {
		t.Fatal(err)
	}
	if n, ok := countLines(path); !ok || n != 2 {
		t.Fatal(n, ok)
	}
}

type metricSink struct{}

func (metricSink) ProcessPacket(core.Packet) error { return nil }
func (metricSink) Metrics() map[string]uint64      { return map[string]uint64{"wg_queue_full": 3} }
func TestHealthTeePreservesPrimaryMetrics(t *testing.T) {
	p := newTeeProcessor(metricSink{}, newHealthSink()).(*teeProcessor)
	if p.Metrics()["wg_queue_full"] != 3 {
		t.Fatal("wrapper hid metrics")
	}
	m := p.Metrics()
	m["wg_queue_full"] = 99
	if p.Metrics()["wg_queue_full"] != 3 {
		t.Fatal("snapshot aliased")
	}
}

type fixtureSocketMetrics struct{ rto uint64 }

func (s *fixtureSocketMetrics) DetailedMetrics() socket.SocketDetailedMetrics {
	return socket.SocketDetailedMetrics{TCPExt: map[string]uint64{"rto": s.rto}}
}

type fixtureTunMetrics struct{}

func (fixtureTunMetrics) Metrics() wg.TUNMetrics { return wg.TUNMetrics{PlaintextFromWG: 42} }

type fixtureDeviceState struct{ fail bool }

func (d fixtureDeviceState) IpcGet() (string, error) {
	if d.fail {
		return "", errors.New("state unavailable")
	}
	return "public_key=a\nlatest_handshake_time_sec=0\n", nil
}
func TestReporterUsesNarrowSnapshotSources(t *testing.T) {
	source := &fixtureSocketMetrics{rto: 10}
	a, b := &metricsReporter{}, &metricsReporter{}
	snap, hs := a.snapshot(source, fixtureTunMetrics{}, fixtureDeviceState{})
	if snap.SchemaVersion != 1 || !snap.WGAvailable || snap.WG["plaintext_from_wg"] != 42 || snap.TCPExt["rto_delta"] != 10 || hs["peers"] != 1 || hs["stale"] != 1 {
		t.Fatal(snap, hs)
	}
	source.rto = 12
	snap, hs = a.snapshot(source, fixtureTunMetrics{}, fixtureDeviceState{fail: true})
	if snap.WGAvailable || len(hs) != 0 || snap.TCPExt["rto_delta"] != 2 {
		t.Fatal(snap, hs)
	}
	other, _ := b.snapshot(source, fixtureTunMetrics{}, nil)
	if other.TCPExt["rto_delta"] != 12 {
		t.Fatal("reporters consumed shared state")
	}
	snap.TCPExt["rto"] = 99
	if source.DetailedMetrics().TCPExt["rto"] != 12 {
		t.Fatal("snapshot mutation reached source")
	}
}
