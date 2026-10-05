package wireguard

import (
	"errors"
	"github.com/irctrakz/wgslirp/pkg/core"
	"sync"
	"testing"
)

type countingWriter struct {
	calls   int
	failAt  int
	failure error
}

func (w *countingWriter) WritePacket(core.Packet) error {
	w.calls++
	if w.calls == w.failAt {
		return w.failure
	}
	return nil
}

func TestTUNMetricsPartialBatchAndOverlay(t *testing.T) {
	cause := errors.New("writer rejected")
	w := &countingWriter{failAt: 2, failure: cause}
	tun, err := NewWGTunWithConfig("metrics", 1380, w, TunConfig{QueueCapacity: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	p := make([]byte, 20)
	p[0] = 0x45
	p[16] = 10
	p[19] = 1
	n, err := tun.Write([][]byte{p, p, p}, 0)
	if n != 2 || !errors.Is(err, cause) || tun.Metrics().PlaintextFromWG != 40 || w.calls != 3 {
		t.Fatalf("partial batch %d %v %+v", n, err, tun.Metrics())
	}
	if err := tun.SetPeerCIDRs([]string{"10.0.0.0/8"}); err != nil {
		t.Fatal(err)
	}
	if n, err = tun.Write([][]byte{p}, 0); n != 1 || err != nil {
		t.Fatal(n, err)
	}
	m := tun.Metrics()
	if m.PlaintextFromWG != 60 || m.PlaintextToWG != 20 || w.calls != 3 {
		t.Fatal(m)
	}
	if _, err = tun.Read([][]byte{make([]byte, 40)}, make([]int, 1), 0); err != nil {
		t.Fatal(err)
	}
	if tun.Metrics() != m {
		t.Fatal("read double-counted queued bytes")
	}
}

func TestSaturationStreaksAndConcurrentSnapshots(t *testing.T) {
	tun, err := NewWGTunWithConfig("metrics", 1380, nil, TunConfig{QueueCapacity: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	p := NewWGPacketProcessor(tun).(*WGPacketProcessor)
	send := func() error { return p.ProcessPacket(core.NewPacket(make([]byte, 20))) }
	if err := send(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := send(); !errors.Is(err, ErrQueueFull) {
			t.Fatal(err)
		}
	}
	m := p.Metrics()
	if m["wg_full_streak_cur"] != 3 || m["wg_full_streak_max"] != 3 || m["wg_full_bursts"] != 1 {
		t.Fatal(m)
	}
	if _, err := tun.Read([][]byte{make([]byte, 40)}, make([]int, 1), 0); err != nil {
		t.Fatal(err)
	}
	if err := send(); err != nil {
		t.Fatal(err)
	}
	m = p.Metrics()
	if m["wg_full_streak_cur"] != 0 || m["wg_full_streak_max"] != 3 {
		t.Fatal(m)
	}
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 10; j++ {
				_ = send()
				_ = p.Metrics()
			}
		}()
	}
	workers.Wait()
	m = p.Metrics()
	if m["wg_queue_full"] != 83 || m["wg_full_streak_cur"] != 80 || m["wg_full_streak_max"] != 80 || m["wg_full_bursts"] != 2 {
		t.Fatal(m)
	}
	m["wg_full_streak_max"] = 0
	if p.Metrics()["wg_full_streak_max"] != 80 {
		t.Fatal("snapshot aliases state")
	}
}
