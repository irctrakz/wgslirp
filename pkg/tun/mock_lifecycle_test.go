package tun

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/irctrakz/wgslirp/pkg/core"
)

type lifecycleConsumer func(core.Packet) error

func (f lifecycleConsumer) ProcessPacket(p core.Packet) error { return f(p) }

func waitMock(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("mock lifecycle stalled")
	}
}

func TestMockTUNCallbackShutdownAndQueueDrain(t *testing.T) {
	m := NewMockTUNDevice("audit", 1500).(*MockTUNDevice)
	t.Cleanup(func() { _ = m.Stop() })
	entered, release, returned := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	m.SetPacketProcessor(lifecycleConsumer(func(p core.Packet) error {
		defer core.ReleasePacket(p)
		if err := m.WritePacket(p); err != nil {
			t.Error(err)
		}
		close(entered)
		<-release
		m.RequestStop() // safe even if another caller already requested shutdown
		close(returned)
		return nil
	}))
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	if err := m.WritePacket(nil); err == nil {
		t.Fatal("nil write accepted")
	}
	if err := m.SimulatePacketReceived([]byte{1, 2}); err != nil {
		t.Fatal(err)
	}
	waitMock(t, entered)
	for i := 0; i < 100; i++ {
		if err := m.SimulatePacketReceived([]byte{3}); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.SimulatePacketReceived([]byte{3}); err == nil {
		t.Fatal("unbounded queue")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := m.StopContext(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked callback: %v", err)
	}
	done := m.RequestStop()
	select {
	case <-done:
		t.Fatal("shutdown completed before callback")
	default:
	}
	if err := m.SimulatePacketReceived(nil); err == nil {
		t.Fatal("admission open after shutdown")
	}
	unblock()
	waitMock(t, returned)
	waitMock(t, done)
	if len(m.packetCh) != 0 {
		t.Fatal("queue retained after shutdown")
	}
	if err := m.Start(); err == nil {
		t.Fatal("restarted stopped mock")
	}
	if err := m.WritePacket(core.NewPacket(nil)); err == nil {
		t.Fatal("write after stop")
	}
	if err := m.Stop(); err != nil {
		t.Fatal(err)
	}
	snapshot := m.GetWrittenPackets()
	snapshot[0][0] = 9
	if m.GetWrittenPackets()[0][0] != 1 {
		t.Fatal("mutable history")
	}
}

func TestMockTUNConcurrentStartStopAndObservers(t *testing.T) {
	for iteration := 0; iteration < 20; iteration++ {
		m := NewMockTUNDevice("audit", 1500).(*MockTUNDevice)
		consumer := lifecycleConsumer(func(p core.Packet) error { core.ReleasePacket(p); return nil })
		m.SetPacketProcessor(consumer)
		var wg sync.WaitGroup
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = m.Start()
				for j := 0; j < 20; j++ {
					m.SetPacketProcessor(consumer)
					_ = m.SimulatePacketReceived([]byte{1})
					_ = m.WritePacket(core.NewPacket([]byte{2}))
					_ = m.Metrics()
					_ = m.GetWrittenPackets()
					m.ClearWrittenPackets()
				}
				_ = m.Stop()
			}()
		}
		m.RequestStop()
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		waitMock(t, done)
		if err := m.Start(); err == nil {
			t.Fatal("restart succeeded")
		}
	}
}
