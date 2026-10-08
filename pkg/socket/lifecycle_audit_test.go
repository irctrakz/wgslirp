package socket

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/irctrakz/wgslirp/pkg/core"
)

func awaitLifecycle(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("lifecycle did not complete")
	}
}

func TestSocketCallbackCanRequestStopAndBoundWait(t *testing.T) {
	b, f, _ := concurrentFlow(t)
	s := b.parent
	// The fixture has no public Start, but uses the real bridge worker ownership.
	s.running = true
	s.udp = newUDPBridge(s)
	t.Cleanup(func() { _ = s.Stop() })
	entered, release, exited := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	s.processor = packetConsumer(func(p core.Packet) error {
		defer core.ReleasePacket(p)
		done := s.RequestStop() // must not synchronously wait for this callback
		if done != s.RequestStop() {
			t.Error("multiple finalizers")
		}
		_ = s.Metrics()
		close(entered)
		<-release
		return nil
	})
	if !b.launch(func() { b.sendPayload(f, []byte("callback")); close(exited) }) {
		t.Fatal("worker rejected")
	}
	awaitLifecycle(t, entered)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := s.StopContext(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked callback: %v", err)
	}
	select {
	case <-s.RequestStop():
		t.Fatal("reported complete before callback returned")
	default:
	}
	if err := s.WritePacket(core.NewCopiedPacket(nil)); err == nil {
		t.Fatal("admission remained open")
	}
	// Both bridges are signaled even when TCP cleanup is blocked on flow state.
	awaitLifecycle(t, b.stopCh)
	awaitLifecycle(t, s.udp.stopCh)
	unblock()
	awaitLifecycle(t, exited)
	awaitLifecycle(t, s.RequestStop())
	if err := s.Stop(); err != nil {
		t.Fatal(err)
	}
	if used, _, _, _ := b.buffers.snapshot(); used != 0 {
		t.Fatalf("retained buffers: %d", used)
	}
}

func TestTCPMaintenancePreservesIdentityAndRTOTracking(t *testing.T) {
	b, old, _ := concurrentFlow(t)
	b.trackRTOFlow(old)
	replacement := &tcpFlow{key: old.key, rtoStop: make(chan struct{})}
	b.mu.Lock()
	b.flows[old.key] = replacement
	b.mu.Unlock()
	// The old RTO observation must not reset the replacement.
	if n := b.parent.ResetRTOTCPFlows(); n != 0 {
		t.Fatalf("reset replacement through stale RTO identity: %d", n)
	}
	b.trackRTOFlow(replacement)
	b.trackRTOFlow(old) // a late retransmit completion cannot overwrite new tracking
	if b.removeFlowIf(old, nil) {
		t.Fatal("removed stale observation")
	}
	old.stateMu.Lock()
	b.removeFlowLocked(old)
	old.stateMu.Unlock()
	b.rtoMu.Lock()
	got := b.rtoActiveFlows[old.key]
	b.rtoMu.Unlock()
	if got != replacement {
		t.Fatal("old removal erased replacement diagnostics")
	}
	if n := b.parent.ResetRTOTCPFlows(); n != 1 {
		t.Fatalf("reset count: %d", n)
	}
	if n := b.parent.ResetAllTCPFlows(); n != 0 {
		t.Fatalf("duplicate reset: %d", n)
	}
	b.trackRTOFlow(replacement)
	b.rtoMu.Lock()
	remaining := len(b.rtoActiveFlows)
	b.rtoMu.Unlock()
	if remaining != 0 {
		t.Fatal("closed flow resurrected RTO tracking")
	}
}

func TestTCPExpiryRechecksActivity(t *testing.T) {
	b, f, _ := concurrentFlow(t)
	cutoff := time.Now().Add(-time.Minute)
	f.lastMu.Lock()
	f.lastActivity = cutoff.Add(-time.Second)
	f.lastMu.Unlock()
	// An observed idle flow that receives traffic before removal stays alive.
	f.touch()
	if b.removeFlowIf(f, func(f *tcpFlow) bool { return f.lastActive().Before(cutoff) }) {
		t.Fatal("removed refreshed flow")
	}
	b.expireFlows(cutoff)
	if len(b.flowSnapshot()) != 1 {
		t.Fatal("expired live flow")
	}
	f.lastMu.Lock()
	f.lastActivity = cutoff.Add(-time.Second)
	f.lastMu.Unlock()
	b.expireFlows(cutoff)
	b.expireFlows(cutoff)
	if len(b.flowSnapshot()) != 0 || loadSocketMetrics(&b.metrics).ConnectionsClosed != 1 {
		t.Fatal("expiry did not close exactly once")
	}
}

func TestMockSocketOwnershipAndSnapshots(t *testing.T) {
	m := NewMockSocketInterface(Config{})
	m.SetPacketProcessor(packetConsumer(func(p core.Packet) error { core.ReleasePacket(p); return nil }))
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	released := 0
	p := core.NewPooledPacket([]byte{1, 2, 3}, func(b []byte) { released++; clear(b) })
	if err := m.SimulatePacketReceived(p); err != nil {
		t.Fatal(err)
	}
	if released != 1 || m.Metrics().BytesReceived != 3 {
		t.Fatal("lost ownership or callback changed length accounting")
	}
	received := m.GetReceivedPackets()
	if received[0].Data()[0] != 1 {
		t.Fatal("history aliases released storage")
	}
	received[0].Data()[0] = 9
	if m.GetReceivedPackets()[0].Data()[0] != 1 {
		t.Fatal("mutable received snapshot")
	}
	data := []byte{4, 5}
	if err := m.WritePacket(core.NewCopiedPacket(data)); err != nil {
		t.Fatal(err)
	}
	data[0] = 9
	sent := m.GetSentPackets()
	sent[0].Data()[0] = 8
	if m.GetSentPackets()[0].Data()[0] != 4 {
		t.Fatal("mutable sent history")
	}
	if err := m.WritePacket(nil); err == nil {
		t.Fatal("accepted nil write")
	}
	if err := m.SimulatePacketReceived(nil); err == nil {
		t.Fatal("accepted nil receive")
	}
}

func TestMockSocketCallbackStopAndConcurrentObservers(t *testing.T) {
	m := NewMockSocketInterface(Config{})
	t.Cleanup(func() { _ = m.Stop() })
	entered, release, returned := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	m.SetPacketProcessor(packetConsumer(func(p core.Packet) error {
		defer core.ReleasePacket(p)
		_ = m.WritePacket(core.NewCopiedPacket([]byte{2})) // no mock mutex held across callback
		m.RequestStop()
		close(entered)
		<-release
		return nil
	}))
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { defer close(returned); _ = m.SimulatePacketReceived(core.NewCopiedPacket([]byte{1})) }()
	awaitLifecycle(t, entered)
	var observers sync.WaitGroup
	for i := 0; i < 8; i++ {
		observers.Add(1)
		go func() {
			defer observers.Done()
			for j := 0; j < 30; j++ {
				_ = m.Metrics()
				_ = m.GetReceivedPackets()
				_ = m.GetSentPackets()
				m.SetPacketProcessor(nil)
				_ = m.WritePacket(core.NewCopiedPacket(nil))
				_ = m.Start()
				if m.RequestStop() != m.RequestStop() {
					t.Error("completion channel changed")
				}
			}
		}()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := m.StopContext(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wait: %v", err)
	}
	unblock()
	observers.Wait()
	awaitLifecycle(t, returned)
	awaitLifecycle(t, m.RequestStop())
	if err := m.Start(); err == nil {
		t.Fatal("restarted stopped mock")
	}
	if err := m.Stop(); err != nil {
		t.Fatal(err)
	}
}

func TestMockSocketRejectRetainsOwnership(t *testing.T) {
	m := NewMockSocketInterface(Config{})
	rejected := errors.New("rejected")
	m.SetPacketProcessor(packetConsumer(func(core.Packet) error { return rejected }))
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	released := 0
	p := core.NewPooledPacket([]byte{1}, func([]byte) { released++ })
	if err := m.SimulatePacketReceived(p); !errors.Is(err, rejected) {
		t.Fatalf("lost rejection cause: %v", err)
	}
	if released != 0 {
		t.Fatal("consumed rejected packet")
	}
	core.ReleasePacket(p)
	if m.Metrics().Errors != 1 {
		t.Fatal("lost error metric")
	}
}

func TestSocketAndMockConcurrentStartStop(t *testing.T) {
	for _, mock := range []bool{false, true} {
		for iteration := 0; iteration < 10; iteration++ {
			var s interface {
				Start() error
				Stop() error
				SetPacketProcessor(core.PacketProcessor)
			}
			if mock {
				s = NewMockSocketInterface(Config{})
			} else {
				s = NewSocketInterface(Config{Protocol: "ip4:udp", MTU: 1500})
			}
			s.SetPacketProcessor(&captureProcessor{})
			var wg sync.WaitGroup
			for i := 0; i < 4; i++ {
				wg.Add(1)
				go func() { defer wg.Done(); _ = s.Start(); _ = s.Stop() }()
			}
			done := make(chan struct{})
			go func() { wg.Wait(); close(done) }()
			awaitLifecycle(t, done)
			if err := s.Start(); err == nil {
				t.Fatal("restart after concurrent stop")
			}
		}
	}
}
