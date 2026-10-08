package socket

import (
	"errors"
	"fmt"
	"github.com/irctrakz/wgslirp/pkg/core"
	"sync"
	"sync/atomic"
	"testing"
)

func TestProcessorConcurrentStopReleasesAcceptedPackets(t *testing.T) {
	entered, unblock := make(chan struct{}), make(chan struct{})
	var first sync.Once
	writer := &mockSocketWriter{writePacketFunc: func(core.Packet) error { first.Do(func() { close(entered) }); <-unblock; return nil }}
	t.Setenv("PROCESSOR_WORKERS", "1")
	p := NewSocketPacketProcessor(writer, 1).(*SocketPacketProcessor)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	var released atomic.Int32
	packet := func() core.Packet {
		b := make([]byte, 20)
		b[0] = 0x45
		return core.NewPooledPacket(b, func([]byte) { released.Add(1) })
	}
	if err := p.ProcessPacket(packet()); err != nil {
		t.Fatal(err)
	}
	<-entered
	if err := p.ProcessPacket(packet()); err != nil {
		t.Fatal(err)
	}
	var stops sync.WaitGroup
	stops.Add(2)
	go func() { defer stops.Done(); _ = p.Stop() }()
	<-p.stopCh
	go func() { defer stops.Done(); _ = p.Stop() }()
	close(unblock)
	stops.Wait()
	if got := released.Load(); got != 2 {
		t.Fatalf("released=%d want=2", got)
	}
	if p.Start() == nil {
		t.Fatal("restarted stopped processor")
	}
	if p.ProcessPacket(core.NewCopiedPacket(make([]byte, 20))) == nil {
		t.Fatal("accepted after stop")
	}
}

type queuedBudgetWriter struct {
	*SocketInterface
	write func(core.Packet) error
}

func (w *queuedBudgetWriter) WritePacket(p core.Packet) error { return w.write(p) }

func TestProcessorQueueBudgetAndCallerOwnership(t *testing.T) {
	for _, limit := range []int{788, 2048} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			t.Setenv("PROCESSOR_WORKERS", "1")
			t.Setenv("PROCESSOR_QUEUE_CAP", "1")
			entered, unblock := make(chan struct{}), make(chan struct{})
			var once sync.Once
			s := NewSocketInterface(Config{SocketBufferCapBytes: limit})
			writer := &queuedBudgetWriter{s, func(core.Packet) error {
				once.Do(func() { close(entered) })
				<-unblock
				return errors.New("injected write failure")
			}}
			p := NewSocketPacketProcessor(writer, 1).(*SocketPacketProcessor)
			if err := p.Start(); err != nil {
				t.Fatal(err)
			}
			var unblockOnce sync.Once
			t.Cleanup(func() { unblockOnce.Do(func() { close(unblock) }); _ = p.Stop() })
			var released atomic.Int32
			packet := func(capacity int) core.Packet {
				b := make([]byte, 20, capacity)
				b[0] = 0x45
				return core.NewPooledPacket(b, func([]byte) { released.Add(1) })
			}
			if err := p.ProcessPacket(packet(512)); err != nil {
				t.Fatal(err)
			}
			awaitBudgetWorker(t, entered)
			assertBudget(t, s.buffers(), 640) // still charged after dequeue
			if err := p.ProcessPacket(packet(20)); err != nil {
				t.Fatal(err)
			}
			assertBudget(t, s.buffers(), 788)
			rejected := packet(20)
			err := p.ProcessPacket(rejected)
			if err == nil || (limit == 788 && !errors.Is(err, ErrBufferLimit)) {
				t.Fatalf("expected rejection, got %v", err)
			}
			if released.Load() != 0 || rejected.Length() != 20 {
				t.Fatal("rejected caller-owned packet released")
			}
			core.ReleasePacket(rejected)
			assertBudget(t, s.buffers(), 788)
			done := make(chan struct{})
			go func() { _ = p.Stop(); close(done) }()
			awaitBudgetWorker(t, p.stopCh)
			unblockOnce.Do(func() { close(unblock) })
			awaitBudgetWorker(t, done)
			assertBudget(t, s.buffers(), 0)
			if released.Load() != 3 {
				t.Fatalf("release count %d", released.Load())
			}
			if p.ProcessPacket(core.NewCopiedPacket([]byte{0x45})) == nil {
				t.Fatal("accepted after stop")
			}
			assertBudget(t, s.buffers(), 0)
		})
	}
}
