package socket

import (
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
	if p.ProcessPacket(core.NewPacket(make([]byte, 20))) == nil {
		t.Fatal("accepted after stop")
	}
}
