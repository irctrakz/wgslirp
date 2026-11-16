package wireguard

import (
	"bytes"
	"errors"
	"github.com/irctrakz/wgslirp/pkg/core"
	"github.com/irctrakz/wgslirp/pkg/socket"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTUNCloseAndInjection(t *testing.T) {
	tun := NewWGTun("test", 1380, nil)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = tun.InjectToPeer([]byte{1})
				_ = tun.Metrics()
			}
		}()
	}
	if err := tun.Close(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if err := tun.Close(); err != nil {
		t.Fatal(err)
	}
	if err := tun.InjectToPeer([]byte{1}); err == nil {
		t.Fatal("accepted packet after close")
	}
	if len(tun.outCh) != 0 {
		t.Fatal("queued packet after close")
	}
	var events []Event
	for event := range tun.events {
		events = append(events, event)
	}
	if len(events) != 2 || events[0] != EventUp || events[1] != EventDown {
		t.Fatalf("events=%v", events)
	}
}

func TestTUNRejectsInvalidBuffers(t *testing.T) {
	tun := NewWGTun("test", 1380, nil)
	defer tun.Close()
	if _, err := tun.Read([][]byte{make([]byte, 20)}, []int{0}, -1); err == nil {
		t.Fatal("negative read offset accepted")
	}
	if _, err := tun.Write([][]byte{make([]byte, 20)}, -1); err == nil {
		t.Fatal("negative write offset accepted")
	}
	_ = tun.InjectToPeer(make([]byte, 30))
	if _, err := tun.Read([][]byte{make([]byte, 20)}, []int{0}, 0); err == nil {
		t.Fatal("packet silently truncated")
	}
}

func assertAllQueueBudgetAvailable(t *testing.T, s *socket.SocketInterface, limit int) {
	t.Helper()
	release, err := s.ReservePacketBuffer(limit - 128)
	if err != nil {
		t.Fatalf("reservation leaked: %v", err)
	}
	release()
}

func TestTUNQueueBudgetCopyReadAndDrain(t *testing.T) {
	t.Setenv("WG_TUN_QUEUE_CAP", "4")
	s := socket.NewSocketInterface(socket.Config{SocketBufferCapBytes: 300})
	tun := NewWGTun("budget", 1380, s)
	defer tun.Close()
	proc := NewWGPacketProcessor(tun)
	original := make([]byte, 20)
	original[0] = 0x45
	expected := append([]byte(nil), original...)
	var released atomic.Int32
	packet := core.NewPooledPacket(original, func(b []byte) {
		for i := range b {
			b[i] = 0xff
		}
		released.Add(1)
	})
	if err := proc.ProcessPacket(packet); err != nil {
		t.Fatal(err)
	}
	if released.Load() != 1 {
		t.Fatal("input not released synchronously")
	}
	if err := tun.InjectToPeer(expected); err != nil {
		t.Fatal(err)
	}
	if err := tun.InjectToPeer(expected); !errors.Is(err, socket.ErrBufferLimit) {
		t.Fatalf("budget not enforced: %v", err)
	}
	out := make([]byte, 20)
	sizes := make([]int, 1)
	if _, err := tun.Read([][]byte{out}, sizes, 0); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, expected) {
		t.Fatal("queued data aliases released pooled input")
	}
	if _, err := tun.Read([][]byte{make([]byte, 1)}, sizes, 0); err == nil {
		t.Fatal("undersized read accepted")
	}
	assertAllQueueBudgetAvailable(t, s, 300)
	if err := tun.InjectToPeer(expected); err != nil {
		t.Fatal(err)
	}
	if err := tun.Close(); err != nil {
		t.Fatal(err)
	}
	assertAllQueueBudgetAvailable(t, s, 300)
	if err := tun.InjectToPeer(expected); err == nil {
		t.Fatal("accepted after close")
	}
	assertAllQueueBudgetAvailable(t, s, 300)
}

type purgeBudgetWriter struct {
	*socket.SocketInterface
	reservations int
	purgeEntered chan struct{}
	resumePurge  chan struct{}
}

func (w *purgeBudgetWriter) ReservePacketBuffer(n int) (func(), error) {
	release, err := w.SocketInterface.ReservePacketBuffer(n)
	w.reservations++
	if err != nil || w.reservations != 2 {
		return release, err
	}
	return func() {
		close(w.purgeEntered)
		<-w.resumePurge
		release()
	}, nil
}

func TestTUNPeerPurgePreservesReplyOrderAndReservations(t *testing.T) {
	const frameBytes = 20
	const budget = 4 * (frameBytes + 128)
	s := socket.NewSocketInterface(socket.Config{SocketBufferCapBytes: budget})
	writer := &purgeBudgetWriter{
		SocketInterface: s,
		purgeEntered:    make(chan struct{}),
		resumePurge:     make(chan struct{}),
	}
	tun, err := NewWGTunWithConfig("purge", 1380, writer, TunConfig{QueueCapacity: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	var resume sync.Once
	defer resume.Do(func() { close(writer.resumePurge) })
	revoked, survivor := [4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 3}
	for i, address := range [][4]byte{survivor, revoked, survivor, revoked} {
		packet := make([]byte, frameBytes)
		packet[0], packet[4] = 0x45, byte(i+1)
		copy(packet[16:20], address[:])
		if err := tun.InjectToPeer(packet); err != nil {
			t.Fatal(err)
		}
	}
	purged := make(chan struct{})
	go func() {
		tun.DiscardPeerPackets(revoked)
		close(purged)
	}()
	select {
	case <-writer.purgeEntered:
	case <-time.After(time.Second):
		t.Fatal("purge never reached the first revoked frame")
	}
	type readResult struct {
		order [2]byte
		count int
		err   error
	}
	read := make(chan readResult, 1)
	go func() {
		buffers := [][]byte{make([]byte, frameBytes), make([]byte, frameBytes)}
		count, err := tun.Read(buffers, make([]int, len(buffers)), 0)
		read <- readResult{order: [2]byte{buffers[0][4], buffers[1][4]}, count: count, err: err}
	}()
	select {
	case got := <-read:
		t.Fatalf("reader dequeued during purge: %+v", got)
	case <-time.After(50 * time.Millisecond):
	}
	resume.Do(func() { close(writer.resumePurge) })
	select {
	case <-purged:
	case <-time.After(time.Second):
		t.Fatal("purge did not finish")
	}
	select {
	case got := <-read:
		if got.err != nil || got.count != 2 || got.order != [2]byte{1, 3} {
			t.Fatalf("surviving replies: %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("reader did not receive surviving frames")
	}
	assertAllQueueBudgetAvailable(t, s, budget)
}

type queueCountingWriter struct {
	*socket.SocketInterface
	reservations atomic.Int32
}

func (w *queueCountingWriter) ReservePacketBuffer(n int) (func(), error) {
	w.reservations.Add(1)
	return w.SocketInterface.ReservePacketBuffer(n)
}

func TestTUNFullQueueRejectsBeforeReservation(t *testing.T) {
	t.Setenv("WG_TUN_QUEUE_CAP", "1")
	s := socket.NewSocketInterface(socket.Config{SocketBufferCapBytes: 300})
	writer := &queueCountingWriter{SocketInterface: s}
	tun := NewWGTun("full", 1380, writer)
	defer tun.Close()
	if err := tun.InjectToPeer([]byte{1}); err != nil {
		t.Fatal(err)
	}
	if err := tun.InjectToPeer(make([]byte, 400)); err == nil {
		t.Fatal("full queue accepted")
	}
	if writer.reservations.Load() != 1 {
		t.Fatal("full queue reserved storage")
	}
	_ = tun.Close()
	assertAllQueueBudgetAvailable(t, s, 300)
}

type sharedQueueWriter struct {
	*socket.SocketInterface
	entered chan struct{}
	unblock chan struct{}
}

func (w *sharedQueueWriter) WritePacket(core.Packet) error {
	close(w.entered)
	<-w.unblock
	return nil
}

func TestProcessorAndTUNShareSocketQueueBudget(t *testing.T) {
	t.Setenv("PROCESSOR_WORKERS", "1")
	s := socket.NewSocketInterface(socket.Config{SocketBufferCapBytes: 300})
	writer := &sharedQueueWriter{s, make(chan struct{}), make(chan struct{})}
	proc := socket.NewSocketPacketProcessor(writer, 1).(*socket.SocketPacketProcessor)
	if err := proc.Start(); err != nil {
		t.Fatal(err)
	}
	var unblock sync.Once
	defer func() { unblock.Do(func() { close(writer.unblock) }); _ = proc.Stop() }()
	tun := NewWGTun("shared", 1380, writer)
	defer tun.Close()
	packet := make([]byte, 20)
	packet[0] = 0x45
	if err := proc.ProcessPacket(core.NewPooledPacket(packet, func([]byte) {})); err != nil {
		t.Fatal(err)
	}
	select {
	case <-writer.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not start")
	}
	if err := tun.InjectToPeer(packet); err != nil {
		t.Fatal(err)
	}
	if err := tun.InjectToPeer(packet); !errors.Is(err, socket.ErrBufferLimit) {
		t.Fatalf("not a shared budget: %v", err)
	}
	if _, err := tun.Read([][]byte{make([]byte, 20)}, []int{0}, 0); err != nil {
		t.Fatal(err)
	}
	// Releasing the TUN entry makes space even while the processor is busy.
	release, err := s.ReservePacketBuffer(20)
	if err != nil {
		t.Fatal(err)
	}
	release()
	unblock.Do(func() { close(writer.unblock) })
	_ = proc.Stop()
	assertAllQueueBudgetAvailable(t, s, 300)
}

func TestTUNBatchReadOwnershipAndPartialFailure(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		packets, buffers, read int
		undersized             bool
	}{{"partial-ready", 3, 4, 3, false}, {"partial-error", 3, 4, 1, true}, {"batch-cap", 129, 130, 128, false}} {
		t.Run(tc.name, func(t *testing.T) {
			s := socket.NewSocketInterface(socket.Config{SocketBufferCapBytes: 65536})
			tun := NewWGTun("batch", 1380, s)
			defer tun.Close()
			for i := 1; i <= tc.packets; i++ {
				if err := tun.InjectToPeer(bytes.Repeat([]byte{byte(i)}, 20)); err != nil {
					t.Fatal(err)
				}
			}
			buffers := make([][]byte, tc.buffers)
			for i := range buffers {
				buffers[i] = make([]byte, 36)
			}
			if tc.undersized {
				buffers[1] = make([]byte, 17)
			}
			sizes := make([]int, len(buffers))
			n, err := tun.Read(buffers, sizes, 16)
			if tc.undersized {
				if n != 1 || err == nil || len(tun.outCh) != 1 {
					t.Fatal("partial failure lost ownership/count", n, err, len(tun.outCh))
				}
			} else if n != tc.read || err != nil || len(tun.outCh) != tc.packets-n {
				t.Fatal("ready batch waited/lost count", n, err)
			}
			for i := 0; i < n; i++ {
				if sizes[i] != 20 || !bytes.Equal(buffers[i][16:], bytes.Repeat([]byte{byte(i + 1)}, 20)) {
					t.Fatal("copied packet/offset mismatch")
				}
			}
			_ = tun.Close()
			assertAllQueueBudgetAvailable(t, s, 65536)
		})
	}
}

func TestTUNConcurrentReadInjectAndCloseReleasesBudget(t *testing.T) {
	s := socket.NewSocketInterface(socket.Config{SocketBufferCapBytes: 4096})
	tun := NewWGTun("concurrent", 1380, s)
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			if _, err := tun.Read([][]byte{make([]byte, 64)}, []int{0}, 0); err != nil {
				return
			}
		}
	}()
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 100; j++ {
				_ = tun.InjectToPeer(make([]byte, 20))
			}
		}()
	}
	workers.Add(2)
	for i := 0; i < 2; i++ {
		go func() { defer workers.Done(); _ = tun.Close() }()
	}
	workers.Wait()
	assertAllQueueBudgetAvailable(t, s, 4096)
}

func TestTUNWriteAccountsSynchronousCopy(t *testing.T) {
	s := socket.NewSocketInterface(socket.Config{SocketBufferCapBytes: 300})
	writer := &sharedQueueWriter{s, make(chan struct{}), make(chan struct{})}
	tun := NewWGTun("write-budget", 1380, writer)
	defer tun.Close()
	done := make(chan error, 1)
	data := make([]byte, 20)
	data[0] = 0x45
	go func() { _, err := tun.Write([][]byte{data}, 0); done <- err }()
	var once sync.Once
	defer once.Do(func() { close(writer.unblock) })
	select {
	case <-writer.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("writer did not start")
	}
	if release, err := s.ReservePacketBuffer(25); !errors.Is(err, socket.ErrBufferLimit) {
		if release != nil {
			release()
		}
		t.Fatal("in-flight write not charged")
	}
	once.Do(func() { close(writer.unblock) })
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	assertAllQueueBudgetAvailable(t, s, 300)
}
