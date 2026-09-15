package wireguard

import (
	"sync"
	"testing"
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
