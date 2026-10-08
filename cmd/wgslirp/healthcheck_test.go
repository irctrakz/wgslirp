package main

import (
	"bytes"
	"errors"
	"testing"

	"github.com/irctrakz/wgslirp/pkg/core"
)

type processorFunc func(core.Packet) error

func (f processorFunc) ProcessPacket(p core.Packet) error { return f(p) }

func TestTeePreservesOwnershipAndForwardingError(t *testing.T) {
	original := core.IsDebugMode()
	t.Cleanup(func() { core.SetDebugMode(original) })
	for _, debug := range []bool{false, true} {
		core.SetDebugMode(debug)
		testTeePreservesOwnershipAndForwardingError(t)
	}
}

func testTeePreservesOwnershipAndForwardingError(t *testing.T) {
	want := []byte{1, 2, 3, 4}
	released := false
	packet := core.NewPooledPacket(append([]byte(nil), want...), func(b []byte) {
		released = true
		for i := range b {
			b[i] = 0
		}
	})
	queueFull := errors.New("queue full")
	primary := processorFunc(func(p core.Packet) error {
		core.ReleasePacket(p)
		return queueFull
	})
	var observed []byte
	observer := processorFunc(func(p core.Packet) error { observed = p.Data(); return nil })
	if err := newTeeProcessor(primary, observer).ProcessPacket(packet); !errors.Is(err, queueFull) {
		t.Fatalf("got %v", err)
	}
	if !released || !bytes.Equal(observed, want) {
		t.Fatalf("released=%v observed=%v", released, observed)
	}
}

func TestHealthConsumersReleaseAcceptedPackets(t *testing.T) {
	original := core.IsDebugMode()
	t.Cleanup(func() { core.SetDebugMode(original) })
	for _, debug := range []bool{false, true} {
		core.SetDebugMode(debug)
		sink := newHealthSink()
		for i := 0; i <= cap(sink.ch); i++ {
			releases := 0
			packet := core.NewPooledPacket([]byte{42}, func(b []byte) { releases++; clear(b) })
			if err := sink.ProcessPacket(packet); err != nil || releases != 1 {
				t.Fatal("sink did not release accepted packet")
			}
		}
		if got := <-sink.ch; len(got) != 1 || got[0] != 42 {
			t.Fatal("sink retained released storage")
		}
		releases := 0
		packet := core.NewPooledPacket([]byte{42}, func(b []byte) { releases++; clear(b) })
		var retained []byte
		observer := processorFunc(func(p core.Packet) error { retained = core.CopyPacketData(p); return errors.New("rejected") })
		if err := newTeeProcessor(nil, observer).ProcessPacket(packet); err != nil || releases != 1 {
			t.Fatal("observer-only tee lost ownership")
		}
		if retained[0] != 42 {
			t.Fatal("observer copy corrupted")
		}
	}
}
