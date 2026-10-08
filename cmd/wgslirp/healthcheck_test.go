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
