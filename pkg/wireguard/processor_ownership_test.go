package wireguard

import (
	"github.com/irctrakz/wgslirp/pkg/core"
	"testing"
)

func TestWGProcessorMissingSinkRejectsOwnership(t *testing.T) {
	released := 0
	p := core.NewPooledPacket([]byte{1}, func([]byte) { released++ })
	processor := NewWGPacketProcessor(nil)
	if err := processor.ProcessPacket(p); err == nil {
		t.Fatal("missing sink accepted ownership")
	}
	if released != 0 {
		t.Fatal("rejection consumed producer ownership")
	}
	core.ReleasePacket(p)
	if released != 1 {
		t.Fatal("packet not released")
	}
}
