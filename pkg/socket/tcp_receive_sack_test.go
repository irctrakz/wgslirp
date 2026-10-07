package socket

import (
	"encoding/binary"
	"reflect"
	"testing"
)

func receiveACKBlocks(t *testing.T, packet []byte, ack uint32) [][2]uint32 {
	t.Helper()
	if _, _, err := parseTransport(packet, 6); err != nil {
		t.Fatalf("invalid ACK/checksum: %v", err)
	}
	if got := binary.BigEndian.Uint32(packet[28:32]); got != ack {
		t.Fatalf("cumulative ACK=%d want=%d", got, ack)
	}
	end := 20 + int(packet[32]>>4)*4
	if end == 40 {
		return nil
	}
	opts := packet[40:end]
	if opts[0] != 5 || opts[1] < 10 || (opts[1]-2)%8 != 0 || int(opts[1]) > len(opts) {
		t.Fatalf("invalid SACK options %x", opts)
	}
	var blocks [][2]uint32
	for i := 2; i < int(opts[1]); i += 8 {
		blocks = append(blocks, [2]uint32{binary.BigEndian.Uint32(opts[i : i+4]), binary.BigEndian.Uint32(opts[i+4 : i+8])})
	}
	return blocks
}

func TestTCPReceiveSACKRetainedAndRefusedBytes(t *testing.T) {
	b, f, c := concurrentFlow(t)
	f.sackPermitted = true
	b.reasmCap = 20
	closeOutbound(t, b, f, 200, 1000, 0x18, make([]byte, 10))
	closeOutbound(t, b, f, 400, 1000, 0x18, make([]byte, 10))
	closeOutbound(t, b, f, 202, 1000, 0x18, make([]byte, 3))  // contained duplicate becomes first block
	closeOutbound(t, b, f, 600, 1000, 0x18, make([]byte, 10)) // quota refusal must never be SACKed
	packets := c.snapshot()
	for i, want := range [][][2]uint32{
		{{200, 210}}, {{400, 410}, {200, 210}},
		{{200, 210}, {400, 410}}, {{200, 210}, {400, 410}},
	} {
		if got := receiveACKBlocks(t, packets[i], 100); !reflect.DeepEqual(got, want) {
			t.Fatalf("ACK %d blocks=%v want=%v", i, got, want)
		}
	}
	if f.futureBytes != 20 || b.parent.admission.reassemblyBytes.Load() != 1 {
		t.Fatal("SACK changed storage ownership or refusal accounting")
	}
	// Delayed ACKs use the same retained ranges, with no change to cumulative ACK.
	f.stateMu.Lock()
	b.scheduleAck(f)
	f.stateMu.Unlock()
	p, _ := closePacket(t, c, len(packets), func([]byte) bool { return true })
	if got := receiveACKBlocks(t, p, 100); !reflect.DeepEqual(got, [][2]uint32{{200, 210}, {400, 410}}) {
		t.Fatalf("delayed SACK=%v", got)
	}
}

func TestTCPReceiveSACKRequiresPeerPermission(t *testing.T) {
	b, f, c := concurrentFlow(t)
	b.tuning.EnableSACK = true // legacy sender recovery cannot grant peer consent
	closeOutbound(t, b, f, 200, 1000, 0x18, make([]byte, 10))
	if got := receiveACKBlocks(t, c.snapshot()[0], 100); len(got) != 0 {
		t.Fatalf("unnegotiated SACK=%v", got)
	}
}

func TestTCPReceiveSACKBoundedAndWrapEdge(t *testing.T) {
	b, f, c := concurrentFlow(t)
	f.sackPermitted = true
	f.stateMu.Lock()
	for _, seq := range []uint32{200, 400, 600, 800, 1000, 202} {
		if !b.queueFuture(f, seq, make([]byte, 4)) {
			t.Fatal("queue refused")
		}
	}
	b.sendCloseACKLocked(f)
	f.stateMu.Unlock()
	if got := receiveACKBlocks(t, c.snapshot()[0], 100); !reflect.DeepEqual(got, [][2]uint32{{200, 206}, {1000, 1004}, {800, 804}, {600, 604}}) {
		t.Fatalf("bounded blocks=%v", got)
	}
	b2, f2, c2 := concurrentFlow(t)
	f2.sackPermitted = true
	f2.clientNxt = ^uint32(0) - 20
	closeOutbound(t, b2, f2, ^uint32(0)-3, 1000, 0x18, make([]byte, 4))
	if got := receiveACKBlocks(t, c2.snapshot()[0], f2.clientNxt); !reflect.DeepEqual(got, [][2]uint32{{^uint32(0) - 3, 0}}) {
		t.Fatalf("wrap edge blocks=%v", got)
	}
}
