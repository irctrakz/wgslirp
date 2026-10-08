package wireguard

import (
    "net"
    "testing"
    "time"

    "github.com/irctrakz/wgslirp/pkg/core"
    "github.com/irctrakz/wgslirp/pkg/socket"
)

// dummyProc is a no-op processor to satisfy MockSocketInterface.Start requirement.
type dummyProc struct{}
func (d *dummyProc) ProcessPacket(packet core.Packet) error { return nil }

func TestWGTun_Write_ForwardsToSocket(t *testing.T) {
    // Setup mock socket
    ms := socket.NewMockSocketInterface(socket.Config{IPAddress: "127.0.0.1", MTU: 1500})
    ms.SetPacketProcessor(&dummyProc{})
    if err := ms.Start(); err != nil { t.Fatalf("start mock socket: %v", err) }
    defer ms.Stop()

    // Create WG tun bound to mock socket
    tun := NewWGTun("wgmux0", 1380, ms)

    pkt := MakeIPv4(net.IPv4(10,0,0,2), net.IPv4(1,1,1,1), 6, []byte("hello"))
    // Adapt to wireguard-go TUN API: Write takes [][]byte and returns packets written.
    sent, err := tun.Write([][]byte{pkt}, 0)
    if err != nil { t.Fatalf("wg write: %v", err) }
    if sent != 1 { t.Fatalf("wg write count=%d want 1", sent) }

    // Verify mock socket saw the packet
    sp := ms.GetSentPackets()
    if len(sp) != 1 {
        t.Fatalf("expected 1 packet to socket, got %d", len(sp))
    }
    if got := sp[0].Data(); len(got) != len(pkt) {
        t.Fatalf("socket packet size %d want %d", len(got), len(pkt))
    }
}

func TestWGPacketProcessor_RoutesToTunRead(t *testing.T) {
    // Socket not used on this path; provide a dummy that always errors on write
    ms := socket.NewMockSocketInterface(socket.Config{IPAddress: "127.0.0.1", MTU: 1500})
    ms.SetPacketProcessor(&dummyProc{})
    _ = ms.Start()
    defer ms.Stop()

    tun := NewWGTun("wgmux0", 1380, ms)
    proc := NewWGPacketProcessor(tun)

    // Prepare synthetic IPv4 UDP packet and inject via processor
    pkt := MakeIPv4(net.IPv4(8,8,8,8), net.IPv4(10,0,0,2), 17, []byte("DNS"))
    if err := proc.ProcessPacket(core.NewCopiedPacket(pkt)); err != nil {
        t.Fatalf("processor error: %v", err)
    }

    // Read from tun (as wireguard-go would) and verify payload matches
    // Read via wireguard-go multi-buffer API
    buf := make([]byte, 1500)
    bufs := [][]byte{buf}
    sizes := make([]int, 1)
    done := make(chan []byte, 1)
    go func() {
        n, err := tun.Read(bufs, sizes, 0)
        if err != nil { t.Logf("tun read error: %v", err); return }
        if n > 0 { done <- append([]byte(nil), bufs[0][:sizes[0]]...) }
    }()
    select {
    case out := <-done:
        if len(out) != len(pkt) { t.Fatalf("tun read len=%d want %d", len(out), len(pkt)) }
    case <-time.After(500 * time.Millisecond):
        t.Fatal("timeout waiting for tun.Read")
    }
}
