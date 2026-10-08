package socket

import (
	"testing"
	"time"
)

// A deterministic established-flow ACK workload isolates dispatch, flow locking,
// ACK/window processing and diagnostics from host dial/network timing. It is not
// a forwarding throughput or connection-establishment benchmark.
func BenchmarkTCPHandleACK(b *testing.B) {
	parent := &SocketInterface{config: Config{MTU: 1500}}
	bridge := newTCPBridge(parent)
	parent.tcp = bridge
	f := &tcpFlow{
		key:   "10.0.0.2:40000-127.0.0.1:80",
		srcIP: [4]byte{10, 0, 0, 2}, dstIP: [4]byte{127, 0, 0, 1}, srcPort: 40000, dstPort: 80,
		state: tcpEstablished, clientNxt: 100, serverNxt: 1000, sndUna: 1000,
		clientMSS: 600, mss: 600, advWnd: 1200, lastAckTime: time.Now(),
		rto: time.Second, rtoStop: make(chan struct{}), ackCh: make(chan struct{}, 1),
	}
	bridge.flows[f.key] = f
	defer bridge.stop()
	packet := closeGuestPacket(f, 100, 1000, 0x10, nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := bridge.HandleOutbound(packet); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
}
