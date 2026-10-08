package socket

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/irctrakz/wgslirp/pkg/core"
)

type notifyingCapture struct {
	captureProcessor
	changed chan struct{}
}

func (c *notifyingCapture) ProcessPacket(p core.Packet) error {
	err := c.captureProcessor.ProcessPacket(p)
	select {
	case c.changed <- struct{}{}:
	default:
	}
	return err
}

func concurrentFlow(t *testing.T) (*tcpBridge, *tcpFlow, *notifyingCapture) {
	t.Helper()
	capture := &notifyingCapture{changed: make(chan struct{}, 1)}
	parent := &SocketInterface{config: Config{MTU: 1500}, processor: capture}
	b := newTCPBridge(parent)
	parent.tcp = b
	f := &tcpFlow{
		key:   "10.0.0.2:40000-127.0.0.1:80",
		srcIP: [4]byte{10, 0, 0, 2}, dstIP: [4]byte{127, 0, 0, 1}, srcPort: 40000, dstPort: 80,
		state: tcpEstablished, clientNxt: 100, serverNxt: 1000, sndUna: 1000,
		mss: 600, advWnd: 1200, lastAckTime: time.Now(),
		rto: time.Second, rtoStop: make(chan struct{}), ackCh: make(chan struct{}, 1),
	}
	b.mu.Lock()
	b.flows[f.key] = f
	b.mu.Unlock()
	t.Cleanup(b.stop)
	return b, f, capture
}

func TestTCPConcurrentSendACKAndMetrics(t *testing.T) {
	b, f, capture := concurrentFlow(t)
	failures := make(chan error, 1)
	b.launch(func() {
		for {
			select {
			case <-b.stopCh:
				return
			case <-capture.changed:
				packets := capture.snapshot()
				last := packets[len(packets)-1]
				ack := binary.BigEndian.Uint32(last[24:28]) + uint32(len(last)-40)
				packet := buildIPv4TCP(f.srcIP, f.dstIP, f.srcPort, f.dstPort, 100, ack, 0x10, nil)
				binary.BigEndian.PutUint16(packet[34:36], 1200)
				repairTestChecksums(packet)
				if err := b.HandleOutbound(packet); err != nil {
					select {
					case failures <- err:
					default:
					}
					return
				}
				_ = b.parent.DetailedMetrics()
				b.SetMSSClamp(600)
				b.SetPaceUS(0)
			}
		}
	})
	done := make(chan bool, 1)
	payload := make([]byte, 12000)
	b.launch(func() { done <- b.sendPayload(f, payload) })
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("send aborted")
		}
	case err := <-failures:
		t.Fatal(err)
	case <-time.After(3 * time.Second):
		t.Fatal("sender stalled waiting for concurrent ACKs")
	}
	next := uint32(1000)
	for _, packet := range capture.snapshot() {
		seq := binary.BigEndian.Uint32(packet[24:28])
		if seq != next {
			t.Fatalf("segment seq=%d want=%d", seq, next)
		}
		next += uint32(len(packet) - 40)
	}
	if next != 13000 {
		t.Fatalf("sent through sequence %d", next)
	}
}

func TestTCPStopJoinsZeroWindowSender(t *testing.T) {
	b, f, capture := concurrentFlow(t)
	f.stateMu.Lock()
	f.advWnd = 0
	f.stateMu.Unlock()
	done := make(chan bool, 1)
	b.launch(func() { done <- b.sendPayload(f, []byte("pending")) })
	stopped := make(chan struct{})
	go func() { b.stop(); b.stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not join sender")
	}
	if <-done {
		t.Fatal("sent into a zero window")
	}
	if len(capture.snapshot()) != 0 {
		t.Fatal("emitted data into zero window")
	}
	if b.launch(func() {}) {
		t.Fatal("accepted worker after shutdown")
	}
	if len(b.flowSnapshot()) != 0 {
		t.Fatal("retained closed flow")
	}
}

func TestTCPOldFlowCannotRemoveReplacement(t *testing.T) {
	b, old, _ := concurrentFlow(t)
	replacement := &tcpFlow{key: old.key, rtoStop: make(chan struct{})}
	b.mu.Lock()
	b.flows[old.key] = replacement
	b.mu.Unlock()
	old.stateMu.Lock()
	b.removeFlowLocked(old)
	old.stateMu.Unlock()
	flows := b.flowSnapshot()
	if len(flows) != 1 || flows[0] != replacement {
		t.Fatal("removed replacement flow")
	}
}
