package socket

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestTCPMSSNegotiationAndSegmentation(t *testing.T) {
	for _, tc := range []struct {
		name                                                          string
		peer, mtu, clamp, laterClamp, negotiated, advertised, segment int
	}{
		{"no peer option", -1, 1500, 0, 0, 1460, 1460, 1460},
		{"smaller peer offer", 600, 1500, 0, 0, 600, 1460, 600},
		{"large peer offer", 65535, 1200, 0, 0, 1160, 1160, 1160},
		{"initial clamp", 900, 1500, 500, 0, 500, 500, 500},
		{"smaller peer than clamp", 300, 1500, 500, 0, 300, 500, 300},
		{"runtime clamp reduction", 600, 1500, 0, 200, 600, 1460, 200},
		{"runtime clamp increase", 900, 1500, 500, 1000, 500, 500, 500},
		{"minimum MTU", -1, 576, 0, 0, 536, 536, 536},
		{"zero peer offer retains failure", 0, 1500, 0, 0, 0, 1460, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.MTU = tc.mtu
			cfg.Transport.MSSClamp = tc.clamp
			cfg.Transport.InitialCwndMSS = 2
			cfg.Transport.FastDialMs = 1000
			parent := NewSocketInterface(cfg)
			capture := &captureProcessor{}
			parent.processor = capture
			b := newTCPBridge(parent)
			t.Cleanup(b.stop)
			client, _ := tcpBudgetPair(t)
			b.dial = func(context.Context, string, time.Duration) (*net.TCPConn, error) { return client, nil }
			var options []byte
			if tc.peer >= 0 {
				options = []byte{2, 4, byte(tc.peer >> 8), byte(tc.peer)}
			}
			src, dst := [4]byte{10, 0, 0, 2}, [4]byte{127, 0, 0, 1}
			if err := b.HandleOutbound(buildIPv4TCPOpts(src, dst, 40000, 80, 1, 0, fSYN, nil, options)); err != nil {
				t.Fatal(err)
			}
			flows := b.flowSnapshot()
			if len(flows) != 1 {
				t.Fatalf("flows=%d", len(flows))
			}
			f := flows[0]
			packets := capture.snapshot()
			if len(packets) != 1 || len(packets[0]) < 44 {
				t.Fatal("missing initial SYN-ACK")
			}
			reply := packets[0]
			if reply[40] != 2 || reply[41] != 4 || int(binary.BigEndian.Uint16(reply[42:44])) != tc.advertised {
				t.Fatalf("SYN-ACK MSS=%v", reply[40:44])
			}
			f.stateMu.Lock()
			negotiated, cwnd, serverSeq := f.mss, f.cc.Cwnd(), f.serverISN
			f.stateMu.Unlock()
			if negotiated != tc.negotiated {
				t.Fatalf("negotiated=%d want=%d", negotiated, tc.negotiated)
			}
			if tc.negotiated > 0 && cwnd != 2*tc.negotiated {
				t.Fatalf("initial cwnd=%d", cwnd)
			}
			if err := b.HandleOutbound(buildIPv4TCP(src, dst, 40000, 80, 2, serverSeq+1, fACK, nil)); err != nil {
				t.Fatal(err)
			}
			if tc.laterClamp != 0 {
				b.SetMSSClamp(tc.laterClamp)
			}
			payload := bytes.Repeat([]byte{0x5a}, max(1, 2*tc.negotiated))
			if ok := b.sendPayload(f, payload); ok != (tc.segment > 0) {
				t.Fatalf("send succeeded=%v", ok)
			}
			var received []byte
			for _, p := range capture.snapshot() {
				ihl := int(p[0]&15) * 4
				offset := ihl + int(p[ihl+12]>>4)*4
				data := p[offset:]
				if len(data) > tc.segment || len(p) > tc.mtu {
					t.Fatalf("segment=%d frame=%d", len(data), len(p))
				}
				received = append(received, data...)
			}
			if tc.segment > 0 && !bytes.Equal(received, payload) {
				t.Fatal("segmentation changed payload")
			}
			f.stateMu.Lock()
			unchanged := f.mss == tc.negotiated
			f.stateMu.Unlock()
			if !unchanged {
				t.Fatal("runtime clamp mutated negotiated MSS")
			}
		})
	}
}
