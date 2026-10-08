package socket

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestTCPReceiveWindowNegotiationAndCapacity(t *testing.T) {
	for _, tc := range []struct {
		name       string
		cap        int
		offered    bool
		scale      uint8
		wantWindow int
	}{
		{"unoffered", 131072, false, 0, 65535},
		{"scaled", 131072, true, 7, 131072},
		{"small", 1000, true, 7, 896},
		{"tiny", 1, true, 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, f, c := concurrentFlow(t)
			b.reasmCap = tc.cap
			f.windowScaleOffered = tc.offered
			f.stateMu.Lock()
			defer f.stateMu.Unlock()
			if err := b.sendInitialSYNACKLocked(f); err != nil {
				t.Fatal(err)
			}
			if f.wsOut != tc.scale {
				t.Fatalf("scale=%d want=%d", f.wsOut, tc.scale)
			}
			syn := c.snapshot()[0]
			if _, _, err := parseTransport(syn, 6); err != nil {
				t.Fatal(err)
			}
			if got := int(binary.BigEndian.Uint16(syn[34:36])); got != min(tc.wantWindow, 65535) {
				t.Fatalf("unscaled SYN window=%d", got)
			}
			opts := syn[40 : 20+int(syn[32]>>4)*4]
			if bytes.Contains(opts, []byte{3, 3, tc.scale}) != tc.offered {
				t.Fatalf("negotiation options=%x", opts)
			}
			for _, flags := range []byte{fACK, 0x18, fFIN | fACK, fRST | fACK} {
				packet := b.buildTCPFlowLocked(f, f.serverNxt, flags, nil, nil, 0x28, 63)
				if !b.sendToGuest(f, packet) {
					t.Fatal("packet refused")
				}
				p := c.snapshot()[len(c.snapshot())-1]
				if _, _, err := parseTransport(p, 6); err != nil {
					t.Fatal(err)
				}
				if got := int(binary.BigEndian.Uint16(p[34:36])) << f.wsOut; got != tc.wantWindow {
					t.Fatalf("flags=%x effective window=%d want=%d", flags, got, tc.wantWindow)
				}
				if p[1] != 0x28 || p[8] != 63 {
					t.Fatal("IP policy changed")
				}
			}
		})
	}
}

func TestTCPReceiveWindowDoesNotRetractForFutureData(t *testing.T) {
	b, f, c := concurrentFlow(t)
	f.wsOut = 7
	f.stateMu.Lock()
	defer f.stateMu.Unlock()
	if !b.queueFuture(f, f.clientNxt+100, make([]byte, 1000)) {
		t.Fatal("queue refused")
	}
	b.sendCloseACKLocked(f)
	p := c.snapshot()[0]
	if got := int(binary.BigEndian.Uint16(p[34:36])) << f.wsOut; got != 131072 {
		t.Fatalf("retained bytes shrank receive span: %d", got)
	}
}

func TestTCPPeerWindowScaleOffer(t *testing.T) {
	for _, scale := range []byte{0, 7, 255} {
		t.Run(fmt.Sprint(scale), func(t *testing.T) {
			b, _, _ := concurrentFlow(t)
			b.dial = func(ctx context.Context, address string, timeout time.Duration) (*net.TCPConn, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			p := buildIPv4TCPOpts([4]byte{10, 0, 0, 3}, [4]byte{127, 0, 0, 1}, 40001, 80, 1, 0, fSYN, nil, []byte{3, 3, scale})
			if err := b.HandleOutbound(p); err != nil {
				t.Fatal(err)
			}
			f := b.lookupFlow("10.0.0.3:40001-127.0.0.1:80")
			if f == nil || !f.windowScaleOffered || f.wsIn != min(scale, 14) {
				t.Fatal("window scale negotiation lost or unbounded")
			}
		})
	}
}
