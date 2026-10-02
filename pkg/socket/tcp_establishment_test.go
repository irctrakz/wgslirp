package socket

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestTCPEstablishmentFailurePolicy(t *testing.T) {
	for _, async := range []bool{false, true} {
		for _, policy := range []string{"rst", "icmp", "none"} {
			t.Run(map[bool]string{false: "fast-", true: "async-"}[async]+policy, func(t *testing.T) {
				parent := NewSocketInterface(DefaultConfig())
				capture := &captureProcessor{}
				parent.processor = capture
				b := newTCPBridge(parent)
				t.Cleanup(b.stop)
				b.errorSignal = policy
				b.dial = func(_ context.Context, _ string, timeout time.Duration) (*net.TCPConn, error) {
					if async && timeout < time.Second {
						return nil, &net.DNSError{IsTimeout: true}
					}
					return nil, errors.New("refused")
				}
				syn := buildIPv4TCP([4]byte{10, 0, 0, 2}, [4]byte{127, 0, 0, 1}, 40000, 80, 42, 0, fSYN, nil)
				if err := b.HandleOutbound(syn); err != nil {
					t.Fatal(err)
				}
				done := make(chan struct{})
				go func() { b.workers.Wait(); close(done) }()
				awaitBudgetWorker(t, done)
				packets := capture.snapshot()
				if async {
					if len(packets) == 0 || packets[0][9] != 6 || packets[0][33] != fSYN|fACK {
						t.Fatal("async dial did not first emit SYN-ACK")
					}
					packets = packets[1:]
				}
				if policy == "none" {
					if len(packets) != 0 {
						t.Fatal("silent failure emitted a packet")
					}
				} else {
					if len(packets) != 1 {
						t.Fatalf("failure packets=%d", len(packets))
					}
					p := packets[0]
					if policy == "rst" && (p[9] != 6 || p[33] != fRST|fACK) {
						t.Fatal("wrong reset")
					}
					if policy == "icmp" && (p[9] != 1 || p[20] != 3 || p[21] != 1) {
						t.Fatal("wrong ICMP failure")
					}
				}
				if len(b.flowSnapshot()) != 0 {
					t.Fatal("failed dial left a flow")
				}
				assertBudget(t, b.dialSlots, 0)
				assertBudget(t, b.buffers, 0)
			})
		}
	}
}

func TestTCPEstablishmentEmitsOneSYNACK(t *testing.T) {
	for _, async := range []bool{false, true} {
		t.Run(map[bool]string{false: "fast", true: "async"}[async], func(t *testing.T) {
			parent := NewSocketInterface(DefaultConfig())
			capture := &captureProcessor{}
			parent.processor = capture
			b := newTCPBridge(parent)
			t.Cleanup(b.stop)
			client, _ := tcpBudgetPair(t)
			var calls atomic.Int32
			b.dial = func(context.Context, string, time.Duration) (*net.TCPConn, error) {
				if calls.Add(1) == 1 && async {
					return nil, &net.DNSError{IsTimeout: true}
				}
				return client, nil
			}
			if err := b.HandleOutbound(buildIPv4TCP([4]byte{10, 0, 0, 2}, [4]byte{127, 0, 0, 1}, 40000, 80, 42, 0, fSYN, nil)); err != nil {
				t.Fatal(err)
			}
			flows := b.flowSnapshot()
			if len(flows) != 1 {
				t.Fatal("missing candidate")
			}
			f := flows[0]
			deadline := time.Now().Add(2 * time.Second)
			for {
				f.stateMu.Lock()
				connected := f.conn != nil
				f.stateMu.Unlock()
				if connected {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("dial did not attach")
				}
				time.Sleep(time.Millisecond)
			}
			b.stop() // Join completion before asserting that no second SYN-ACK was sent.
			packets := capture.snapshot()
			if len(packets) != 1 || packets[0][33] != fSYN|fACK {
				t.Fatalf("expected one SYN-ACK, got %d packets", len(packets))
			}
			assertBudget(t, b.dialSlots, 0)
			assertBudget(t, b.buffers, 0)
		})
	}
}
