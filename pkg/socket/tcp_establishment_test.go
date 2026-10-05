package socket

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/irctrakz/wgslirp/pkg/core"
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
				gate := make(chan struct{})
				if !async {
					b.tuning.FastDialMs = 1000
					close(gate)
				}
				var calls atomic.Int32
				b.dial = func(ctx context.Context, _ string, timeout time.Duration) (*net.TCPConn, error) {
					calls.Add(1)
					if timeout != 5*time.Second {
						t.Errorf("dial lifetime: %v", timeout)
					}
					select {
					case <-gate:
					case <-ctx.Done():
						return nil, ctx.Err()
					}
					return nil, errors.New("refused")
				}
				syn := buildIPv4TCP([4]byte{10, 0, 0, 2}, [4]byte{127, 0, 0, 1}, 40000, 80, 42, 0, fSYN, nil)
				if err := b.HandleOutbound(syn); err != nil {
					t.Fatal(err)
				}
				if async {
					close(gate)
				}
				done := make(chan struct{})
				go func() { b.workers.Wait(); close(done) }()
				awaitBudgetWorker(t, done)
				if calls.Load() != 1 {
					t.Fatalf("dial calls=%d", calls.Load())
				}
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
				want := uint64(0)
				if async {
					want = 1
				}
				if atomic.LoadUint64(&b.dialStart) != want || atomic.LoadUint64(&b.dialFail) != want || atomic.LoadUint64(&b.dialOk) != 0 || atomic.LoadInt64(&b.dialInflight) != 0 {
					t.Fatal("failure changed asynchronous dial accounting")
				}
			})
		}
	}
}

func TestDialHandoffClosesLateSocketAfterCancellation(t *testing.T) {
	for _, reason := range []string{"rst", "stop", "fast-stop", "synack-refusal", "quote-limit"} {
		t.Run(reason, func(t *testing.T) {
			parent := NewSocketInterface(DefaultConfig())
			parent.processor = &captureProcessor{}
			if reason == "synack-refusal" {
				parent.processor = &mockPacketProcessor{processPacketFunc: func(core.Packet) error { return errors.New("refused") }}
			}
			b := newTCPBridge(parent)
			if reason == "fast-stop" {
				b.tuning.FastDialMs = 1000
			}
			if reason == "quote-limit" {
				b.buffers.limit = 1
			}
			client, host := tcpBudgetPair(t)
			started, cancelled, finish := make(chan struct{}), make(chan struct{}), make(chan struct{})
			release := sync.OnceFunc(func() { close(finish) })
			t.Cleanup(func() { release(); b.stop() })
			var calls atomic.Int32
			b.dial = func(ctx context.Context, _ string, _ time.Duration) (*net.TCPConn, error) {
				calls.Add(1)
				close(started)
				<-ctx.Done()
				close(cancelled)
				<-finish // Model a successful connect racing with cancellation.
				return client, nil
			}
			src, dst := [4]byte{10, 0, 0, 2}, [4]byte{127, 0, 0, 1}
			done := make(chan error, 1)
			go func() { done <- b.HandleOutbound(buildIPv4TCP(src, dst, 40000, 80, 42, 0, fSYN, nil)) }()
			awaitBudgetWorker(t, started)
			if reason == "fast-stop" {
				b.requestStop()
			}
			select {
			case err := <-done:
				if reason == "rst" || reason == "stop" {
					if err != nil {
						t.Fatal(err)
					}
				} else if err == nil {
					t.Fatal("expected establishment failure")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("SYN handler blocked")
			}
			switch reason {
			case "rst":
				if err := b.HandleOutbound(buildIPv4TCP(src, dst, 40000, 80, 43, 0, fRST, nil)); err != nil {
					t.Fatal(err)
				}
			case "stop":
				b.requestStop()
			}
			awaitBudgetWorker(t, cancelled)
			assertBudget(t, b.dialSlots, 1) // Cancellation alone must not free a running dial's slot.
			release()
			b.stop()
			if calls.Load() != 1 {
				t.Fatalf("dial calls=%d", calls.Load())
			}
			if err := host.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			var p [1]byte
			if n, err := host.Read(p[:]); n != 0 || err != io.EOF {
				t.Fatalf("late socket not closed: n=%d err=%v", n, err)
			}
			assertBudget(t, b.dialSlots, 0)
			assertBudget(t, b.buffers, 0)
			if len(b.flowSnapshot()) != 0 || atomic.LoadInt64(&b.dialInflight) != 0 {
				t.Fatal("retained flow or dial accounting")
			}
		})
	}
}

func TestDialHandoffFlushesPendingDataBeforeHalfClose(t *testing.T) {
	parent := NewSocketInterface(DefaultConfig())
	capture := &captureProcessor{}
	parent.processor = capture
	b := newTCPBridge(parent)
	client, host := tcpBudgetPair(t)
	gate := make(chan struct{})
	release := sync.OnceFunc(func() { close(gate) })
	t.Cleanup(func() { release(); b.stop() })
	var calls atomic.Int32
	b.dial = func(ctx context.Context, _ string, _ time.Duration) (*net.TCPConn, error) {
		calls.Add(1)
		select {
		case <-gate:
			return client, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	src, dst := [4]byte{10, 0, 0, 2}, [4]byte{127, 0, 0, 1}
	if err := b.HandleOutbound(buildIPv4TCP(src, dst, 40000, 80, 42, 0, fSYN, nil)); err != nil {
		t.Fatal(err)
	}
	flows := b.flowSnapshot()
	if len(flows) != 1 {
		t.Fatal("missing connecting flow")
	}
	f := flows[0]
	f.stateMu.Lock()
	ack := f.serverNxt
	f.stateMu.Unlock()
	payload := []byte("pending data before FIN")
	if err := b.HandleOutbound(buildIPv4TCP(src, dst, 40000, 80, 43, ack, fACK|fFIN, payload)); err != nil {
		t.Fatal(err)
	}
	assertBudget(t, b.dialSlots, 1)
	release()
	if err := host.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(host)
	if err != nil || string(got) != string(payload) {
		t.Fatalf("pending bytes/EOF: %q %v", got, err)
	}
	if atomic.LoadUint64(&b.dialStart) != 1 || atomic.LoadUint64(&b.dialOk) != 1 || atomic.LoadUint64(&b.dialFail) != 0 || atomic.LoadInt64(&b.dialInflight) != 0 {
		t.Fatal("attached dial retained completion accounting")
	}
	b.stop()
	if calls.Load() != 1 {
		t.Fatalf("dial calls=%d", calls.Load())
	}
	synacks := 0
	for _, p := range capture.snapshot() {
		if p[9] == 6 && p[33] == fSYN|fACK {
			synacks++
		}
	}
	if synacks != 1 {
		t.Fatalf("SYN-ACKs=%d", synacks)
	}
	assertBudget(t, b.dialSlots, 0)
	assertBudget(t, b.buffers, 0)
}

func TestDialHandoffHonorsLongConfiguredFastWait(t *testing.T) {
	parent := NewSocketInterface(DefaultConfig())
	parent.processor = &captureProcessor{}
	b := newTCPBridge(parent)
	t.Cleanup(b.stop)
	b.tuning.FastDialMs = 6000
	b.dial = func(_ context.Context, _ string, timeout time.Duration) (*net.TCPConn, error) {
		if timeout != 6*time.Second {
			t.Errorf("configured wait truncated: %v", timeout)
		}
		return nil, errors.New("refused")
	}
	if err := b.HandleOutbound(buildIPv4TCP([4]byte{10, 0, 0, 2}, [4]byte{127, 0, 0, 1}, 40000, 80, 42, 0, fSYN, nil)); err != nil {
		t.Fatal(err)
	}
	assertBudget(t, b.dialSlots, 0)
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
			gate := make(chan struct{})
			if !async {
				b.tuning.FastDialMs = 1000
				close(gate)
			}
			b.dial = func(ctx context.Context, _ string, _ time.Duration) (*net.TCPConn, error) {
				calls.Add(1)
				select {
				case <-gate:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
				return client, nil
			}
			if err := b.HandleOutbound(buildIPv4TCP([4]byte{10, 0, 0, 2}, [4]byte{127, 0, 0, 1}, 40000, 80, 42, 0, fSYN, nil)); err != nil {
				t.Fatal(err)
			}
			if async {
				close(gate)
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
			if calls.Load() != 1 {
				t.Fatalf("dial calls=%d", calls.Load())
			}
			packets := capture.snapshot()
			if len(packets) != 1 || packets[0][33] != fSYN|fACK {
				t.Fatalf("expected one SYN-ACK, got %d packets", len(packets))
			}
			assertBudget(t, b.dialSlots, 0)
			assertBudget(t, b.buffers, 0)
		})
	}
}
