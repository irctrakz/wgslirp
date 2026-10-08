package socket

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestTCPACKIdleWindowProgress(t *testing.T) {
	for _, opening := range []bool{false, true} {
		b, f, _ := concurrentFlow(t)
		b.ackIdleGate, b.ackIdleFail = time.Second, 2*time.Second
		f.serverNxt += 600
		f.advWnd = 0
		f.lastAckTime = time.Now().Add(-3 * time.Second)
		ack := buildIPv4TCP(f.srcIP, f.dstIP, f.srcPort, f.dstPort, f.clientNxt, f.sndUna, fACK, nil)
		window := uint16(0)
		if opening {
			window = 1200
		}
		binary.BigEndian.PutUint16(ack[34:36], window)
		repairTestChecksums(ack)
		if err := b.HandleOutbound(ack); err != nil {
			t.Fatal(err)
		}
		b.expireACKIdleFlows(time.Now())
		if f.closed == opening {
			t.Fatalf("opening=%v closed=%v: only window progress should prevent expiry", opening, f.closed)
		}
	}
}

func TestTCPACKIdlePolicy(t *testing.T) {
	for _, tc := range []struct {
		name              string
		gate, fail, idle  time.Duration
		inflight, minimum int
		gated, closed     bool
	}{
		{"before-gate", 6 * time.Second, 120 * time.Second, 5 * time.Second, 600, 0, false, false},
		{"old-monitor-deadline", 6 * time.Second, 120 * time.Second, 45 * time.Second, 1200, 0, true, false},
		{"failure-boundary", 6 * time.Second, 120 * time.Second, 120 * time.Second, 600, 0, true, true},
		{"gate-disabled", 0, 120 * time.Second, 180 * time.Second, 1200, 0, false, false},
		{"failure-disabled", 6 * time.Second, 0, 180 * time.Second, 1200, 0, true, false},
		{"below-minimum", time.Second, 2 * time.Second, 3 * time.Second, 599, 0, false, false},
		{"custom-minimum", time.Second, 2 * time.Second, 3 * time.Second, 800, 900, false, false},
		{"custom-deadline", time.Second, 2 * time.Second, 3 * time.Second, 900, 900, true, true},
		{"failure-before-gate", 10 * time.Second, time.Second, 5 * time.Second, 600, 0, false, false},
		{"no-outstanding-data", time.Second, 2 * time.Second, 3 * time.Second, 0, 0, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, f, capture := concurrentFlow(t)
			b.ackIdleGate, b.ackIdleFail, b.ackIdleMinInflight = tc.gate, tc.fail, tc.minimum
			b.errorSignal = "rst"
			now := time.Now()
			f.lastAckTime = now.Add(-tc.idle)
			f.serverNxt = f.sndUna + uint32(tc.inflight)
			f.advWnd = 0 // A closed peer window must not hide outstanding data.
			f.stateMu.Lock()
			gated := b.ackIdleGatedLocked(f, now)
			f.stateMu.Unlock()
			if gated != tc.gated {
				t.Fatalf("gated=%v, want %v", gated, tc.gated)
			}
			b.expireACKIdleFlows(now)
			if f.closed != tc.closed {
				t.Fatalf("closed=%v, want %v", f.closed, tc.closed)
			}
			packets := capture.snapshot()
			if tc.closed {
				if len(packets) != 1 || packets[0][33] != fRST|fACK {
					t.Fatal("missing reset")
				}
				if b.lookupFlow(f.key) != nil {
					t.Fatal("closed flow remains registered")
				}
			} else if len(packets) != 0 {
				t.Fatal("unexpected reset")
			}
		})
	}
}

func TestTCPACKIdleSenderAndMaintenanceAgree(t *testing.T) {
	for _, sender := range []bool{false, true} {
		for _, signal := range []string{"rst", "icmp", "none"} {
			b, f, capture := concurrentFlow(t)
			b.ackIdleGate, b.ackIdleFail, b.errorSignal = time.Second, 2*time.Second, signal
			f.lastAckTime = time.Now().Add(-3 * time.Second)
			f.serverNxt += 600
			if sender {
				f.stateMu.Lock()
				allowed := b.sendAllowanceLocked(f)
				f.stateMu.Unlock()
				if allowed != 0 {
					t.Fatal("expired sender allowed data")
				}
			} else {
				b.expireACKIdleFlows(time.Now())
			}
			if !f.closed {
				t.Fatal("stalled flow survived")
			}
			b.expireACKIdleFlows(time.Now())
			want := 1
			if signal == "none" {
				want = 0
			}
			if len(capture.snapshot()) != want {
				t.Fatal("reset policy or repeated cleanup differs")
			}
		}
	}
}

func TestTCPACKIdleProgressAndCloseTimers(t *testing.T) {
	b, f, _ := concurrentFlow(t)
	b.ackIdleGate, b.ackIdleFail = time.Second, 2*time.Second
	f.serverNxt += 1200
	f.lastAckTime = time.Now().Add(-3 * time.Second)
	// A real advancing ACK resets idle time while some bytes remain in flight.
	ack := buildIPv4TCP(f.srcIP, f.dstIP, f.srcPort, f.dstPort, f.clientNxt, f.sndUna+600, fACK, nil)
	if err := b.HandleOutbound(ack); err != nil {
		t.Fatal(err)
	}
	b.expireACKIdleFlows(time.Now())
	if f.closed {
		t.Fatal("progress did not prevent expiry")
	}
	f.stateMu.Lock()
	gated := b.ackIdleGatedLocked(f, time.Now())
	f.state = tcpTimeWait
	f.lastAckTime = time.Now().Add(-3 * time.Second)
	f.stateMu.Unlock()
	if gated {
		t.Fatal("progress did not reopen gate")
	}
	b.expireACKIdleFlows(time.Now())
	if f.closed {
		t.Fatal("ACK-idle maintenance bypassed TIME-WAIT")
	}
	b.stop()
	b.expireACKIdleFlows(time.Now())
}
