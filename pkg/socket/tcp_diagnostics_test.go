package socket

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/irctrakz/wgslirp/pkg/logging"
	"github.com/sirupsen/logrus"
)

func captureTCPLogs(t *testing.T, level logrus.Level) *bytes.Buffer {
	t.Helper()
	logger := logging.WithFields(nil).Logger
	output, previousLevel := logger.Out, logger.GetLevel()
	var logs bytes.Buffer
	logger.SetOutput(&logs)
	logger.SetLevel(level)
	t.Cleanup(func() { logger.SetOutput(output); logger.SetLevel(previousLevel) })
	return &logs
}

func TestTCPRegistrySnapshotIsDebugOnly(t *testing.T) {
	for _, level := range []logrus.Level{logrus.WarnLevel, logrus.InfoLevel, logrus.DebugLevel} {
		t.Run(level.String(), func(t *testing.T) {
			logs := captureTCPLogs(t, level)
			b, f, _ := concurrentFlow(t)
			logs.Reset() // The bridge's startup message is independent of the snapshot.
			f.state = tcpTimeWait
			f.sndUna = f.serverNxt
			b.trackRTOFlow(f)
			b.dumpDetailedMetrics()
			if level != logrus.DebugLevel {
				if logs.Len() != 0 {
					t.Fatalf("routine snapshot emitted at quiet level: %s", logs)
				}
			} else if !strings.Contains(logs.String(), "TCP registry snapshot:") || !strings.Contains(logs.String(), "state=TIME_WAIT inflight=0") || strings.Contains(logs.String(), "level=warning") {
				t.Fatalf("snapshot misrepresents retained flow: %s", logs)
			}
			b.rtoMu.Lock()
			tracked := b.rtoActiveFlows[f.key]
			b.rtoMu.Unlock()
			if tracked != f {
				t.Fatal("logging level changed retransmission tracking")
			}
		})
	}
}

func TestTCPACKIdleWarningRequiresRemoval(t *testing.T) {
	logs := captureTCPLogs(t, logrus.WarnLevel)
	b, f, capture := concurrentFlow(t)
	b.ackIdleGate, b.ackIdleFail, b.errorSignal = time.Second, 2*time.Second, "none"
	now := time.Now()
	f.serverNxt = f.sndUna + 600
	f.lastAckTime = now.Add(-1500 * time.Millisecond)
	b.expireACKIdleFlows(now)
	if f.closed || logs.Len() != 0 {
		t.Fatalf("temporary ACK delay warned or closed flow: %s", logs)
	}
	b.expireACKIdleFlows(now.Add(time.Second))
	if !f.closed || !strings.Contains(logs.String(), "removing connection:") || !strings.Contains(logs.String(), "check path loss/delay and peer responsiveness") {
		t.Fatalf("missing actionable removal warning: %s", logs)
	}
	if len(capture.snapshot()) != 0 {
		t.Fatal("warning changed the explicit no-reset policy")
	}
	b.expireACKIdleFlows(now.Add(2 * time.Second))
	if strings.Count(logs.String(), "removing connection:") != 1 {
		t.Fatalf("duplicate warning after removal: %s", logs)
	}
}

func TestTCPCloseWarningDistinguishesTimeWaitExpiry(t *testing.T) {
	for _, normalExpiry := range []bool{false, true} {
		t.Run(map[bool]string{false: "close_failure", true: "time_wait_expiry"}[normalExpiry], func(t *testing.T) {
			logs := captureTCPLogs(t, logrus.WarnLevel)
			b, f, capture := concurrentFlow(t)
			now := time.Now()
			f.state = tcpFinWait1
			f.closeDeadline = now.Add(-time.Second)
			if normalExpiry {
				f.state = tcpTimeWait
				f.timeWaitUntil = now
			}
			f.stateMu.Lock()
			b.closeTickLocked(f, now)
			b.closeTickLocked(f, now.Add(time.Second))
			f.stateMu.Unlock()
			if !f.closed {
				t.Fatal("deadline did not remove flow")
			}
			if normalExpiry {
				if logs.Len() != 0 || len(capture.snapshot()) != 0 {
					t.Fatalf("normal TIME-WAIT expiry reported failure: %s", logs)
				}
			} else if strings.Count(logs.String(), "aborting connection:") != 1 || !strings.Contains(logs.String(), "state=FIN_WAIT_1") || len(capture.snapshot()) != 1 {
				t.Fatalf("close failure lacks accurate consequence: %s", logs)
			}
		})
	}
}
