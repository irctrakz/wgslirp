package socket

import (
	"time"

	"github.com/irctrakz/wgslirp/pkg/logging"
)

// ackIdleGatedLocked requires stateMu. A zero gate disables both gating and
// ACK-idle failure, preserving the configurable sender policy. Window-opening
// updates count as progress through lastAckTime, just like advancing ACKs.
func (b *tcpBridge) ackIdleGatedLocked(f *tcpFlow, now time.Time) bool {
	if f.closed || f.state == tcpSynRcvd || b.ackIdleGate <= 0 {
		return false
	}
	minimum := b.ackIdleMinInflight
	if minimum <= 0 {
		minimum = f.mss
	}
	inFlight := int(f.serverNxt - f.sndUna)
	return inFlight > 0 && inFlight >= minimum && now.Sub(f.lastAckTime) >= b.ackIdleGate
}

// expireACKIdleLocked requires stateMu; readers and maintenance use the same
// deadline and signaling policy. FIN/TIME-WAIT retain their own close timers.
func (b *tcpBridge) expireACKIdleLocked(f *tcpFlow, now time.Time) {
	if b.ackIdleFail <= 0 || !b.ackIdleGatedLocked(f, now) || now.Sub(f.lastAckTime) < b.ackIdleFail {
		return
	}
	if b.failureLog.Allow(now) {
		logging.Warnf("TCP ACK progress timed out; removing connection: flow=%s state=%s ack_idle=%v limit=%v inflight=%d; reconnect if needed and check path loss/delay and peer responsiveness",
			f.key, f.state, now.Sub(f.lastAckTime), b.ackIdleFail, f.serverNxt-f.sndUna)
	}
	if b.errorSignal != "none" {
		_ = b.sendToGuest(f, b.buildTCPFlowLocked(f, f.serverNxt, fRST|fACK, nil, nil, 0, 64))
	}
	b.removeFlowLocked(f)
}

// The existing reaper also covers established flows whose host reader is idle.
// Recheck progress under stateMu so an ACK cannot race a stale snapshot decision.
func (b *tcpBridge) expireACKIdleFlows(now time.Time) {
	for _, f := range b.flowSnapshot() {
		f.stateMu.Lock()
		if f.state == tcpEstablished {
			b.expireACKIdleLocked(f, now)
		}
		f.stateMu.Unlock()
	}
}
