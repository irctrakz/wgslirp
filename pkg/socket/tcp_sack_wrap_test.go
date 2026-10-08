package socket

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
	"time"
)

func sackOption(left, right uint32) []byte {
	opts := make([]byte, 12)
	opts[0], opts[1] = 5, 10
	binary.BigEndian.PutUint32(opts[2:6], left)
	binary.BigEndian.PutUint32(opts[6:10], right)
	return opts
}

// Seed the sequence boundary instead of transferring 4 GiB. Exercise actual
// segmentation, wire ACK/SACK processing, hole retransmission and budget release.
func TestTCPSACKLossRecoveryAcrossWrap(t *testing.T) {
	for _, start := range []uint32{1000, ^uint32(0) - 899, ^uint32(0) - 1199, ^uint32(0) - 1799} {
		t.Run(fmt.Sprint(start), func(t *testing.T) {
			b, f, c := concurrentFlow(t)
			f.sndUna, f.serverNxt = start, start
			f.advWnd = 4000
			f.sackPermitted = true
			payload := bytes.Repeat([]byte("wrap"), 450)
			if !b.sendPayload(f, payload) {
				t.Fatal("send failed")
			}
			before := len(c.snapshot())
			// Lose segments 1 and 3, selectively ACK only segment 2 (which may wrap).
			for i := 0; i < 3; i++ {
				p := buildIPv4TCPOpts(f.srcIP, f.dstIP, f.srcPort, f.dstPort, 100, start, 0x10, nil, sackOption(start+600, start+1200))
				if err := b.HandleOutbound(p); err != nil {
					t.Fatal(err)
				}
			}
			packets := c.snapshot()
			if len(packets) <= before {
				t.Fatal("missing first hole retransmission")
			}
			for _, p := range packets[before:] {
				if binary.BigEndian.Uint32(p[24:28]) != start || !bytes.Equal(p[40:], payload[:600]) {
					t.Fatal("retransmitted SACKed/wrong data")
				}
			}
			before = len(packets)
			closeOutbound(t, b, f, 100, start+1200, 0x10, nil)
			packets = c.snapshot()
			if len(packets) <= before {
				t.Fatal("partial ACK did not recover second hole")
			}
			if p := packets[len(packets)-1]; binary.BigEndian.Uint32(p[24:28]) != start+1200 || !bytes.Equal(p[40:], payload[1200:]) {
				t.Fatal("wrong second hole")
			}
			closeOutbound(t, b, f, 100, start+1799, 0x10, nil)
			if !f.sackRecovery {
				t.Fatal("recovery ended with one byte still outstanding")
			}
			closeOutbound(t, b, f, 100, start+1800, 0x10, nil)
			if f.sackRecovery || f.sndUna != start+1800 || len(f.txQueue) != 0 || len(f.sackList) != 0 {
				t.Fatal("recovery state retained after cumulative ACK")
			}
			assertBudget(t, b.buffers, 0)
		})
	}
}

func TestTCPSACKRejectsUnsentAndStaleRanges(t *testing.T) {
	f := &tcpFlow{sndUna: ^uint32(0) - 99, serverNxt: 200}
	parseSACKBlocks(f, sackOption(^uint32(0)-49, 50))
	if !isSACKed(f, ^uint32(0)-24, 25) {
		t.Fatal("valid wrap block lost")
	}
	parseSACKBlocks(f, sackOption(100, 300))
	if isSACKed(f, 150, 250) {
		t.Fatal("unsent bytes accepted")
	}
	f.sndUna = 50
	parseSACKBlocks(f, nil)
	if len(f.sackList) != 0 {
		t.Fatal("stale SACK retained")
	}
}

// A receiver may discard selectively acknowledged bytes. Only cumulative ACKs
// release ownership; an expired oldest segment must remain retransmittable.
func TestTCPRTORetransmitsRenegedSACKAcrossWrap(t *testing.T) {
	for _, start := range []uint32{1000, ^uint32(0) - 899} {
		t.Run(fmt.Sprint(start), func(t *testing.T) {
			b, f, capture := concurrentFlow(t)
			f.sndUna, f.serverNxt = start, start
			f.sackPermitted = true
			payload := bytes.Repeat([]byte("renege"), 200)
			if !b.sendPayload(f, payload) {
				t.Fatal("send failed")
			}
			p := buildIPv4TCPOpts(f.srcIP, f.dstIP, f.srcPort, f.dstPort, 100, start, 0x10, nil, sackOption(start+600, start+1200))
			if err := b.HandleOutbound(p); err != nil {
				t.Fatal(err)
			}
			closeOutbound(t, b, f, 100, start+600, 0x10, nil)
			f.stateMu.Lock()
			if !isSACKed(f, start+600, start+1200) {
				f.stateMu.Unlock()
				t.Fatal("SACK was not retained")
			}
			f.rto = 50 * time.Millisecond
			f.txMu.Lock()
			f.txQueue[0].sentAt = time.Now().Add(-time.Second)
			f.txMu.Unlock()
			f.stateMu.Unlock()
			before := len(capture.snapshot())
			if !b.launch(func() { b.retransmitLoop(f) }) {
				t.Fatal("worker rejected")
			}
			packet, _ := closePacket(t, capture, before, func(p []byte) bool { return len(p) > 40 })
			if binary.BigEndian.Uint32(packet[24:28]) != start+600 || !bytes.Equal(packet[40:], payload[600:]) {
				t.Fatal("wrong reneged segment retransmitted")
			}
			f.stateMu.Lock()
			stillSACKed := isSACKed(f, start+600, start+1200)
			f.stateMu.Unlock()
			if stillSACKed {
				t.Fatal("stale SACK survived RTO")
			}
			closeOutbound(t, b, f, 100, start+1200, 0x10, nil)
			b.stop()
			assertBudget(t, b.buffers, 0)
		})
	}
}
