package wireguard

import (
	"strconv"
	"strings"
	"time"
)

// PeerState contains only monitoring fields; private/preshared keys are ignored.
type PeerState struct {
	PublicKey, Endpoint string
	Handshake           int64
	Keepalive, RX, TX   uint64
}

// ParsePeerState tolerates unknown UAPI fields and never returns device secrets.
func ParsePeerState(state string) []PeerState {
	var peers []PeerState
	for _, line := range strings.Split(state, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		if key == "public_key" || key == "peer" {
			peers = append(peers, PeerState{PublicKey: value})
			continue
		}
		if len(peers) == 0 {
			continue
		}
		p := &peers[len(peers)-1]
		switch key {
		case "endpoint":
			p.Endpoint = value
		case "latest_handshake_time_sec":
			v, err := strconv.ParseInt(value, 10, 64)
			if err == nil {
				p.Handshake = v
			}
		case "persistent_keepalive_interval":
			v, err := strconv.ParseUint(value, 10, 16)
			if err == nil {
				p.Keepalive = v
			}
		case "rx_bytes":
			v, err := strconv.ParseUint(value, 10, 64)
			if err == nil {
				p.RX = v
			}
		case "tx_bytes":
			v, err := strconv.ParseUint(value, 10, 64)
			if err == nil {
				p.TX = v
			}
		}
	}
	return peers
}

// HandshakeSummary counts peer sections once. Never-handshaken peers are stale;
// ages describe only completed handshakes, clamping future timestamps to zero.
func HandshakeSummary(peers []PeerState, now time.Time) map[string]uint64 {
	m := map[string]uint64{"peers": uint64(len(peers)), "fresh": 0, "stale": 0, "oldest_sec": 0, "newest_sec": 0}
	haveAge := false
	for _, p := range peers {
		if p.Handshake <= 0 {
			continue
		}
		age := uint64(0)
		if p.Handshake < now.Unix() {
			age = uint64(now.Unix() - p.Handshake)
		}
		if !haveAge || age < m["newest_sec"] {
			m["newest_sec"] = age
		}
		if age > m["oldest_sec"] {
			m["oldest_sec"] = age
		}
		haveAge = true
		threshold := uint64(60)
		if p.Keepalive <= 65535 && p.Keepalive*3 > threshold {
			threshold = p.Keepalive * 3
		}
		if age < threshold {
			m["fresh"]++
		}
	}
	m["stale"] = m["peers"] - m["fresh"]
	return m
}
