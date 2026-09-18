package wireguard

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestPeerStateAndHandshakeSummary(t *testing.T) {
	state := "private_key=secret\nlatest_handshake_time_sec=900\npublic_key=a\nlatest_handshake_time_sec=1000\npersistent_keepalive_interval=25\nunknown=future\nrx_bytes=4\ntx_bytes=5\npeer=b\nlatest_handshake_time_sec=900\npublic_key=c\nlatest_handshake_time_sec=0\npublic_key=d\nlatest_handshake_time_sec=999999999999999999999999999\npersistent_keepalive_interval=18446744073709551615\n"
	peers := ParsePeerState(state)
	if len(peers) != 4 || peers[0].RX != 4 || peers[0].TX != 5 || peers[3].Handshake != 0 || peers[3].Keepalive != 0 {
		t.Fatalf("peers: %+v", peers)
	}
	expected := map[string]uint64{"peers": 4, "fresh": 1, "stale": 3, "oldest_sec": 100, "newest_sec": 0}
	if got := HandshakeSummary(peers, time.Unix(1000, 0)); !reflect.DeepEqual(got, expected) {
		t.Fatalf("summary: %v", got)
	}
	peers[1].Handshake = 1100
	got := HandshakeSummary(peers, time.Unix(1000, 0))
	if got["fresh"] != 2 || got["oldest_sec"] != 0 {
		t.Fatalf("future clock: %v", got)
	}
	if got := HandshakeSummary(ParsePeerState("private_key=secret\n"), time.Unix(1000, 0)); got["peers"] != 0 {
		t.Fatal(got)
	}
	if strings.Contains(peers[0].PublicKey, "secret") {
		t.Fatal("secret retained")
	}
}
