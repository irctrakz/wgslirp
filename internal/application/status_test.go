package application

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/irctrakz/wgslirp/pkg/socket"
)

const privateHex = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
const publicBase64 = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo="
const peerHex = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"

func TestPortableStatus(t *testing.T) {
	var idle *Runtime
	status, err := idle.Status()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(status)
	if err != nil || string(raw) != `{"state":"idle","listen_port":null,"server_public_key":null,"uptime_ms":0,"peers":[],"metrics":null}` {
		t.Fatalf("idle status: %s (%v)", raw, err)
	}

	// This is the pinned dependency's UAPI field spelling and hex encoding.
	// Deliberately put the peers in reverse public-key order.
	secret := strings.Repeat("f", 64)
	state := "private_key=" + privateHex + "\nlisten_port=49152\npublic_key=" + strings.Repeat("42", 32) +
		"\nallowed_ip=10.0.0.2/32\nendpoint=invalid\nlast_handshake_time_sec=0\ntx_bytes=invalid" +
		"\npublic_key=" + peerHex +
		"\npreshared_key=" + secret + "\nallowed_ip=10.0.0.3/32\nendpoint=[fe80::1%eth0]:40000" +
		"\nlast_handshake_time_sec=1710000000\nrx_bytes=18446744073709551615\ntx_bytes=0\n"
	status, err = parseStatus(state)
	if err != nil {
		t.Fatal(err)
	}
	if *status.ServerPublicKey != publicBase64 || *status.ListenPort != 49152 {
		t.Fatal("status did not report the derived public key and bound port")
	}
	if len(status.Peers) != 2 || status.Peers[0].Address != "10.0.0.3" || status.Peers[1].Address != "10.0.0.2" {
		// The '3' prefix sorts before 'Q' in the wire representation.
		t.Fatalf("peers are not sorted by wire public key: %+v", status.Peers)
	}
	raw, err = json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"rx_bytes":"18446744073709551615"`, `"tx_bytes":"0"`,
		`"last_handshake_unix_sec":1710000000`, `"endpoint":"[fe80::1%eth0]:40000"`,
		`"endpoint":null,"last_handshake_unix_sec":null,"rx_bytes":null,"tx_bytes":null`,
	} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("missing %s in status: %s", want, raw)
		}
	}
	for _, forbidden := range []string{"private_key", "preshared_key", privateHex, secret} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatal("status disclosed private UAPI data")
		}
	}
}

func TestStatusFailsWhenAppliedPeerStateIsUncertain(t *testing.T) {
	header := "private_key=" + privateHex + "\nlisten_port=49152\n"
	for _, state := range []string{
		"private_key=" + privateHex,
		"private_key=" + strings.Repeat("00", 32) + "\nlisten_port=49152",
		header + "public_key=" + peerHex,
		header + "public_key=" + strings.Repeat("00", 32) + "\nallowed_ip=10.0.0.2/32",
		header + "public_key=" + peerHex + "\nallowed_ip=10.0.0.0/24",
		header + "public_key=" + peerHex + "\nallowed_ip=0.0.0.2/32",
		header + "public_key=" + peerHex + "\nallowed_ip=127.0.0.2/32",
		header + "public_key=" + peerHex + "\nallowed_ip=240.0.0.2/32",
		header + "public_key=" + peerHex + "\nallowed_ip=10.0.0.2/32\nallowed_ip=10.0.0.3/32",
		header + "public_key=" + peerHex + "\nallowed_ip=10.0.0.2/32\npublic_key=" + peerHex + "\nallowed_ip=10.0.0.3/32",
	} {
		if _, err := parseStatus(state); !errors.Is(err, ErrRuntimeStateUncertain) || err.Error() != "runtime_state_uncertain" {
			t.Fatal("invalid applied state did not return a sanitized error")
		}
	}
}

func TestPortableMetricsAvailability(t *testing.T) {
	sample := socket.TCPResourceMetrics{
		ActiveFlows: 3, BufferBytesInUse: 8192, PendingDialRefusals: 2, BufferRefusals: 3,
	}
	got := portableMetrics(sample, true)
	if got == nil || *got != (Metrics{3, 8192, "0", "2", "3"}) {
		t.Fatalf("metrics: %+v", got)
	}
	if portableMetrics(sample, false) != nil {
		t.Fatal("missing metrics represented as zero")
	}
}
