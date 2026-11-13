package application

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/irctrakz/wgslirp/pkg/socket"
)

// ErrRuntimeStateUncertain maps to the helper's terminal error of the same
// name. Underlying UAPI output and errors may contain private configuration.
var ErrRuntimeStateUncertain = errors.New("runtime_state_uncertain")

// Status is the portable result of a version 1 status request. The controller
// supplies the revision in the response envelope when it serializes commands.
type Status struct {
	State           string       `json:"state"`
	ListenPort      *uint16      `json:"listen_port"`
	ServerPublicKey *string      `json:"server_public_key"`
	UptimeMS        int64        `json:"uptime_ms"`
	Peers           []PeerStatus `json:"peers"`
	Metrics         *Metrics     `json:"metrics"`
}

type PeerStatus struct {
	PublicKey            string  `json:"public_key"`
	Address              string  `json:"address"`
	Endpoint             *string `json:"endpoint"`
	LastHandshakeUnixSec *uint64 `json:"last_handshake_unix_sec"`
	RXBytes              *string `json:"rx_bytes"`
	TXBytes              *string `json:"tx_bytes"`
}

type Metrics struct {
	ActiveTCPFlows      uint64 `json:"active_tcp_flows"`
	BufferBytesInUse    uint64 `json:"buffer_bytes_in_use"`
	TCPFlowRefusals     string `json:"tcp_flow_refusals"`
	PendingDialRefusals string `json:"pending_dial_refusals"`
	BufferRefusals      string `json:"buffer_refusals"`
}

// Status returns a fresh, sanitized snapshot without polling in the background.
// The nil runtime represents idle. Running status describes the restricted
// profile (one IPv4 /32 per peer), and fails if the applied state is unreadable
// or incompatible with that profile. Callers serialize it with mutations.
func (r *Runtime) Status() (Status, error) {
	if r == nil {
		return Status{State: "idle", Peers: []PeerStatus{}}, nil
	}
	if r.ctx.Err() != nil {
		return Status{}, ErrRuntimeStateUncertain
	}
	state, err := r.device.IpcGet()
	if err != nil {
		return Status{}, ErrRuntimeStateUncertain
	}
	status, err := parseStatus(state)
	if err != nil {
		return Status{}, err
	}
	status.UptimeMS = time.Since(r.readyAt).Milliseconds()
	status.Metrics = portableMetrics(r.socket.TCPResourceMetrics())
	return status, nil
}

func portableMetrics(sample socket.TCPResourceMetrics, available bool) *Metrics {
	if !available {
		return nil
	}
	return &Metrics{
		ActiveTCPFlows:      sample.ActiveFlows,
		BufferBytesInUse:    sample.BufferBytesInUse,
		TCPFlowRefusals:     strconv.FormatUint(sample.FlowRefusals, 10),
		PendingDialRefusals: strconv.FormatUint(sample.PendingDialRefusals, 10),
		BufferRefusals:      strconv.FormatUint(sample.BufferRefusals, 10),
	}
}

// The UAPI returns hex keys, the actual listener port and the live allowed IPs.
// Use these for applied state. Optional telemetry can be absent independently.
func parseStatus(state string) (Status, error) {
	status := Status{State: "running", Peers: []PeerStatus{}}
	var peer *PeerStatus
	for _, line := range strings.Split(state, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if key == "public_key" {
			raw, err := hex.DecodeString(value)
			if err != nil || len(raw) != 32 || [32]byte(raw) == [32]byte{} || len(status.Peers) >= 128 {
				return Status{}, ErrRuntimeStateUncertain
			}
			status.Peers = append(status.Peers, PeerStatus{PublicKey: base64.StdEncoding.EncodeToString(raw)})
			peer = &status.Peers[len(status.Peers)-1]
			continue
		}
		if peer == nil {
			switch key {
			case "private_key":
				raw, err := hex.DecodeString(value)
				if err != nil || len(raw) != 32 || [32]byte(raw) == [32]byte{} || status.ServerPublicKey != nil {
					clear(raw)
					return Status{}, ErrRuntimeStateUncertain
				}
				privateKey, err := ecdh.X25519().NewPrivateKey(raw)
				clear(raw)
				if err != nil {
					return Status{}, ErrRuntimeStateUncertain
				}
				public := base64.StdEncoding.EncodeToString(privateKey.PublicKey().Bytes())
				status.ServerPublicKey = &public
			case "listen_port":
				port, err := strconv.ParseUint(value, 10, 16)
				if err != nil || port == 0 || status.ListenPort != nil {
					return Status{}, ErrRuntimeStateUncertain
				}
				actualPort := uint16(port)
				status.ListenPort = &actualPort
			}
			continue
		}
		switch key {
		case "allowed_ip":
			prefix, err := netip.ParsePrefix(value)
			if err != nil || !validGuestIPv4(prefix.Addr()) || prefix.Bits() != 32 || peer.Address != "" {
				return Status{}, ErrRuntimeStateUncertain
			}
			peer.Address = prefix.Addr().String()
		case "endpoint":
			endpoint, err := netip.ParseAddrPort(value)
			if err == nil && endpoint.Port() != 0 && len(value) <= 96 &&
				strings.IndexFunc(value, func(r rune) bool { return r <= ' ' || r >= 127 }) == -1 {
				peer.Endpoint = &value
			}
		case "latest_handshake_time_sec", "last_handshake_time_sec":
			seconds, err := strconv.ParseUint(value, 10, 64)
			if err == nil && seconds > 0 && seconds <= 9007199254740991 {
				peer.LastHandshakeUnixSec = &seconds
			}
		case "rx_bytes":
			peer.RXBytes = statusCounter(value)
		case "tx_bytes":
			peer.TXBytes = statusCounter(value)
		}
	}
	if status.ListenPort == nil || status.ServerPublicKey == nil {
		return Status{}, ErrRuntimeStateUncertain
	}
	keys, addresses := map[string]bool{}, map[string]bool{}
	for _, peer := range status.Peers {
		if peer.Address == "" || keys[peer.PublicKey] || addresses[peer.Address] ||
			peer.PublicKey == *status.ServerPublicKey {
			return Status{}, ErrRuntimeStateUncertain
		}
		keys[peer.PublicKey], addresses[peer.Address] = true, true
	}
	sort.Slice(status.Peers, func(i, j int) bool {
		return status.Peers[i].PublicKey < status.Peers[j].PublicKey
	})
	return status, nil
}

func statusCounter(value string) *string {
	count, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return nil
	}
	canonical := strconv.FormatUint(count, 10)
	return &canonical
}
