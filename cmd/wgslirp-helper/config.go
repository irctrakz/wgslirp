package main

import (
	"encoding/json"
	"net/netip"
	"regexp"
	"strconv"

	"github.com/irctrakz/wgslirp/internal/application"
	"github.com/irctrakz/wgslirp/pkg/socket"
	wg "github.com/irctrakz/wgslirp/pkg/wireguard"
)

const maxExactInteger = 1<<53 - 1

var (
	keyPattern      = regexp.MustCompile("^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$")
	opPattern       = regexp.MustCompile("^[a-z][a-z0-9_]{0,31}$")
	instancePattern = regexp.MustCompile("^[0-9a-f]{32}$")
	versionPattern  = regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$")
)

type object = map[string]any

func exactFields(obj object, keys ...string) bool {
	if len(obj) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, ok := obj[key]; !ok {
			return false
		}
	}
	return true
}

func integer(value any, min, max uint64) (uint64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseUint(string(number), 10, 64)
	return n, err == nil && n >= min && n <= max
}

func patterned(value any, pattern *regexp.Regexp) (string, bool) {
	s, ok := value.(string)
	return s, ok && pattern.MatchString(s)
}

func ipv4(value any) netip.Addr {
	s, _ := value.(string)
	ip, _ := netip.ParseAddr(s)
	if !ip.Is4() {
		return netip.Addr{}
	}
	return ip
}

type peer struct {
	key     string
	address netip.Addr
}

func parsePeer(value any) (peer, bool) {
	p, ok := value.(object)
	key, keyOK := patterned(p["public_key"], keyPattern)
	address := ipv4(p["address"])
	return peer{key, address}, ok && exactFields(p, "public_key", "address") && keyOK && address.IsValid()
}

func parseMapping(value any) (socket.TCPMapping, bool) {
	m, ok := value.(object)
	guestPort, guestOK := integer(m["guest_port"], 1, 65535)
	hostPort, hostOK := integer(m["host_port"], 1, 65535)
	guest, host := ipv4(m["guest_ip"]), ipv4(m["host_ip"])
	return socket.TCPMapping{
			Guest: netip.AddrPortFrom(guest, uint16(guestPort)),
			Host:  netip.AddrPortFrom(host, uint16(hostPort)),
		}, ok && exactFields(m, "guest_ip", "guest_port", "host_ip", "host_port") &&
			guestOK && hostOK && guest.IsValid() && host.IsValid()
}

// parseConfig validates the wire shape without applying semantic policy.
// Semantic checks are deferred until after checking the runtime state.
func parseConfig(params object) (application.Config, []socket.TCPMapping, bool) {
	cfg := application.Config{
		Device:  wg.DeviceConfig{ListenPort: 51820, MTU: 1380},
		Socket:  socket.DefaultConfig(),
		Tun:     wg.DefaultTunConfig(),
		Capture: wg.DefaultCaptureConfig(),
		Pool:    socket.PoolConfig{Enabled: true},
	}
	cfg.Socket.Protocol = "ip4:tcp"
	key, keyOK := patterned(params["private_key"], keyPattern)
	peers, peersOK := params["peers"].([]any)
	mappings, mappingsOK := params["mappings"].([]any)
	if !keyOK || !peersOK || len(peers) > 128 || !mappingsOK || len(mappings) < 1 || len(mappings) > 32 {
		return cfg, nil, false
	}
	cfg.Device.PrivateKey = key
	for key, value := range params {
		switch key {
		case "private_key", "peers", "mappings":
		case "listen_port":
			n, ok := integer(value, 0, 65535)
			if !ok {
				return cfg, nil, false
			}
			cfg.Device.ListenPort = int(n)
		case "mtu":
			n, ok := integer(value, 576, 9000)
			if !ok {
				return cfg, nil, false
			}
			cfg.Device.MTU = int(n)
		case "limits":
			if !parseLimits(&cfg, value) {
				return cfg, nil, false
			}
		default:
			return cfg, nil, false
		}
	}
	cfg.Socket.MTU = cfg.Device.MTU
	for _, raw := range peers {
		p, ok := parsePeer(raw)
		if !ok {
			return cfg, nil, false
		}
		cfg.Device.Peers = append(cfg.Device.Peers, wg.PeerConfig{
			PublicKey: p.key, AllowedIPs: []string{netip.PrefixFrom(p.address, 32).String()},
		})
	}
	routes := make([]socket.TCPMapping, 0, len(mappings))
	for _, raw := range mappings {
		mapping, ok := parseMapping(raw)
		if !ok {
			return cfg, nil, false
		}
		routes = append(routes, mapping)
	}
	return cfg, routes, true
}

func parseLimits(cfg *application.Config, value any) bool {
	limits, ok := value.(object)
	if !ok {
		return false
	}
	for key, value := range limits {
		var target *int
		var min, max uint64 = 1, 65536
		switch key {
		case "max_tcp_flows":
			target = &cfg.Socket.MaxTCPFlows
		case "max_pending_dials":
			target = &cfg.Socket.MaxPendingTCPDials
		case "socket_buffer_bytes":
			target = &cfg.Socket.SocketBufferCapBytes
			min, max = 1<<20, 1<<30
		case "tun_queue_packets":
			target = &cfg.Tun.QueueCapacity
		default:
			return false
		}
		n, ok := integer(value, min, max)
		if !ok {
			return false
		}
		*target = int(n)
	}
	return true
}
