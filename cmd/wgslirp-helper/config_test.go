package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/irctrakz/wgslirp/pkg/socket"
)

func TestRestrictedHelperConfig(t *testing.T) {
	const config = `{"private_key":"dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=","peers":[],"mappings":[{"guest_ip":"10.77.0.1","guest_port":8096,"host_ip":"127.0.0.1","host_port":8096}]}`
	var params object
	decoder := json.NewDecoder(strings.NewReader(config))
	decoder.UseNumber()
	if err := decoder.Decode(&params); err != nil {
		t.Fatal(err)
	}
	cfg, routes, ok := parseConfig(params)
	if !ok {
		t.Fatal("valid restricted wire shape rejected")
	}
	policy, err := socket.NewDestinationPolicy(routes)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Socket.Destinations = policy
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Device.ListenPort != 51820 || cfg.Device.MTU != 1380 || cfg.Socket.MTU != 1380 ||
		cfg.Socket.MaxTCPFlows != 256 || cfg.Socket.MaxPendingTCPDials != 64 ||
		cfg.Socket.SocketBufferCapBytes != 67108864 || cfg.Tun.QueueCapacity != 1024 {
		t.Fatal("restricted defaults differ from the protocol")
	}
}
