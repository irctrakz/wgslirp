package main

import "testing"

func TestSocketConfigEnvironment(t *testing.T) {
	values := map[string]string{"TCP_ACK_DELAY_MS": "0", "TCP_FLOW_LIFETIME_SEC": "37", "UDP_FLOW_LIFETIME_SEC": "19", "TCP_REASSEMBLY_CAP_BYTES": "4096", "MAX_TCP_FLOWS": "2", "MAX_UDP_FLOWS": "3"}
	values["MAX_PENDING_TCP_DIALS"] = "4"
	values["SOCKET_BUFFER_CAP_BYTES"] = "8192"
	values["TCP_PEND_CAP_BYTES"] = "1024"
	values["TCP_RETRANSMIT_CAP_BYTES"] = "2048"
	lookup := func(key string) (string, bool) { v, ok := values[key]; return v, ok }
	cfg, err := socketConfig(1380, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxPendingTCPDials != 4 || cfg.SocketBufferCapBytes != 8192 || cfg.TCPPendingCapBytes != 1024 || cfg.TCPRetransmitCapBytes != 2048 {
		t.Fatalf("ignored safety budgets: %+v", cfg)
	}
	if cfg.TCPAckDelayMs != 0 || cfg.TCPFlowLifetimeSec != 37 || cfg.UDPFlowLifetimeSec != 19 || cfg.TCPReassemblyCapBytes != 4096 || cfg.MaxTCPFlows != 2 || cfg.MaxUDPFlows != 3 || cfg.MTU != 1380 {
		t.Fatalf("unexpected configuration: %+v", cfg)
	}
	for _, value := range []string{"", "invalid", "-1", "999999999999999999999999"} {
		values["MAX_TCP_FLOWS"] = value
		if _, err := socketConfig(1380, lookup); err == nil {
			t.Fatalf("accepted %q", value)
		}
	}
	defaults, err := socketConfig(1380, func(string) (string, bool) { return "", false })
	if err != nil || defaults.TCPAckDelayMs != 10 || defaults.TCPFlowLifetimeSec != 120 || defaults.TCPReassemblyCapBytes != 131072 {
		t.Fatalf("defaults: %+v %v", defaults, err)
	}
}
