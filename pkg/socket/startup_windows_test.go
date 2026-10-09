package socket

import (
	"strings"
	"testing"
)

func TestWindowsEchoRequiresExplicitOptOut(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Protocol, cfg.ICMPEcho = "ip4:tcp", true
	s := NewSocketInterface(cfg)
	s.SetPacketProcessor(&captureProcessor{})
	defer s.Stop()
	if err := s.Start(); err == nil || !strings.Contains(err.Error(), "ICMP_ECHO=false") {
		t.Fatalf("expected actionable Windows echo error, got %v", err)
	}
	if s.conn != nil || s.dgram != nil || s.tcp != nil || s.udp != nil {
		t.Fatal("failed echo startup created forwarding resources")
	}
}
