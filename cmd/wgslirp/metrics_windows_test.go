package main

import (
	"github.com/irctrakz/wgslirp/pkg/socket"
	"testing"
)

func TestWindowsOmitsUnavailableFDLimits(t *testing.T) {
	limits := buildServerLimits(socket.SocketDetailedMetrics{})
	for _, key := range []string{"nofile_soft", "nofile_hard", "fd_util_pct"} {
		if _, ok := limits[key]; ok {
			t.Fatalf("unavailable metric %s reported as available", key)
		}
	}
}
