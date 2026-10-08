package wireguard

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/irctrakz/wgslirp/pkg/socket"
)

func TestPacketErrorLogPreservesLocalSizeRejection(t *testing.T) {
	var lines []string
	l := &packetErrorLog{emit: func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) }}
	err := fmt.Errorf("UDP slirp error: local host rejected packet for size: %w; reduce datagram size or check host path MTU", syscall.EMSGSIZE)
	l.Errorf("Failed to write packets to TUN device: %v", err)
	l.Flush()
	if len(lines) != 1 || !strings.Contains(lines[0], syscall.EMSGSIZE.Error()) || !strings.Contains(lines[0], "reduce datagram size or check host path MTU") {
		t.Fatal("local rejection reason/action hidden", lines)
	}
}

func TestPacketErrorLogSummarizesBurstAndQuietTail(t *testing.T) {
	var lines []string
	l := &packetErrorLog{emit: func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) }}
	for i := 0; i < 100; i++ {
		l.Errorf("Failed to write packets to TUN device: %v", fmt.Errorf("wrapped: %w", socket.ErrUnsupportedFragment))
	}
	if len(lines) != 1 || !strings.Contains(lines[0], "incoming IPv4 fragments are unsupported") {
		t.Fatalf("first failure: %v", lines)
	}
	l.Flush()
	if len(lines) != 2 || lines[1] != "Repeated TUN packet failures: reason=unsupported_ipv4_fragment suppressed=99" {
		t.Fatalf("summary: %v", lines)
	}
	l.Flush()
	if len(lines) != 2 {
		t.Fatal("quiet flush duplicated summary")
	}
	l.Errorf("Failed to write packets to TUN device: %v", socket.ErrUnsupportedFragment)
	if len(lines) != 3 {
		t.Fatal("new interval must log first failure")
	}
}

func TestPacketErrorLogKeepsCategoriesAndUnexpectedErrorsVisible(t *testing.T) {
	var lines []string
	l := &packetErrorLog{emit: func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) }}
	for _, reason := range packetErrorReasons {
		for i := 0; i < 3; i++ {
			l.Errorf("Failed to write packets to TUN device: %v", fmt.Errorf("context: %w", reason.err))
		}
	}
	for i := 0; i < 2; i++ {
		l.Errorf("Failed to write packets to TUN device: %v", errors.New("unexpected host failure"))
		l.Errorf("Other WireGuard error: %v", socket.ErrUnsupportedFragment)
	}
	if len(lines) != len(packetErrorReasons)+4 {
		t.Fatalf("errors hidden: %v", lines)
	}
	l.Flush()
	for _, reason := range packetErrorReasons {
		want := "Repeated TUN packet failures: reason=" + reason.name + " suppressed=2"
		found := false
		for _, line := range lines {
			if line == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing %s", want)
		}
	}
}

func TestPacketErrorLogConcurrentFlushAndShutdown(t *testing.T) {
	var mu sync.Mutex
	var reported uint64
	l := &packetErrorLog{emit: func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		if strings.HasPrefix(format, "Repeated TUN") {
			reported += args[1].(uint64)
		} else {
			reported++
		}
	}}
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 1000; j++ {
				l.Errorf("Failed to write packets to TUN device: %v", socket.ErrUnsupportedFragment)
			}
		}()
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		for i := 0; i < 100; i++ {
			l.Flush()
		}
	}()
	workers.Wait()
	h := &wgHandle{done: make(chan struct{}), packetErrors: l}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if reported != 8000 {
		t.Fatalf("reported=%d want=8000", reported)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if reported != 8000 {
		t.Fatal("repeated shutdown duplicated counts")
	}
}
