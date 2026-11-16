//go:build integration

package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Exercise the standalone binary's actual signal handler. The separate image
// acceptance test covers SIGTERM under encrypted traffic in a container.
func TestStandaloneSIGTERM(t *testing.T) {
	binary := os.Getenv("WGSLIRP_RELEASE_BINARY")
	if binary == "" {
		t.Skip("set WGSLIRP_RELEASE_BINARY to the built Linux executable")
	}
	reservation, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	port := reservation.LocalAddr().(*net.UDPAddr).Port
	reservation.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary)
	cmd.Env = []string{
		"WG_PRIVATE_KEY=dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=",
		fmt.Sprintf("WG_LISTEN_PORT=%d", port),
		"ICMP_ECHO=false",
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	lines := make(chan string, 16)
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			select {
			case lines <- scanner.Text():
			case <-ctx.Done():
				return
			}
		}
	}()
	waited := false
	defer func() {
		if !waited {
			cancel()
			_ = cmd.Wait()
		}
	}()

	for {
		select {
		case line, ok := <-lines:
			if !ok {
				t.Fatal("standalone exited before reporting readiness")
			}
			t.Log(line)
			if strings.Contains(line, fmt.Sprintf("wireguard device up on UDP :%d", port)) {
				if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
					t.Fatal(err)
				}
				// Drain stderr to EOF before Wait closes the pipe.
				for line := range lines {
					t.Log(line)
				}
				err := cmd.Wait()
				waited = true
				if err != nil {
					t.Fatalf("standalone SIGTERM exit: %v", err)
				}
				rebound, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: port})
				if err != nil {
					t.Fatalf("listener port still occupied after exit: %v", err)
				}
				rebound.Close()
				return
			}
		case <-ctx.Done():
			t.Fatal("standalone did not report readiness before the deadline")
		}
	}
}
