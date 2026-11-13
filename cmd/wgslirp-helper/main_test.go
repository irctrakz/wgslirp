package main

import (
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/irctrakz/wgslirp/internal/application"
	"github.com/irctrakz/wgslirp/internal/helperwire"
	"github.com/irctrakz/wgslirp/pkg/logging"
	"github.com/irctrakz/wgslirp/pkg/socket"
	wg "github.com/irctrakz/wgslirp/pkg/wireguard"
)

func TestHelperProtocolOutput(t *testing.T) {
	const marker = "WGSLIRP_TEST_HELPER_DIAGNOSTICS"
	if mode := os.Getenv(marker); mode != "" {
		testHelperOutput(t, mode)
		return
	}
	for _, mode := range []string{"debug", "bind-failure"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHelperProtocolOutput$")
			cmd.Env = append(os.Environ(), marker+"="+mode)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			stdout, err := cmd.Output()
			if err != nil || string(stdout) != "{\"id\":1}\n" {
				t.Fatalf("helper stdout: %q (%v), stderr: %s", stdout, err, &stderr)
			}
			want := "DEBUG: [wg]"
			if mode == "bind-failure" {
				want = "ERROR: [wg]"
			}
			if !strings.Contains(stderr.String(), want) {
				t.Fatalf("missing dependency diagnostics on stderr: %s", &stderr)
			}
			if strings.Contains(stderr.String(), "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=") ||
				strings.Contains(stderr.String(), "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a") {
				t.Fatal("helper diagnostics disclosed a private key")
			}
		})
	}
}

func helperTestConfig() application.Config {
	cfg := application.Config{
		Device: wg.DeviceConfig{
			PrivateKey: "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=",
			MTU:        1380,
			Options:    &wg.DeviceOptions{Debug: true},
		},
		Socket:  socket.DefaultConfig(),
		Tun:     wg.DefaultTunConfig(),
		Capture: wg.DefaultCaptureConfig(),
		Pool:    socket.PoolConfig{Enabled: true},
	}
	cfg.Socket.Protocol = "ip4:tcp"
	return cfg
}

func testHelperOutput(t *testing.T, mode string) {
	logging.SetLevel(logging.DebugLevel)
	cfg := helperTestConfig()
	if mode == "bind-failure" {
		reservation, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
		if err != nil {
			t.Fatal(err)
		}
		defer reservation.Close()
		cfg.Device.ListenPort = reservation.LocalAddr().(*net.UDPAddr).Port
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	diagnostics := configureDiagnostics()
	runtime, err := application.Start(ctx, helperConfig(cfg, diagnostics), application.Observers{})
	if mode == "bind-failure" {
		if err == nil || !strings.Contains(err.Error(), "wireguard start:") {
			t.Fatalf("expected bind failure: %v", err)
		}
	} else {
		if err != nil {
			t.Fatal(err)
		}
		if err := runtime.Close(); err != nil {
			t.Fatal(err)
		}
	}
	output, err := helperwire.NewStdoutOutput()
	if err != nil {
		t.Fatal(err)
	}
	if err := output.WriteFrame(context.Background(), []byte(`{"id":1}`)); err != nil {
		t.Fatal(err)
	}
	// Avoid the Go test harness's PASS line in the captured protocol stream.
	diagnostics.finish()
	os.Exit(0)
}
