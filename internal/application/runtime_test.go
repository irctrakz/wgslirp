package application

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/irctrakz/wgslirp/pkg/core"
	"github.com/irctrakz/wgslirp/pkg/socket"
	wg "github.com/irctrakz/wgslirp/pkg/wireguard"
)

func TestRuntimeLifecycle(t *testing.T) {
	const marker = "WGSLIRP_RUNTIME_TEST"
	if mode := os.Getenv(marker); mode != "" {
		testRuntimeLifecycle(t, mode)
		return
	}
	// Give each case fresh process-wide pooling, capture and runtime ownership.
	for _, mode := range []string{"shutdown", "bind-failure", "cancel-start", "run-cancel"} {
		t.Run(mode, func(t *testing.T) {
			runRuntimeSubprocess(t, "TestRuntimeLifecycle", marker+"="+mode,
				"WG_PRIVATE_KEY=invalid", "WG_TUN_QUEUE_CAP=invalid", "POOLING=invalid")
		})
	}
}

func runRuntimeSubprocess(t *testing.T, test string, env ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+test+"$")
	cmd.Env = append(os.Environ(), env...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("lifecycle subprocess: %v\n%s", err, out)
	}
}

func testConfig() Config {
	cfg := Config{
		Device: wg.DeviceConfig{
			PrivateKey: "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=",
			MTU:        1380,
		},
		Socket:  socket.DefaultConfig(),
		Tun:     wg.DefaultTunConfig(),
		Pool:    socket.PoolConfig{Enabled: true},
		Capture: wg.DefaultCaptureConfig(),
	}
	cfg.Socket.Protocol = "ip4:tcp"
	cfg.Socket.MTU = cfg.Device.MTU
	return cfg
}

func testRuntimeLifecycle(t *testing.T, mode string) {
	cfg := testConfig()
	cfg.Capture.Path = filepath.Join(t.TempDir(), "capture.pcap")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	switch mode {
	case "shutdown":
		// A cancelled or invalid preflight must not consume the one runtime slot.
		cancelled, stop := context.WithCancel(ctx)
		stop()
		if _, err := Start(cancelled, cfg, Observers{}); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled preflight: %v", err)
		}
		invalid := cfg
		invalid.Tun.QueueCapacity = 0
		if _, err := Start(ctx, invalid, Observers{}); err == nil {
			t.Fatal("invalid TUN settings accepted")
		}
		for _, protocol := range []string{"unsupported", "ip4:tcp-typo", "ip6:tcp"} {
			invalid = cfg
			invalid.Socket.Protocol = protocol
			if _, err := Start(ctx, invalid, Observers{}); err == nil || !strings.Contains(err.Error(), "unsupported protocol") {
				t.Fatalf("invalid socket protocol %q: %v", protocol, err)
			}
		}
		if _, err := os.Stat(cfg.Capture.Path); !os.IsNotExist(err) {
			t.Fatalf("preflight touched capture file: %v", err)
		}
		joined := make(chan struct{})
		r, err := Start(ctx, cfg, Observers{
			DeviceReady: func(ctx context.Context, _ *socket.SocketInterface, _ *wg.WGTun, _ wg.DeviceHandle) {
				<-ctx.Done()
				close(joined)
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		var callers sync.WaitGroup
		for i := 0; i < 2; i++ {
			callers.Add(1)
			go func() {
				defer callers.Done()
				if err := r.Close(); err != nil {
					t.Error(err)
				}
			}()
		}
		callers.Wait()
		select {
		case <-joined:
		default:
			t.Fatal("close returned before observer exited")
		}
		if _, err := Start(ctx, cfg, Observers{}); err == nil || !strings.Contains(err.Error(), "already attempted") {
			t.Fatalf("runtime restarted in the same process: %v", err)
		}
	case "bind-failure":
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		cfg.Device.ListenPort = conn.LocalAddr().(*net.UDPAddr).Port
		joined := make(chan struct{})
		_, err = Start(ctx, cfg, Observers{
			SocketReady: func(ctx context.Context, _ *socket.SocketInterface) {
				<-ctx.Done()
				close(joined)
			},
		})
		if err == nil || !strings.Contains(err.Error(), "wireguard start:") {
			t.Fatalf("expected WireGuard bind failure: %v", err)
		}
		select {
		case <-joined:
		default:
			t.Fatal("failed start returned before observer exited")
		}
	case "cancel-start":
		_, err := Start(ctx, cfg, Observers{
			WrapProcessor: func(primary core.PacketProcessor) core.PacketProcessor {
				cancel()
				return primary
			},
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel during startup: %v", err)
		}
	case "run-cancel":
		if err := Run(ctx, cfg, Observers{
			DeviceReady: func(context.Context, *socket.SocketInterface, *wg.WGTun, wg.DeviceHandle) {
				cancel()
			},
		}); err != nil {
			t.Fatalf("run shutdown on cancellation: %v", err)
		}
	default:
		t.Fatalf("unexpected lifecycle case %q", mode)
	}
	if err := wg.ConfigurePCAP(cfg.Capture); err == nil || !strings.Contains(err.Error(), "closed or failed") {
		t.Fatalf("capture remained open after cleanup: %v", err)
	}
}

func TestRuntimeProtocolDefaults(t *testing.T) {
	cfg := testConfig()
	for _, protocol := range []string{"", "ip4:icmp", "ip4:tcp", "ip4:udp"} {
		cfg.Socket.Protocol = protocol
		if err := cfg.Validate(); err != nil {
			t.Errorf("protocol %q: %v", protocol, err)
		}
	}
}
