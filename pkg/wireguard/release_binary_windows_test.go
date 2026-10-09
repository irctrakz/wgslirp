//go:build integration && windows

package wireguard

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Exercise the exact executable subsequently archived by the Windows CI job.
// Process termination here is fixture cleanup, not a graceful-shutdown claim.
func TestReleaseBinary(t *testing.T) {
	binary := os.Getenv("WGSLIRP_RELEASE_BINARY")
	if binary == "" {
		t.Skip("set WGSLIRP_RELEASE_BINARY to the already-built Windows executable")
	}
	for _, fragments := range []bool{false, true} {
		t.Run(fmt.Sprintf("fragments=%t", fragments), func(t *testing.T) {
			serverPrivate, serverPublic := encryptedKey(t)
			guestPrivate, guestPublic := encryptedKey(t)
			reservation, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			port := reservation.LocalAddr().(*net.UDPAddr).Port
			reservation.Close()
			logPath := filepath.Join(t.TempDir(), "server.log")
			log, err := os.Create(logPath)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { log.Close() })
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			cmd := exec.CommandContext(ctx, binary)
			for _, name := range []string{"SystemRoot", "TEMP", "TMP", "PATH"} {
				if value, ok := os.LookupEnv(name); ok {
					cmd.Env = append(cmd.Env, name+"="+value)
				}
			}
			cmd.Env = append(cmd.Env, "WG_PRIVATE_KEY="+serverPrivate,
				fmt.Sprintf("WG_LISTEN_PORT=%d", port), "WG_MTU=1380", "WG_PEER_0_PUBLIC_KEY="+guestPublic,
				"WG_PEER_0_ALLOWED_IPS=10.0.0.2/32", "ICMP_ECHO=false", "GOMAXPROCS=2", "GOMEMLIMIT=64MiB")
			cmd.Stdout, cmd.Stderr = log, log
			if err := cmd.Start(); err != nil {
				cancel()
				t.Fatal(err)
			}
			done := make(chan struct{})
			var processErr error
			go func() { processErr = cmd.Wait(); close(done) }()
			t.Cleanup(func() {
				cancel()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("release binary did not terminate")
				}
			})
			deadline := time.NewTimer(5 * time.Second)
			defer deadline.Stop()
			tick := time.NewTicker(10 * time.Millisecond)
			defer tick.Stop()
		ready:
			for {
				select {
				case <-done:
					t.Fatalf("release binary exited before startup: %v", processErr)
				case <-deadline.C:
					t.Fatal("release binary startup deadline")
				case <-tick.C:
					data, err := os.ReadFile(logPath)
					if err == nil && strings.Contains(string(data), "wireguard device up on UDP") {
						break ready
					}
				}
			}
			responses := make(encryptedGuestSink, 32)
			guestTun, err := NewWGTunWithConfig("binary-guest", 1380, responses, DefaultTunConfig())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { guestTun.Close() })
			guest, err := StartDevice(DeviceConfig{PrivateKey: guestPrivate, MTU: 1380,
				Peers: []PeerConfig{{PublicKey: serverPublic, AllowedIPs: []string{"0.0.0.0/0"}, Endpoint: fmt.Sprintf("127.0.0.1:%d", port)}}}, guestTun)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { guest.Close() })
			testEncryptedWireGuardRoundTrip(t, guestTun, responses, fragments)
			select {
			case <-done:
				t.Fatalf("release binary exited during forwarding: %v", processErr)
			default:
			}
		})
	}
}
