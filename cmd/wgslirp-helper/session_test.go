package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/irctrakz/wgslirp/internal/application"
	"github.com/irctrakz/wgslirp/internal/helperwire"
)

// Hold startup after acquiring the fake resource. Real stdin/stdout pipes
// remain active while the operation is held, as in the W1 transcripts.
func TestHelperInterruptedStartup(t *testing.T) {
	const marker = "WGSLIRP_TEST_HELD_START"
	if mode := os.Getenv(marker); mode != "" {
		runHeldStartChild(mode)
		return
	}
	for _, mode := range []string{"eof", "queue_full", "shutdown_timeout"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := execHeldStart(ctx, marker, mode)
			input, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			stderr, err := cmd.StderrPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() {
				cancel()
				if cmd.ProcessState == nil {
					_ = cmd.Wait()
				}
			}()
			p := helperProcess{cmd: cmd, in: input, out: bufio.NewReader(stdout)}
			p.handshake(t)
			p.send(t, p.request(2, "start", fixtureConfig(0)))
			trace := bufio.NewReader(stderr)
			expectTrace(t, trace, "acquired\n")
			if mode == "eof" {
				_ = input.Close()
			} else {
				p.send(t, p.request(3, "status", object{}), p.request(4, "status", object{}))
			}
			expectTrace(t, trace, "cancelled\n")
			if mode != "shutdown_timeout" {
				expectTrace(t, trace, "closed\n")
			}
			exit := 0
			if mode != "eof" {
				diag := p.receive(t)
				if diag["type"] != "session_error" || diag["code"] != mode || diag["instance_id"] != p.instance {
					t.Fatalf("unexpected terminal frame: %v", diag)
				}
				exit = 1
			}
			p.expectEOF(t)
			p.wait(t, exit)
		})
	}
}

func execHeldStart(ctx context.Context, marker, mode string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHelperInterruptedStartup$")
	cmd.Env = append(os.Environ(), marker+"="+mode)
	return cmd
}

func expectTrace(t *testing.T, trace *bufio.Reader, want string) {
	t.Helper()
	if line, err := trace.ReadString('\n'); line != want || err != nil {
		t.Fatalf("trace %q, wanted %q: %v", line, want, err)
	}
}

func runHeldStartChild(mode string) {
	ignoreBrokenPipeSignal()
	out, err := helperwire.NewStdoutOutput()
	if err != nil {
		os.Exit(2)
	}
	start := func(ctx context.Context, _ application.Config, _ application.Observers) (managedRuntime, error) {
		_, _ = io.WriteString(os.Stderr, "acquired\n")
		<-ctx.Done()
		_, _ = io.WriteString(os.Stderr, "cancelled\n")
		// Hand the worker its resources even after cancellation. It must
		// release them and suppress readiness and all queued replies.
		return &heldRuntime{stuck: mode == "shutdown_timeout"}, nil
	}
	os.Exit(serve(os.Stdin, out, controller{start: start, diagnostics: io.Discard}, time.Second))
}

type heldRuntime struct{ stuck bool }

func (*heldRuntime) Status() (application.Status, error) { panic("published cancelled startup") }
func (*heldRuntime) AddPeer(string, netip.Addr) error    { panic("admitted after cancellation") }
func (*heldRuntime) RemovePeer(string) error             { panic("admitted after cancellation") }
func (r *heldRuntime) Close() error {
	if r.stuck {
		<-make(chan struct{})
	}
	_, _ = io.WriteString(os.Stderr, "closed\n")
	return nil
}

func TestStartupReason(t *testing.T) {
	if got := startupReason(errors.New("address already in use")); got != "other" {
		t.Fatalf("classified text as a platform error: %s", got)
	}
}

func TestSessionRejectsUnnegotiatedConfig(t *testing.T) {
	p := launchHelper(t, false)
	p.send(t, object{"id": 1, "op": "start", "params": fixtureConfig(0)})
	if msg := p.receive(t); msg["code"] != "invalid_frame" || msg["type"] != "session_error" {
		t.Fatalf("unexpected first-frame rejection: %v", msg)
	}
	p.wait(t, 1)
	p.expectEOF(t)
}
