package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/irctrakz/wgslirp/internal/helperwire"
	"golang.org/x/sys/windows"
)

func TestWindowsSessionCancelsFullPipeRetry(t *testing.T) {
	const marker = "WGSLIRP_TEST_FULL_PIPE_RETRY"
	if os.Getenv(marker) == "1" {
		os.Exit(runFullPipeRetryChild())
	}
	for _, mode := range []string{"eof", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestWindowsSessionCancelsFullPipeRetry$")
			cmd.Env = append(os.Environ(), marker+"=1")
			defer func() {
				cancel()
				if cmd.Process != nil && cmd.ProcessState == nil {
					_ = cmd.Wait()
				}
			}()
			stdin, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			stderr, err := cmd.StderrPipe()
			if err != nil {
				t.Fatal(err)
			}
			var read, write windows.Handle
			if err := windows.CreatePipe(&read, &write, nil, 4096); err != nil {
				t.Fatal(err)
			}
			reader := os.NewFile(uintptr(read), "stdout reader")
			writer := os.NewFile(uintptr(write), "stdout writer")
			defer reader.Close()
			defer writer.Close()
			pipeMode := uint32(windows.PIPE_NOWAIT)
			if err := windows.SetNamedPipeHandleState(write, &pipeMode, nil, nil); err != nil {
				t.Fatal(err)
			}
			filler := bytes.Repeat([]byte{'x'}, 4096)
			var n uint32
			if err := windows.WriteFile(write, filler, &n, nil); err != nil || int(n) != len(filler) {
				t.Fatalf("prefill: wrote %d bytes: %v", n, err)
			}
			cmd.Stdout = writer
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			_ = writer.Close()

			p := helperProcess{cmd: cmd, in: stdin, out: bufio.NewReader(reader)}
			p.send(t, hello(1))
			trace := bufio.NewReader(stderr)
			expectTrace(t, trace, "retry waiting\n")
			exit := 0
			if mode == "eof" {
				_ = stdin.Close()
			} else {
				exit = 1
				if _, err := io.WriteString(stdin, "{bad}\n"); err != nil {
					t.Fatal(err)
				}
				// This second retry belongs to the terminal diagnostic and
				// proves the interrupted reply has already relinquished stdout.
				expectTrace(t, trace, "retry waiting\n")
			}
			// Drain only after cancellation has completed. For EOF, reaping
			// is the synchronization point because no terminal reply is due.
			if mode == "eof" {
				p.wait(t, exit)
			}
			prefix := make([]byte, len(filler))
			if _, err := io.ReadFull(p.out, prefix); err != nil || !bytes.Equal(prefix, filler) {
				t.Fatalf("prefill changed: %v", err)
			}
			if mode == "malformed" {
				msg := p.receive(t)
				instance, _ := msg["instance_id"].(string)
				if len(msg) != 3 || msg["type"] != "session_error" || msg["code"] != "invalid_frame" ||
					!instancePattern.MatchString(instance) {
					t.Fatalf("unexpected diagnostic: %v", msg)
				}
				p.wait(t, exit)
			}
			p.expectEOF(t)
		})
	}
}

func runFullPipeRetryChild() int {
	first := true
	out, err := helperwire.ObserveWindowsStdoutRetry(func(timer <-chan time.Time) <-chan time.Time {
		if first {
			first = false
			fmt.Fprintln(os.Stderr, "retry waiting")
			// No timer wakeup is possible. The real retry select must
			// take session cancellation to release the response writer.
			return nil
		}
		fmt.Fprintln(os.Stderr, "retry waiting")
		return timer
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	return serve(os.Stdin, out, controller{diagnostics: io.Discard, start: startRuntime}, shutdownTimeout)
}
