package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/irctrakz/wgslirp/internal/application"
	"github.com/irctrakz/wgslirp/internal/helperwire"
	"github.com/irctrakz/wgslirp/pkg/logging"
	"golang.org/x/sys/unix"
)

func TestInheritedHelperPipes(t *testing.T) {
	const marker = "WGSLIRP_TEST_INHERITED_PIPES"
	if mode := os.Getenv(marker); mode != "" {
		testInheritedHelperPipesChild(t, mode)
		return
	}
	for _, mode := range []string{"cancel", "timeout", "broken-stdout", "broken-stderr", "full-stderr"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestInheritedHelperPipes$")
			defer func() {
				cancel()
				if cmd.Process != nil && cmd.ProcessState == nil {
					_ = cmd.Wait()
				}
			}()
			cmd.Env = append(os.Environ(), marker+"="+mode)
			stdin, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			out, outWriter := testPipe(t)
			diagnostics, diagWriter := testPipe(t)
			cmd.Stdout, cmd.Stderr = outWriter, diagWriter
			if mode == "broken-stdout" {
				_ = out.Close()
			} else if mode == "broken-stderr" {
				_ = diagnostics.Close()
			} else if mode == "full-stderr" {
				size, err := unix.FcntlInt(diagWriter.Fd(), unix.F_SETPIPE_SZ, 4096)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := diagWriter.Write(bytes.Repeat([]byte{'x'}, size)); err != nil {
					t.Fatal(err)
				}
			} else if _, err := unix.FcntlInt(outWriter.Fd(), unix.F_SETPIPE_SZ, 4096); err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			_ = outWriter.Close()
			_ = diagWriter.Close()
			switch mode {
			case "broken-stdout":
				expectPipeLine(t, bufio.NewReader(diagnostics), "stdout EPIPE handled\n")
			case "broken-stderr", "full-stderr":
				if err := out.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
					t.Fatal(err)
				}
				reader := bufio.NewReader(out)
				expectPipeLine(t, reader, "{}\n")
				expectPipeLine(t, reader, "{\"closed\":true}\n")
			default:
				start := time.Now()
				prefix := make([]byte, 1)
				if _, err := io.ReadFull(out, prefix); err != nil || string(prefix) != "{" {
					t.Fatalf("expected a partial frame, got %q (%v)", prefix, err)
				}
				if mode == "cancel" {
					if _, err := stdin.Write([]byte{1}); err != nil {
						t.Fatal(err)
					}
				}
				expectPipeLine(t, bufio.NewReader(diagnostics), "write retired\n")
				if mode == "timeout" && time.Since(start) < 4*time.Second {
					t.Fatal("write timed out before its five-second budget")
				}
				// Drain while the child is still alive. EOF must come from
				// retiring stdout, and the interrupted frame must lack LF.
				rest, err := io.ReadAll(out)
				if err != nil || bytes.ContainsRune(rest, '\n') || len(rest)+1 >= helperwire.MaxFrameBytes+1 {
					t.Fatalf("interrupted frame continued: %d bytes (%v)", len(rest), err)
				}
			}
			_ = stdin.Close()
			if err := cmd.Wait(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func testPipe(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = r.Close()
		_ = w.Close()
	})
	// Bound reads even if an inherited pipe remains stuck open.
	if err := r.SetReadDeadline(time.Now().Add(12 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return r, w
}

func expectPipeLine(t *testing.T, r *bufio.Reader, want string) {
	t.Helper()
	if got, err := r.ReadString('\n'); err != nil || got != want {
		t.Fatalf("expected %q, got %q (%v)", want, got, err)
	}
}

func testInheritedHelperPipesChild(t *testing.T, mode string) {
	diagnostics := configureDiagnostics()
	stdin := bufio.NewReader(os.Stdin)
	output, err := helperwire.NewStdoutOutput()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	switch mode {
	case "broken-stdout":
		if err := output.WriteFrame(ctx, []byte("{}")); !errors.Is(err, syscall.EPIPE) {
			t.Fatalf("expected EPIPE, got %v", err)
		}
		fmt.Fprintln(os.Stderr, "stdout EPIPE handled")
	case "broken-stderr", "full-stderr":
		logging.SetLevel(logging.DebugLevel)
		log.Print("helper startup diagnostic")
		runtime, err := application.Start(ctx, helperConfig(helperTestConfig(), diagnostics), application.Observers{})
		if err != nil {
			t.Fatal(err)
		}
		if err := output.WriteFrame(ctx, []byte("{}")); err != nil {
			t.Fatal(err)
		}
		if err := runtime.Close(); err != nil {
			t.Fatal(err)
		}
		diagnostics.finish()
		if err := output.WriteFrame(ctx, []byte(`{"closed":true}`)); err != nil {
			t.Fatal(err)
		}
	default:
		want := context.DeadlineExceeded
		if mode == "cancel" {
			cancellable, cancel := context.WithCancel(ctx)
			ctx, want = cancellable, context.Canceled
			go func() {
				_, _ = stdin.ReadByte()
				cancel()
			}()
		}
		frame := []byte(`{"data":"` + strings.Repeat("x", helperwire.MaxFrameBytes-len(`{"data":""}`)) + `"}`)
		if err := output.WriteFrame(ctx, frame); !errors.Is(err, want) {
			t.Fatalf("expected %v, got %v", want, err)
		}
		if err := output.WriteFrame(context.Background(), []byte("{}")); !errors.Is(err, helperwire.ErrOutputClosed) {
			t.Fatalf("retired stdout accepted another frame: %v", err)
		}
		fmt.Fprintln(os.Stderr, "write retired")
	}
	if _, err := stdin.ReadByte(); !errors.Is(err, io.EOF) {
		t.Fatalf("expected parent to close stdin: %v", err)
	}
	if mode != "broken-stderr" && mode != "full-stderr" {
		diagnostics.finish()
	}
	os.Exit(0)
}
