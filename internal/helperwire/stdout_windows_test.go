package helperwire

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const windowsDiagnostic = "{\"type\":\"session_error\",\"code\":\"invalid_frame\"}\n"

func TestWindowsInheritedStdoutCancellation(t *testing.T) {
	const marker = "WGSLIRP_TEST_WINDOWS_STDOUT"
	if mode := os.Getenv(marker); mode != "" {
		testWindowsStdoutChild(t, mode)
		os.Exit(0)
	}
	for _, mode := range []string{"zero", "prefilled-blocking", "partial", "complete"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestWindowsInheritedStdoutCancellation$")
			defer func() {
				cancel()
				if cmd.Process != nil && cmd.ProcessState == nil {
					_ = cmd.Wait()
				}
			}()
			cmd.Env = append(os.Environ(), marker+"="+mode)
			input, err := cmd.StdinPipe()
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
			reader, writer := os.NewFile(uintptr(read), "stdout reader"), os.NewFile(uintptr(write), "stdout writer")
			defer reader.Close()
			defer writer.Close()
			var filler []byte
			if mode == "zero" || mode == "prefilled-blocking" {
				filler = bytes.Repeat([]byte{'x'}, 4096)
				if mode == "zero" {
					waitMode := uint32(windows.PIPE_NOWAIT)
					if err := windows.SetNamedPipeHandleState(write, &waitMode, nil, nil); err != nil {
						t.Fatal(err)
					}
				}
				var n uint32
				if err := windows.WriteFile(write, filler, &n, nil); err != nil || n != uint32(len(filler)) {
					t.Fatalf("prefill: wrote %d bytes: %v", n, err)
				}
			}
			cmd.Stdout = writer
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			_ = writer.Close()
			trace := bufio.NewReader(stderr)
			line, err := trace.ReadString('\n')
			if line != "attempted\n" || err != nil {
				t.Fatalf("unexpected trace %q: %v", line, err)
			}
			written := peekWindowsPipe(t, read) - len(filler)
			switch mode {
			case "zero", "prefilled-blocking":
				if written != 0 {
					t.Fatalf("full pipe accepted %d bytes", written)
				}
			case "partial":
				if written <= 0 || written >= MaxFrameBytes+1 {
					t.Fatalf("expected a partial frame, wrote %d bytes", written)
				}
			case "complete":
				if written != len("{}\n") {
					t.Fatalf("expected a complete frame, wrote %d bytes", written)
				}
			}
			if _, err := input.Write([]byte{1}); err != nil {
				t.Fatal(err)
			}
			if line, err := trace.ReadString('\n'); line != "returned\n" || err != nil {
				t.Fatalf("write did not return after cancellation: %q (%v)", line, err)
			}
			if len(filler) > 0 {
				prefix := make([]byte, len(filler))
				if _, err := io.ReadFull(reader, prefix); err != nil || !bytes.Equal(prefix, filler) {
					t.Fatalf("prefill changed: %v", err)
				}
			}
			_ = input.Close()
			data, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "zero", "prefilled-blocking":
				if string(data) != windowsDiagnostic {
					t.Fatalf("diagnostic after zero bytes: %q", data)
				}
			case "partial":
				if want := windowsLargePayload()[:written]; string(data) != want {
					t.Fatalf("partial frame changed after cancellation: %d bytes, want %d", len(data), written)
				}
			case "complete":
				if string(data) != "{}\n"+windowsDiagnostic {
					t.Fatalf("diagnostic after LF: %q", data)
				}
			}
			if err := cmd.Wait(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func peekWindowsPipe(t *testing.T, read windows.Handle) int {
	t.Helper()
	// Peek without consuming any capacity or unblocking the child's writer.
	peek := windows.NewLazySystemDLL("kernel32.dll").NewProc("PeekNamedPipe")
	var available uint32
	ok, _, err := peek.Call(uintptr(read), 0, 0, 0, uintptr(unsafe.Pointer(&available)), 0)
	if ok == 0 {
		t.Fatal(err)
	}
	return int(available)
}

func windowsLargePayload() string {
	return "{\"x\":\"" + string(bytes.Repeat([]byte{'x'}, MaxFrameBytes-8)) + "\"}"
}

func testWindowsStdoutChild(t *testing.T, mode string) {
	out, err := NewStdoutOutput()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	payload := "{}"
	if mode == "partial" {
		payload = windowsLargePayload()
	}
	observed := false
	err = out.WriteResponse(ctx, []byte(payload), func(attempt func() bool) {
		complete := attempt()
		if observed {
			return
		}
		observed = true
		// Inspect the actual result of the first native WriteFile call.
		// The wrapper below records it before the write loop can retry.
		if complete != (mode == "complete") {
			t.Fatal("unexpected first write completion")
		}
		_, _ = io.WriteString(os.Stderr, "attempted\n")
		if _, err := io.ReadFull(os.Stdin, make([]byte, 1)); err != nil {
			t.Fatal(err)
		}
		cancel()
	})
	if mode == "complete" {
		if err != nil {
			t.Fatal(err)
		}
	} else if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled write: %v", err)
	}
	if out.Usable() != (mode != "partial") {
		t.Fatal("incorrect stream state after cancellation")
	}
	_, _ = io.WriteString(os.Stderr, "returned\n")
	if _, err := io.ReadAll(os.Stdin); err != nil {
		t.Fatal(err)
	}
	err = out.WriteFrame(context.Background(), []byte(windowsDiagnostic[:len(windowsDiagnostic)-1]))
	if mode == "partial" && !errors.Is(err, ErrOutputClosed) || mode != "partial" && err != nil {
		t.Fatalf("diagnostic after cancellation: %v", err)
	}
}
