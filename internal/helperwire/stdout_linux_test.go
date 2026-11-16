package helperwire

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const queueFullDiagnostic = `{"type":"session_error","code":"queue_full"}`

// The production raw write callback returns false only after unix.Write
// returns EAGAIN. Observe that result while leaving polling to the real fd.
type observedRawWrite struct {
	syscall.RawConn
	wouldBlock func()
}

func (w observedRawWrite) Write(write func(uintptr) bool) error {
	return w.RawConn.Write(func(fd uintptr) bool {
		ready := write(fd)
		if !ready {
			w.wouldBlock()
		}
		return ready
	})
}

func TestInheritedStdoutDiagnosticAfterEAGAIN(t *testing.T) {
	const marker = "WGSLIRP_TEST_STDOUT_EAGAIN"
	if os.Getenv(marker) == "1" {
		testStdoutDiagnosticChild(t)
		os.Exit(0)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestInheritedStdoutDiagnosticAfterEAGAIN$")
	defer func() {
		cancel()
		if cmd.Process != nil && cmd.ProcessState == nil {
			_ = cmd.Wait()
		}
	}()
	cmd.Env = append(os.Environ(), marker+"=1")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	size, err := unix.FcntlInt(writer.Fd(), unix.F_SETPIPE_SZ, 4096)
	if err != nil {
		t.Fatal(err)
	}
	fill := bytes.Repeat([]byte{'x'}, size)
	if n, err := writer.Write(fill); err != nil || n != len(fill) {
		t.Fatalf("fill stdout: wrote %d bytes (%v)", n, err)
	}
	cmd.Stdout = writer
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	_ = writer.Close()
	if err := reader.SetReadDeadline(time.Now().Add(9 * time.Second)); err != nil {
		t.Fatal(err)
	}

	markers := bufio.NewReader(stderr)
	for _, want := range []string{"stdout EAGAIN\n", "response cancelled\n"} {
		if got, err := markers.ReadString('\n'); err != nil || got != want {
			t.Fatalf("expected %q, got %q (%v)", want, got, err)
		}
		if want == "stdout EAGAIN\n" {
			// Keep stdout full until the cancelled write has returned.
			if _, err := stdin.Write([]byte{1}); err != nil {
				t.Fatal(err)
			}
		}
	}
	prefix := make([]byte, len(fill))
	if _, err := io.ReadFull(reader, prefix); err != nil || !bytes.Equal(prefix, fill) {
		t.Fatalf("prefilled stdout changed: %v", err)
	}
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(reader); err != nil || string(got) != queueFullDiagnostic+"\n" {
		t.Fatalf("stdout after cancellation = %q (%v)", got, err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
}

func testStdoutDiagnosticChild(t *testing.T) {
	out, err := NewStdoutOutput()
	if err != nil {
		t.Fatal(err)
	}
	writer := out.writer.(*stdoutWriter)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cancellationRead := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(os.Stdin, make([]byte, 1))
		cancellationRead <- err
		cancel()
	}()
	raw := writer.raw
	writer.raw = observedRawWrite{RawConn: raw, wouldBlock: func() {
		fmt.Fprintln(os.Stderr, "stdout EAGAIN")
	}}
	if err := out.WriteFrame(ctx, []byte("{}")); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected zero-byte cancellation, got %v", err)
	}
	if err := <-cancellationRead; err != nil {
		t.Fatal(err)
	}
	writer.raw = raw
	fmt.Fprintln(os.Stderr, "response cancelled")
	if _, err := io.ReadAll(os.Stdin); err != nil {
		t.Fatal(err)
	}
	if err := out.WriteFrame(context.Background(), []byte(queueFullDiagnostic)); err != nil {
		t.Fatal(err)
	}
}
