package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/irctrakz/wgslirp/internal/helperwire"
	"golang.org/x/sys/unix"
)

func TestHelperShutdownBudgetWithFullOutputPipes(t *testing.T) {
	const marker = "WGSLIRP_TEST_FULL_SHUTDOWN_PIPES"
	const cleanupBudget = 250 * time.Millisecond
	if os.Getenv(marker) == "1" {
		os.Exit(runFullShutdownChild(cleanupBudget))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHelperShutdownBudgetWithFullOutputPipes$")
	cmd.Env = append(os.Environ(), marker+"=1")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, outWriter := testPipe(t)
	stderr, stderrWriter := testPipe(t)
	ready, readyWriter := testPipe(t)
	fill := func(w *os.File) []byte {
		size, err := unix.FcntlInt(w.Fd(), unix.F_SETPIPE_SZ, 4096)
		if err != nil {
			t.Fatal(err)
		}
		filler := bytes.Repeat([]byte{'x'}, size)
		if _, err := w.Write(filler); err != nil {
			t.Fatal(err)
		}
		return filler
	}
	outFiller, stderrFiller := fill(outWriter), fill(stderrWriter)
	cmd.Stdout, cmd.Stderr = outWriter, stderrWriter
	cmd.ExtraFiles = []*os.File{readyWriter}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cancel()
		if cmd.ProcessState == nil {
			_ = cmd.Wait()
		}
	}()
	_ = outWriter.Close()
	_ = stderrWriter.Close()
	_ = readyWriter.Close()
	if _, err := io.ReadFull(ready, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_ = stdin.Close()
	p := helperProcess{cmd: cmd}
	p.wait(t, 1)
	elapsed := time.Since(start)
	if elapsed < cleanupBudget+terminalWriteTimeout || elapsed > cleanupBudget+terminalWriteTimeout+2*time.Second {
		t.Fatalf("blocked final output exit took %v", elapsed)
	}
	for _, pipe := range []struct {
		read *os.File
		want []byte
	}{{out, outFiller}, {stderr, stderrFiller}} {
		data, err := io.ReadAll(pipe.read)
		if err != nil || !bytes.Equal(data, pipe.want) {
			t.Fatalf("stalled pipe changed: got %d bytes: %v", len(data), err)
		}
	}
}

func runFullShutdownChild(cleanupBudget time.Duration) int {
	diag := configureDiagnostics()
	defer diag.finish()
	_, _ = io.WriteString(diag, "blocked diagnostic\n")
	out, err := helperwire.NewStdoutOutput()
	if err != nil {
		return 2
	}
	ready := os.NewFile(3, "ready")
	_, _ = ready.Write([]byte{1})
	_ = ready.Close()
	// Seed a controller with an active runtime whose Close never returns.
	// The test closes real stdin with both output pipes still full.
	c := controller{runtime: &heldRuntime{stuck: true}, diagnostics: diag}
	return serve(os.Stdin, out, c, cleanupBudget)
}
