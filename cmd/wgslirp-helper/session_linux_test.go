package main

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestHelperProcessUnreadOutput(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := helperCommand(ctx)
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, writer := testPipe(t)
	size, err := unix.FcntlInt(writer.Fd(), unix.F_SETPIPE_SZ, 4096)
	if err != nil {
		t.Fatal(err)
	}
	filler := bytes.Repeat([]byte{'x'}, size)
	if _, err := writer.Write(filler); err != nil {
		t.Fatal(err)
	}
	if err := startHelperOnPipe(cmd, writer); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cancel()
		if cmd.ProcessState == nil {
			_ = cmd.Wait()
		}
	}()
	p := helperProcess{cmd: cmd, in: input}
	start := time.Now()
	p.send(t, hello(1))
	p.wait(t, 1)
	if elapsed := time.Since(start); elapsed < 4*time.Second || elapsed > 12*time.Second {
		t.Fatalf("unread stdout exit took %v", elapsed)
	}
	payload, err := io.ReadAll(out)
	if err != nil || !bytes.Equal(payload, filler) {
		t.Fatalf("blocked stdout changed: got %d bytes, err=%v", len(payload), err)
	}
}

func startHelperOnPipe(cmd *exec.Cmd, writer *os.File) error {
	cmd.Stdout = writer
	defer writer.Close()
	return cmd.Start()
}

func TestHelperProcessParentDisappears(t *testing.T) {
	const marker = "WGSLIRP_TEST_PIPE_OWNER"
	if os.Getenv(marker) == "1" {
		// The test parent handed this process the only remaining stdin writer.
		input := os.NewFile(3, "helper stdin")
		_, err := io.WriteString(input, "{\"id\":1,\"op\":\"hello\",\"params\":{\"versions\":[1]}}\n")
		if err != nil {
			os.Exit(2)
		}
		// Wait for a complete start request from the test parent, then keep
		// the pipe open until killed. Never perform a graceful close.
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			os.Exit(2)
		}
		if _, err := io.WriteString(input, line); err != nil {
			os.Exit(2)
		}
		for {
			time.Sleep(time.Hour)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := helperCommand(ctx)
	input, writer := testPipe(t)
	out, outWriter := testPipe(t)
	cmd.Stdin = input
	if err := startHelperOnPipe(cmd, outWriter); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cancel()
		if cmd.ProcessState == nil {
			_ = cmd.Wait()
		}
	}()
	_ = input.Close()

	owner := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHelperProcessParentDisappears$")
	owner.Env = append(os.Environ(), marker+"=1")
	owner.ExtraFiles = []*os.File{writer}
	ownerInput, err := owner.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if owner.ProcessState == nil {
			_ = owner.Process.Kill()
			_ = owner.Wait()
		}
	}()
	_ = writer.Close()

	p := helperProcess{cmd: cmd, in: ownerInput, out: bufio.NewReader(out)}
	msg := p.receive(t)
	p.instance, _ = msg["instance_id"].(string)
	p.check(t, msg, 1, "hello", 0, "")
	start := p.roundTrip(t, 2, "start", fixtureConfig(0), 1, "")
	if err := owner.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = owner.Wait()
	p.wait(t, 0)
	p.expectEOF(t)
	assertUDPReleased(t, int(start["listen_port"].(float64)))
}
