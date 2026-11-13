package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

const (
	fixturePrivate = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo="
	fixturePublic  = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo="
	fixturePeer    = "3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08="
)

func fixtureConfig(port int) object {
	return object{
		"private_key": fixturePrivate, "listen_port": port, "peers": []object{},
		"mappings": []object{{"guest_ip": "10.77.0.1", "guest_port": 8096, "host_ip": "127.0.0.1", "host_port": 8096}},
	}
}

type helperProcess struct {
	cmd      *exec.Cmd
	in       io.WriteCloser
	out      *bufio.Reader
	instance string
}

func helperCommand(ctx context.Context, args ...string) *exec.Cmd {
	if path := os.Getenv("WGSLIRP_HELPER_TEST_BINARY"); path != "" {
		return exec.CommandContext(ctx, path, args...)
	}
	cmd := exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=^TestHelperProcessEntry$", "--"}, args...)...)
	cmd.Env = append(os.Environ(), "WGSLIRP_TEST_PROCESS=1")
	return cmd
}

func TestHelperProcessEntry(t *testing.T) {
	if os.Getenv("WGSLIRP_TEST_PROCESS") == "1" {
		os.Exit(runMain(os.Args[3:]))
	}
}

func launchHelper(t *testing.T, closeStdout bool) *helperProcess {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	cmd := helperCommand(ctx)
	t.Cleanup(func() {
		cancel()
		if cmd.Process != nil && cmd.ProcessState == nil {
			_ = cmd.Wait()
		}
	})
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = out.Close(); _ = writer.Close() })
	cmd.Stdout = writer
	if closeStdout {
		_ = out.Close()
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	_ = writer.Close()
	return &helperProcess{cmd: cmd, in: input, out: bufio.NewReader(out)}
}

func (p *helperProcess) send(t *testing.T, frames ...object) {
	t.Helper()
	var lines strings.Builder
	for _, frame := range frames {
		if err := json.NewEncoder(&lines).Encode(frame); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := io.WriteString(p.in, lines.String()); err != nil {
		t.Fatal(err)
	}
}

func (p *helperProcess) receive(t *testing.T) object {
	t.Helper()
	line, err := p.out.ReadBytes('\n')
	if err != nil {
		t.Fatalf("read response %q: %v", line, err)
	}
	var msg object
	if err := json.Unmarshal(line, &msg); err != nil {
		t.Fatalf("invalid stdout frame %q: %v", line, err)
	}
	return msg
}

func (p *helperProcess) request(id int, op string, params any) object {
	return object{"id": id, "op": op, "instance_id": p.instance, "params": params}
}

func hello(versions ...int) object {
	return object{"id": 1, "op": "hello", "params": object{"versions": versions}}
}

func (p *helperProcess) handshake(t *testing.T) {
	t.Helper()
	p.send(t, hello(2, 1))
	msg := p.receive(t)
	p.instance, _ = msg["instance_id"].(string)
	if !instancePattern.MatchString(p.instance) {
		t.Fatalf("invalid instance ID: %v", msg)
	}
	result := p.check(t, msg, 1, "hello", 0, "")
	if result["version"] != float64(1) || result["binary_version"] != binaryVersion() ||
		result["os"] != runtime.GOOS || result["arch"] != runtime.GOARCH ||
		fmt.Sprint(result["capabilities"]) != "[restricted_tcp live_peers]" {
		t.Fatalf("unexpected hello: %v", msg)
	}
}

func (p *helperProcess) check(t *testing.T, msg object, id int, op string, revision int, code string) object {
	t.Helper()
	result, hasResult := msg["result"].(object)
	failure, hasError := msg["error"].(object)
	if len(msg) != 6 || msg["id"] != float64(id) || msg["op"] != op ||
		msg["revision"] != float64(revision) || msg["instance_id"] != p.instance ||
		msg["ok"] != (code == "") || hasResult != (code == "") || hasError != (code != "") ||
		(hasError && failure["code"] != code) {
		t.Fatalf("response to %d/%s, wanted revision %d and error %q, got %v", id, op, revision, code, msg)
	}
	return result
}

func (p *helperProcess) roundTrip(t *testing.T, id int, op string, params any, revision int, code string) object {
	t.Helper()
	p.send(t, p.request(id, op, params))
	return p.check(t, p.receive(t), id, op, revision, code)
}

func (p *helperProcess) wait(t *testing.T, code int) {
	t.Helper()
	err := p.cmd.Wait()
	if p.cmd.ProcessState == nil || p.cmd.ProcessState.ExitCode() != code {
		t.Fatalf("expected exit %d, got %v", code, err)
	}
}

func (p *helperProcess) expectEOF(t *testing.T) {
	t.Helper()
	if tail, err := io.ReadAll(p.out); err != nil || len(tail) != 0 {
		t.Fatalf("extra output after shutdown %q: %v", tail, err)
	}
}

func TestHelperProcessLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if out, err := helperCommand(ctx, "--version").Output(); err != nil || strings.TrimSpace(string(out)) != binaryVersion() {
		t.Fatalf("version = %q, %v", out, err)
	}
	p := launchHelper(t, false)
	p.handshake(t)
	idle := p.roundTrip(t, 2, "status", object{}, 0, "")
	if idle["state"] != "idle" || idle["listen_port"] != nil || idle["server_public_key"] != nil ||
		idle["metrics"] != nil || idle["uptime_ms"] != float64(0) || fmt.Sprint(idle["peers"]) != "[]" {
		t.Fatalf("unexpected idle status: %v", idle)
	}
	cfg := fixtureConfig(0)
	p.roundTrip(t, 3, "validate", cfg, 0, "")
	add := object{"expected_revision": 0, "peer": object{"public_key": fixturePeer, "address": "10.77.0.2"}}
	p.roundTrip(t, 4, "peer_add", add, 0, "invalid_state")
	start := p.roundTrip(t, 5, "start", cfg, 1, "")
	port, ok := start["listen_port"].(float64)
	if !ok || port <= 0 || start["server_public_key"] != fixturePublic {
		t.Fatalf("unexpected readiness: %v", start)
	}
	p.roundTrip(t, 6, "start", cfg, 1, "invalid_state")
	p.roundTrip(t, 7, "peer_add", add, 1, "revision_conflict")
	add["expected_revision"] = 1
	p.send(t, p.request(8, "peer_add", add), p.request(9, "status", object{}))
	p.check(t, p.receive(t), 8, "peer_add", 2, "")
	running := p.check(t, p.receive(t), 9, "status", 2, "")
	peers, ok := running["peers"].([]any)
	if !ok || len(peers) != 1 || peers[0].(object)["public_key"] != fixturePeer ||
		peers[0].(object)["address"] != "10.77.0.2" || running["listen_port"] != port ||
		running["server_public_key"] != fixturePublic || running["state"] != "running" || running["metrics"] == nil {
		t.Fatalf("unexpected running status: %v", running)
	}
	p.roundTrip(t, 10, "peer_remove", object{"expected_revision": 2, "public_key": fixturePeer}, 3, "")
	add["expected_revision"] = 3
	p.roundTrip(t, 11, "peer_add", add, 3, "peer_conflict")
	removed := p.roundTrip(t, 12, "status", object{}, 3, "")
	if fmt.Sprint(removed["peers"]) != "[]" {
		t.Fatalf("revoked peer in status: %v", removed)
	}
	p.send(t, p.request(13, "stop", object{}), p.request(14, "stop", object{}))
	p.check(t, p.receive(t), 13, "stop", 3, "")
	assertUDPReleased(t, int(port))
	p.wait(t, 0)
	p.expectEOF(t)
}

func assertUDPReleased(t *testing.T, port int) {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: port})
	if err != nil {
		t.Fatalf("listener not released: %v", err)
	}
	_ = conn.Close()
}

func TestHelperProcessTerminalPaths(t *testing.T) {
	t.Run("unsupported", func(t *testing.T) {
		p := launchHelper(t, false)
		p.send(t, hello(2))
		msg := p.receive(t)
		p.instance, _ = msg["instance_id"].(string)
		if !instancePattern.MatchString(p.instance) {
			t.Fatalf("invalid instance: %v", msg)
		}
		p.check(t, msg, 1, "hello", 0, "unsupported_version")
		p.wait(t, 1)
		p.expectEOF(t)
	})
	t.Run("malformed", func(t *testing.T) {
		p := launchHelper(t, false)
		p.handshake(t)
		_, err := io.WriteString(p.in, "{\"x\":1,\"x\":2}\n")
		if err != nil {
			t.Fatal(err)
		}
		msg := p.receive(t)
		if msg["type"] != "session_error" || msg["code"] != "invalid_frame" || msg["instance_id"] != p.instance {
			t.Fatalf("unexpected diagnostic: %v", msg)
		}
		p.wait(t, 1)
		p.expectEOF(t)
	})
	t.Run("occupied", func(t *testing.T) {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		p := launchHelper(t, false)
		p.handshake(t)
		cfg := fixtureConfig(conn.LocalAddr().(*net.UDPAddr).Port)
		p.roundTrip(t, 2, "validate", cfg, 0, "")
		p.send(t, p.request(3, "start", cfg))
		msg := p.receive(t)
		p.check(t, msg, 3, "start", 0, "start_failed")
		if msg["error"].(object)["reason"] != "address_in_use" {
			t.Fatalf("unexpected startup error: %v", msg)
		}
		p.wait(t, 1)
		p.expectEOF(t)
	})
	t.Run("stdin-closed", func(t *testing.T) {
		p := launchHelper(t, false)
		p.handshake(t)
		start := p.roundTrip(t, 2, "start", fixtureConfig(0), 1, "")
		_ = p.in.Close()
		p.wait(t, 0)
		p.expectEOF(t)
		assertUDPReleased(t, int(start["listen_port"].(float64)))
	})
	t.Run("broken-stdout", func(t *testing.T) {
		p := launchHelper(t, true)
		p.send(t, hello(1))
		p.wait(t, 1)
	})
}

func TestHelperProcessErrorPrecedence(t *testing.T) {
	p := launchHelper(t, false)
	p.handshake(t)
	bad := p.request(2, "future", nil)
	bad["instance_id"] = strings.Repeat("0", 32)
	p.send(t, bad)
	p.check(t, p.receive(t), 2, "future", 0, "invalid_request")
	p.send(t, object{"id": 2, "op": "status"})
	p.check(t, p.receive(t), 2, "status", 0, "duplicate_id")
	bad["id"], bad["params"] = 3, object{}
	p.send(t, bad)
	p.check(t, p.receive(t), 3, "future", 0, "wrong_instance")
	p.roundTrip(t, 4, "future", object{}, 0, "unknown_operation")
	p.roundTrip(t, 5, "hello", object{"versions": []int{1}}, 0, "invalid_request")
	p.roundTrip(t, 6, "status", object{"extra": true}, 0, "invalid_request")
	cfg := fixtureConfig(0)
	cfg["private_key"] = strings.Repeat("A", 43) + "="
	p.roundTrip(t, 7, "validate", cfg, 0, "invalid_config")
	p.roundTrip(t, 8, "stop", object{}, 0, "")
	p.wait(t, 0)
	p.expectEOF(t)
}
