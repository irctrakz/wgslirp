//go:build integration && releaseimage && linux

package wireguard

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This fixture controls Docker on a disposable runner; the tested application
// receives neither the Docker socket nor privileges. Select it explicitly.
func TestReleaseImage(t *testing.T) {
	t.Run("default", func(t *testing.T) { testReleaseImage(t, true) })
	t.Run("disabled", func(t *testing.T) { testReleaseImage(t, false) })
}

func testReleaseImage(t *testing.T, reassembly bool) {
	image := os.Getenv("WGSLIRP_RELEASE_IMAGE")
	if image == "" {
		t.Skip("set WGSLIRP_RELEASE_IMAGE to an already-built release image")
	}
	run := os.Getenv("WGSLIRP_RELEASE_RUN")
	if run == "" || strings.Trim(run, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-") != "" {
		t.Fatal("a dedicated alphanumeric WGSLIRP_RELEASE_RUN is required")
	}
	name := "wgslirp-release-" + run
	if !reassembly {
		name += "-disabled"
	}
	label := "wgslirp.release.run=" + run
	docker := func(args ...string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("docker %s: %w: %s", args[0], err, out)
		}
		return strings.TrimSpace(string(out)), nil
	}
	mustDocker := func(args ...string) string {
		t.Helper()
		out, err := docker(args...)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	report := map[string]any{"image": image, "source_commit": os.Getenv("WGSLIRP_RELEASE_COMMIT"), "run": run, "ipv4_reassembly": reassembly}
	report["reassembly_environment"] = "unset"
	report["pooling_environment"] = "unset"
	report["icmp_echo_environment"] = "unset"
	if !reassembly {
		report["reassembly_environment"] = "false"
		report["pooling_environment"] = "false"
		report["icmp_echo_environment"] = "false"
	}
	t.Cleanup(func() {
		report["passed"] = !t.Failed()
		if dir := os.Getenv("WGSLIRP_RELEASE_REPORT"); dir != "" {
			data, err := json.MarshalIndent(report, "", "  ")
			if err == nil {
				file := "runtime-default.json"
				if !reassembly {
					file = "runtime-disabled.json"
				}
				err = os.WriteFile(filepath.Join(dir, file), data, 0600)
			}
			if err != nil {
				t.Error(err)
			}
		}
	})
	mustDocker("network", "create", "--internal", "--label", label, name)
	t.Cleanup(func() {
		if _, err := docker("network", "rm", name); err != nil {
			t.Error(err)
		}
	})
	gateway := net.ParseIP(mustDocker("network", "inspect", "--format", "{{(index .IPAM.Config 0).Gateway}}", name)).To4()
	if gateway == nil {
		t.Fatal("missing dedicated network IPv4 gateway")
	}
	serverPrivate, serverPublic := encryptedKey(t)
	guestPrivate, guestPublic := encryptedKey(t)
	config := strings.Join([]string{"WG_PRIVATE_KEY=" + serverPrivate, "WG_LISTEN_PORT=51820", "WG_MTU=1380",
		"METRICS_INTERVAL=50ms", "METRICS_FORMAT=text", "PRINT_CONFIG=true",
		"WG_PEER_0_PUBLIC_KEY=" + guestPublic, "WG_PEER_0_ALLOWED_IPS=10.0.0.2/32"}, "\n") + "\n"
	if !reassembly {
		config += "IPV4_REASSEMBLY=false\nPOOLING=false\nICMP_ECHO=false\n"
	}
	envFile := filepath.Join(t.TempDir(), "device.env")
	if err := os.WriteFile(envFile, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	createArgs := []string{"create", "--name", name, "--label", label, "--network", name,
		"--env-file", envFile,
		"--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
		"--cpus=1", "--memory=256m", "--memory-swap=256m", "--pids-limit=128",
		"--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m", "--restart=no",
		"--log-driver=json-file", "--log-opt=max-size=1m", "--log-opt=max-file=1", image}
	if reassembly {
		// Deliberately deny ping sockets for the non-root image. This must fail
		// actionably rather than fall back to raw ICMP or fabricate replies.
		deniedName := name + "-echo-denied"
		deniedArgs := append([]string(nil), createArgs[:len(createArgs)-1]...)
		deniedArgs[2] = deniedName
		deniedArgs = append(deniedArgs, "--sysctl", "net.ipv4.ping_group_range=0 0", image)
		mustDocker(deniedArgs...)
		removed := false
		t.Cleanup(func() {
			if !removed {
				if _, err := docker("rm", "-f", deniedName); err != nil {
					t.Error(err)
				}
			}
		})
		mustDocker("start", deniedName)
		if code := mustDocker("wait", deniedName); code == "0" {
			t.Fatal("ping-denied image incorrectly started successfully")
		}
		logs := mustDocker("logs", deniedName)
		if !strings.Contains(logs, "ICMP_ECHO") || !strings.Contains(logs, "ping_group_range") || !strings.Contains(logs, "ICMP_ECHO=false") {
			t.Fatal("ping-denied startup did not provide actionable diagnostics")
		}
		mustDocker("rm", deniedName)
		removed = true
		report["icmp_echo_denied_startup_verified"] = true
	}
	if !reassembly {
		// The escape hatch must start and forward even when ping sockets are denied.
		createArgs = append(createArgs[:len(createArgs)-1], "--sysctl", "net.ipv4.ping_group_range=0 0", image)
	}
	mustDocker(createArgs...)
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := docker("logs", "--tail", "30", name)
			t.Log(out)
		}
		if _, err := docker("rm", "-f", name); err != nil {
			t.Error(err)
		}
	})
	// Decode only nonsensitive fields; never persist inspect's environment/keys.
	type inspection struct {
		Image  string
		Config struct{ User string }
		State  struct {
			Running, OOMKilled bool
			ExitCode           int
		}
		HostConfig struct {
			Memory, MemorySwap, NanoCpus, PidsLimit int64
			ReadonlyRootfs                          bool
			CapDrop, SecurityOpt                    []string
		}
	}
	inspect := func() inspection {
		t.Helper()
		var result []inspection
		if err := json.Unmarshal([]byte(mustDocker("inspect", name)), &result); err != nil || len(result) != 1 {
			t.Fatal("invalid container inspection", err)
		}
		return result[0]
	}
	mustDocker("start", name)
	i := inspect()
	if !i.State.Running || i.Config.User == "" || i.Config.User == "root" || i.Config.User == "0" ||
		i.HostConfig.Memory != 256<<20 || i.HostConfig.MemorySwap != 256<<20 || i.HostConfig.NanoCpus != 1e9 ||
		i.HostConfig.PidsLimit != 128 || !i.HostConfig.ReadonlyRootfs ||
		strings.Join(i.HostConfig.CapDrop, ",") != "ALL" || !strings.Contains(strings.Join(i.HostConfig.SecurityOpt, ","), "no-new-privileges") {
		t.Fatalf("runtime restrictions not applied: %+v", i)
	}
	report["initial"] = i
	uid := mustDocker("exec", name, "id", "-u")
	if uid == "0" {
		t.Fatal("container process is root")
	}
	status := mustDocker("exec", name, "cat", "/proc/1/status")
	if !strings.Contains(status, "CapEff:\t0000000000000000") || !strings.Contains(status, "NoNewPrivs:\t1") {
		t.Fatal("PID 1 capabilities or no-new-privileges mismatch")
	}
	report["uid"] = uid
	report["ping_group_range"] = mustDocker("exec", name, "cat", "/proc/sys/net/ipv4/ping_group_range")
	for file, want := range map[string]string{"memory.max": "268435456", "memory.swap.max": "0", "pids.max": "128", "cpu.max": "100000 100000"} {
		if got := mustDocker("exec", name, "cat", "/sys/fs/cgroup/"+file); got != want {
			t.Fatalf("cgroup %s=%q, want %q", file, got, want)
		}
	}
	serverIP := mustDocker("inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name)
	if net.ParseIP(serverIP).To4() == nil {
		t.Fatal("missing container IPv4 address")
	}
	endpoint := net.JoinHostPort(serverIP, "51820")
	responses := make(encryptedGuestSink, 32)
	guestTun, err := NewWGTunWithConfig("release-guest", 1380, responses, DefaultTunConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { guestTun.Close() })
	guest, err := StartDevice(DeviceConfig{PrivateKey: guestPrivate, MTU: 1380,
		Peers: []PeerConfig{{PublicKey: serverPublic, AllowedIPs: []string{"0.0.0.0/0"}, Endpoint: endpoint}}}, guestTun)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { guest.Close() })
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udp.Close() })
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	fragmentTraffic := reassembly
	var datagramID uint16
	send := func(proto byte, dstPort uint16, seq, ack uint32, flags byte, payload []byte) error {
		p := encryptedPacket(proto, dstPort, seq, ack, flags, payload)
		copy(p[16:20], gateway)
		p[10], p[11] = 0, 0
		binary.BigEndian.PutUint16(p[10:12], encryptedChecksum(p[:20]))
		offset := 26
		if proto == 6 {
			offset = 36
		}
		p[offset], p[offset+1] = 0, 0
		pseudo := append([]byte(nil), p[12:20]...)
		pseudo = append(pseudo, 0, proto, byte((len(p)-20)>>8), byte(len(p)-20))
		pseudo = append(pseudo, p[20:]...)
		checksum := encryptedChecksum(pseudo)
		if proto == 17 && checksum == 0 {
			checksum = 0xffff
		}
		binary.BigEndian.PutUint16(p[offset:offset+2], checksum)
		if fragmentTraffic {
			datagramID++
			for _, fragment := range encryptedFragments(p, datagramID, 16) {
				if err := guestTun.InjectToPeer(fragment); err != nil {
					return err
				}
			}
			return nil
		}
		return guestTun.InjectToPeer(p)
	}
	receive := func(proto byte) ([]byte, error) {
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		for {
			select {
			case p := <-responses:
				if len(p) >= 28 && p[9] == proto {
					return p, nil
				}
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-timer.C:
				return nil, fmt.Errorf("encrypted reply deadline")
			}
		}
	}
	// Send an actual encrypted guest echo to the runner's network gateway.
	// The kernel response is independent of the userspace synthesis code.
	echoPayload := []byte("wgslirp-release-echo")
	echo := make([]byte, 28+len(echoPayload))
	echo[0], echo[8], echo[9] = 0x45, 64, 1
	binary.BigEndian.PutUint16(echo[2:4], uint16(len(echo)))
	copy(echo[12:16], net.IPv4(10, 0, 0, 2).To4())
	copy(echo[16:20], gateway)
	echo[20] = 8
	binary.BigEndian.PutUint16(echo[24:26], 0x1234)
	binary.BigEndian.PutUint16(echo[26:28], 7)
	copy(echo[28:], echoPayload)
	binary.BigEndian.PutUint16(echo[22:24], encryptedChecksum(echo[20:]))
	binary.BigEndian.PutUint16(echo[10:12], encryptedChecksum(echo[:20]))
	if err := guestTun.InjectToPeer(echo); err != nil {
		t.Fatal(err)
	}
	if reassembly {
		reply, err := receive(1)
		if err != nil || len(reply) != len(echo) || reply[20] != 0 || reply[21] != 0 ||
			!bytes.Equal(reply[12:16], gateway) || !bytes.Equal(reply[16:20], echo[12:16]) ||
			!bytes.Equal(reply[24:], echo[24:]) || encryptedChecksum(reply[:20]) != 0 || encryptedChecksum(reply[20:]) != 0 {
			t.Fatal("encrypted ICMP echo mismatch", err)
		}
		report["verified_icmp_echo_rounds"] = 1
	} else {
		select {
		case reply := <-responses:
			t.Fatalf("disabled echo unexpectedly returned protocol %d", reply[9])
		case <-time.After(time.Second):
		}
		report["icmp_echo_disabled_verified"] = true
	}
	listener.SetDeadline(time.Now().Add(10 * time.Second))
	if err := send(6, port, 100, 0, 2, nil); err != nil {
		t.Fatal(err)
	}
	conn, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	syn, err := receive(6)
	if err != nil || len(syn) < 40 || syn[33]&0x12 != 0x12 {
		t.Fatal("missing SYN ACK", err)
	}
	seq, ack := uint32(101), binary.BigEndian.Uint32(syn[24:28])+1
	if err := send(6, port, seq, ack, 0x10, nil); err != nil {
		t.Fatal(err)
	}
	exchange := func(round int) error {
		payload := bytes.Repeat([]byte{byte(round)}, 1024)
		udp.SetDeadline(time.Now().Add(5 * time.Second))
		if err := send(17, uint16(udp.LocalAddr().(*net.UDPAddr).Port), 0, 0, 0, payload); err != nil {
			return err
		}
		var buf [1024]byte
		n, from, err := udp.ReadFromUDP(buf[:])
		if err != nil {
			return err
		}
		if !bytes.Equal(buf[:n], payload) {
			return fmt.Errorf("UDP host mismatch")
		}
		if _, err := udp.WriteToUDP(buf[:n], from); err != nil {
			return err
		}
		p, err := receive(17)
		if err != nil {
			return err
		}
		if !bytes.Equal(p[28:], payload) {
			return fmt.Errorf("UDP guest mismatch")
		}
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		if err := send(6, port, seq, ack, 0x18, payload); err != nil {
			return err
		}
		seq += uint32(len(payload))
		// A full request must arrive at the host before echoing it.
		for used := 0; used < len(buf); {
			n, err := conn.Read(buf[used:])
			if err != nil {
				return err
			}
			used += n
		}
		if !bytes.Equal(buf[:], payload) {
			return fmt.Errorf("TCP host mismatch")
		}
		if _, err := conn.Write(payload); err != nil {
			return err
		}
		var got []byte
		for attempts := 0; attempts < 32 && len(got) < len(payload); attempts++ {
			p, err := receive(6)
			if err != nil {
				return err
			}
			if len(p) < 40 || p[33]&4 != 0 {
				return fmt.Errorf("invalid TCP reply")
			}
			h := 20 + int(p[32]>>4)*4
			if h > len(p) {
				return fmt.Errorf("invalid TCP header")
			}
			if binary.BigEndian.Uint32(p[24:28]) == ack {
				got = append(got, p[h:]...)
				ack += uint32(len(p) - h)
			}
			if err := send(6, port, seq, ack, 0x10, nil); err != nil {
				return err
			}
		}
		if !bytes.Equal(got, payload) {
			return fmt.Errorf("TCP guest mismatch")
		}
		return nil
	}
	for round := 0; round < 8; round++ {
		if err := exchange(round); err != nil {
			t.Fatal(err)
		}
	}
	report["verified_tcp_udp_rounds"] = 8
	// Capture startup evidence before the expiry workload can rotate bounded logs.
	// Verify the image's effective policy, not just the fixture's intended inputs.
	var policies []struct {
		Pool   struct{ Enabled bool }
		Socket struct{ ICMPEcho bool }
	}
	for _, line := range strings.Split(mustDocker("logs", name), "\n") {
		const marker = "effective configuration: "
		if _, summary, found := strings.Cut(line, marker); found {
			var policy struct {
				Pool   struct{ Enabled bool }
				Socket struct{ ICMPEcho bool }
			}
			if err := json.Unmarshal([]byte(summary), &policy); err != nil {
				t.Fatal("invalid effective configuration", err)
			}
			policies = append(policies, policy)
		}
	}
	if len(policies) != 1 || policies[0].Pool.Enabled != reassembly || policies[0].Socket.ICMPEcho != reassembly {
		t.Fatal("release image pooling/echo policy mismatch")
	}
	report["pooling"] = policies[0].Pool.Enabled
	report["icmp_echo"] = policies[0].Socket.ICMPEcho
	// Exercise the actual wireguard-go error callback with a bounded encrypted
	// fragment burst. Explicit disabled mode rejects fragments; default mode rejects a
	// conflicting overlap and disposes its assembly. Later traffic must progress.
	for fragment := 0; fragment < 16; fragment++ {
		p := encryptedPacket(17, uint16(udp.LocalAddr().(*net.UDPAddr).Port), 0, 0, 0, make([]byte, 8))
		copy(p[16:20], gateway)
		binary.BigEndian.PutUint16(p[6:8], 0x2000) // more fragments
		binary.BigEndian.PutUint16(p[4:6], uint16(1000+fragment))
		p[10], p[11] = 0, 0
		binary.BigEndian.PutUint16(p[10:12], encryptedChecksum(p[:20]))
		if err := guestTun.InjectToPeer(p); err != nil {
			t.Fatal(err)
		}
		if reassembly {
			conflict := append([]byte(nil), p...)
			conflict[20] ^= 1
			if err := guestTun.InjectToPeer(conflict); err != nil {
				t.Fatal(err)
			}
		}
		// Injection is not a processing acknowledgement. WireGuard may batch
		// packets. Wait for this rejection before injecting the next packet, so
		// this fixture
		// produces exactly sixteen distinct error callbacks without changing
		// production packet/error handling.
		deadline := time.Now().Add(5 * time.Second)
		for {
			observed := 0
			for _, line := range strings.Split(mustDocker("logs", name), "\n") {
				if !strings.Contains(line, "metrics: ts=") {
					continue
				}
				for _, field := range strings.Fields(line) {
					if strings.HasPrefix(field, "err=") {
						count, err := strconv.Atoi(strings.TrimPrefix(field, "err="))
						if err != nil {
							t.Fatal("invalid error counter")
						}
						observed = count
						break
					}
				}
			}
			if observed > fragment+1 {
				t.Fatal("unexpected packet errors during fragment fixture")
			}
			if observed == fragment+1 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("fragment rejection counter deadline")
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	if reassembly {
		fragmentTraffic = false
		// Eight incomplete datagrams fill the per-source quota. Thirty-two more
		// cannot allocate storage. Ordinary TCP/UDP must continue throughout the
		// fixed 60-second lifetime, and expiry must restore fragment admission.
		for id := 2000; id < 2040; id++ {
			p := encryptedFragments(encryptedPacket(17, uint16(udp.LocalAddr().(*net.UDPAddr).Port), 0, 0, 0, make([]byte, 8)), uint16(id), 8)[0]
			copy(p[16:20], gateway)
			p[10], p[11] = 0, 0
			binary.BigEndian.PutUint16(p[10:12], encryptedChecksum(p[:20]))
			if err := guestTun.InjectToPeer(p); err != nil {
				t.Fatal(err)
			}
		}
		fragmentMetric := func(key string) uint64 {
			var value uint64
			for _, line := range strings.Split(mustDocker("logs", name), "\n") {
				if !strings.Contains(line, "ipv4_fragments:") {
					continue
				}
				for _, field := range strings.Fields(line) {
					if text, ok := strings.CutPrefix(field, key+"="); ok {
						text = strings.Trim(text, "\"")
						parsed, err := strconv.ParseUint(text, 10, 64)
						if err != nil {
							t.Fatal("invalid fragment metric", field)
						}
						value = parsed
					}
				}
			}
			return value
		}
		deadline := time.Now().Add(5 * time.Second)
		for fragmentMetric("rejected") < 48 {
			if time.Now().After(deadline) {
				t.Fatal("fragment flood admission deadline")
			}
			time.Sleep(20 * time.Millisecond)
		}
		if fragmentMetric("cached") != 8 || fragmentMetric("reserved_bytes") != 8*(65535+4096) {
			t.Fatal("fragment flood containment mismatch")
		}
		report["flood_cached"] = 8
		report["flood_reserved_bytes"] = 8 * (65535 + 4096)
		deadline = time.Now().Add(65 * time.Second)
		ordinaryRounds := 0
		for fragmentMetric("expired") < 8 {
			if time.Now().After(deadline) {
				t.Fatal("fragment expiry deadline")
			}
			if err := exchange(100); err != nil {
				t.Fatal("ordinary traffic during fragment exhaustion", err)
			}
			ordinaryRounds++
			time.Sleep(250 * time.Millisecond)
		}
		deadline = time.Now().Add(5 * time.Second)
		for fragmentMetric("reserved_bytes") != 0 {
			if time.Now().After(deadline) {
				t.Fatal("expiry retained fragment storage")
			}
			time.Sleep(20 * time.Millisecond)
		}
		report["ordinary_rounds_during_exhaustion"] = ordinaryRounds
		report["expired_datagrams"] = 8
		fragmentTraffic = true
		if err := exchange(101); err != nil {
			t.Fatal("fragment admission after expiry", err)
		}
		t.Log("RELEASE_IMAGE_FRAGMENT_REASSEMBLY_OK flood=40 cached=8 expired=8 restored=true")
	}
	for _, file := range []string{"memory.events", "pids.events"} {
		value := mustDocker("exec", name, "cat", "/sys/fs/cgroup/"+file)
		report[file] = value
		fields := strings.Fields(value)
		if len(fields) == 0 || len(fields)%2 != 0 {
			t.Fatalf("invalid %s", file)
		}
		for index := 1; index < len(fields); index += 2 {
			if fields[index] != "0" {
				t.Fatalf("resource event in %s: %s", file, value)
			}
		}
	}
	report["memory_peak_after_eight_rounds"] = mustDocker("exec", name, "cat", "/sys/fs/cgroup/memory.peak")
	ready, done := make(chan struct{}), make(chan error, 1)
	go func() {
		for round := 8; round < 256; round++ {
			if err := exchange(round); err != nil {
				done <- err
				return
			}
			if round == 8 {
				close(ready)
			}
			time.Sleep(10 * time.Millisecond)
		}
		done <- fmt.Errorf("traffic exhausted before termination")
	}()
	// Always join traffic before closing its peer device and test resources.
	t.Cleanup(func() { cancel(); udp.Close(); conn.Close(); <-done })
	select {
	case <-ready:
	case err := <-done:
		done <- err
		t.Fatal("traffic stopped before SIGTERM", err)
	case <-time.After(10 * time.Second):
		t.Fatal("traffic start deadline")
	}
	start := time.Now()
	select {
	case err := <-done:
		done <- err
		t.Fatal("traffic stopped before SIGTERM", err)
	default:
	}
	mustDocker("kill", "--signal=TERM", name)
	code := mustDocker("wait", name)
	shutdownDuration := time.Since(start)
	if code != strconv.Itoa(0) || shutdownDuration > 10*time.Second {
		t.Fatalf("SIGTERM exit=%s duration=%s", code, shutdownDuration)
	}
	i = inspect()
	if i.State.Running || i.State.OOMKilled || i.State.ExitCode != 0 {
		t.Fatalf("unclean termination: %+v", i.State)
	}
	report["final"] = i
	report["sigterm_ms"] = shutdownDuration.Milliseconds()
	logs := mustDocker("logs", name)
	if !reassembly {
		if strings.Count(logs, "incoming IPv4 fragments are unsupported") != 1 ||
			strings.Count(logs, "Repeated TUN packet failures: reason=unsupported_ipv4_fragment suppressed=15") != 1 {
			t.Fatal("fragment burst must log one immediate failure and one shutdown summary of 15 repeats")
		}
		report["fragment_log_burst"] = map[string]int{"failures": 16, "immediate": 1, "suppressed": 15}
		t.Log("RELEASE_IMAGE_FRAGMENT_LOG_OK failures=16 immediate=1 suppressed=15")
	}
	t.Logf("RELEASE_IMAGE_OK image=%s uid=%s rounds>=9 sigterm=%s", i.Image, uid, shutdownDuration)
}
