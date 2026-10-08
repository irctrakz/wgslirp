//go:build integration && mixed && linux

package wireguard

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/irctrakz/wgslirp/pkg/socket"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	wgtun "golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// The guest owns an independent TCP implementation. Neither side needs a kernel
// TUN, raw sockets, sysctl changes or elevated capabilities.
func mixedTestLink(t *testing.T) (*socket.SocketInterface, *netstack.Net) {
	return mixedTestLinkWithOptions(t, false, nil)
}

func mixedTestLinkWithOptions(t *testing.T, reassembly bool, wrap func(wgtun.Device) wgtun.Device) (*socket.SocketInterface, *netstack.Net) {
	t.Helper()
	serverPrivate, serverPublic := encryptedKey(t)
	guestPrivate, guestPublic := encryptedKey(t)
	cfg := socket.DefaultConfig()
	cfg.Protocol, cfg.MTU = "ip4:tcp", 1380
	cfg.IPv4Reassembly = reassembly
	s := socket.NewSocketInterface(cfg)
	tun, err := NewWGTunWithConfig("mixed-server", 1380, s, DefaultTunConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tun.Close() })
	s.SetPacketProcessor(NewWGPacketProcessor(tun))
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Stop() })
	server, err := StartDevice(DeviceConfig{PrivateKey: serverPrivate, MTU: 1380,
		Peers: []PeerConfig{{PublicKey: guestPublic, AllowedIPs: []string{"10.0.0.2/32"}}}}, tun)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	state, err := server.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	port := 0
	for _, line := range strings.Split(state, "\n") {
		if value, ok := strings.CutPrefix(line, "listen_port="); ok {
			port, err = strconv.Atoi(value)
		}
	}
	if err != nil || port <= 0 {
		t.Fatal("missing WireGuard listen port")
	}
	guestTun, network, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.0.0.2")}, nil, 1380)
	if err != nil {
		t.Fatal(err)
	}
	var guestDevice wgtun.Device = guestTun
	if wrap != nil {
		guestDevice = wrap(guestDevice)
	}
	guest := device.NewDevice(guestDevice, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "[mixed-guest] "))
	t.Cleanup(guest.Close) // Device owns and closes guestTun exactly once.
	private, _ := base64.StdEncoding.DecodeString(guestPrivate)
	public, _ := base64.StdEncoding.DecodeString(serverPublic)
	if err := guest.IpcSet(fmt.Sprintf("private_key=%x\npublic_key=%x\nallowed_ip=0.0.0.0/0\nendpoint=127.0.0.1:%d\n", private, public, port)); err != nil {
		t.Fatal(err)
	}
	if err := guest.Up(); err != nil {
		t.Fatal(err)
	}
	return s, network
}

func TestEncryptedMixed(t *testing.T) {
	baseline := runtime.NumGoroutine()
	if !t.Run("traffic", runEncryptedMixed) {
		return
	}
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > baseline+4 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if runtime.NumGoroutine() > baseline+4 {
		t.Fatal("workers survived cleanup")
	}
	t.Log("MIXED_ACCEPTED short_requests=128 bulk_connections=2 bulk_bytes_each_direction=8388608 udp_round_trips=512")
}

func runEncryptedMixed(t *testing.T) {
	runEncryptedMixedWithLink(t, mixedTestLink)
}

func runEncryptedMixedWithLink(t *testing.T, link func(*testing.T) (*socket.SocketInterface, *netstack.Net)) {
	runEncryptedMixedProfile(t, link, mixedProfile{
		shortRounds: 32, udpRounds: 512, bulkBytes: 4 << 20, bulkRepeats: 1,
		shortPause: 100 * time.Millisecond, udpPause: 20 * time.Millisecond, deadline: 45 * time.Second,
	})
}

type mixedProfile struct {
	shortRounds, udpRounds, bulkBytes, bulkRepeats int
	shortPause, udpPause, deadline                 time.Duration
	sustained                                      bool
}

// Sustained profiles stream a repeated bounded block, and keep short/UDP traffic
// alive until both bulk streams finish. Legacy acceptance retains fixed counts.
func runEncryptedMixedProfile(t *testing.T, link func(*testing.T) (*socket.SocketInterface, *netstack.Net), profile mixedProfile) {
	// Use the container's ordinary IPv4 address: a remote loopback destination
	// would depend on the guest stack's special loopback routing semantics.
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	var host netip.Addr
	for _, a := range addresses {
		p, err := netip.ParsePrefix(a.String())
		if err == nil && p.Addr().Is4() && !p.Addr().IsLoopback() && p.Addr().IsGlobalUnicast() {
			host = p.Addr()
			break
		}
	}
	if !host.IsValid() {
		t.Fatal("bounded container requires a non-loopback IPv4 address")
	}
	s, guest := link(t)
	deadline := time.Now().Add(profile.deadline)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	t.Cleanup(cancel)
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IP(host.AsSlice())})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	if err := listener.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	target := netip.AddrPortFrom(host, uint16(listener.Addr().(*net.TCPAddr).Port))
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IP(host.AsSlice())})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udp.Close() })
	if err := udp.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	udpTarget := netip.AddrPortFrom(host, uint16(udp.LocalAddr().(*net.UDPAddr).Port))

	// Fixed worker/connection counts, finite payloads and a shared deadline keep
	// both the test peer and the production bridge bounded, including on failure.
	var workers sync.WaitGroup
	results := make(chan error, 9) // seven clients, TCP acceptor, UDP responder
	launch := func(f func() error) {
		workers.Add(1)
		go func() { defer workers.Done(); results <- f() }()
	}
	t.Cleanup(func() { cancel(); listener.Close(); udp.Close(); workers.Wait() })
	hostStop := make(chan struct{})
	udpDone, bulkDone := make(chan struct{}), make(chan struct{})
	var bulkRemaining atomic.Int32
	bulkRemaining.Store(2)
	var bulkElapsed atomic.Int64
	var loadStarted time.Time
	var accepted, empty atomic.Uint64
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("MIXED_FAILURE accepted=%d empty=%d metrics=%+v", accepted.Load(), empty.Load(), s.DetailedMetrics())
		}
	})
	launch(func() error {
		var handlers sync.WaitGroup
		defer handlers.Wait()
		limit := make(chan struct{}, 6)
		maxAccepts := 2 * (4*profile.shortRounds + 2)
		errors := make(chan error, maxAccepts)
		// A timed-out fast dial can be accepted before cancellation reaches the
		// host. Its asynchronous replacement is a second socket for one request.
		// Serve until clients finish, with at most two accepts per intended flow.
	acceptLoop:
		for accepted.Load() < uint64(maxAccepts) {
			select {
			case limit <- struct{}{}:
			case <-ctx.Done():
				return ctx.Err()
			}
			c, err := listener.AcceptTCP()
			if err != nil {
				<-limit
				select {
				case <-hostStop:
					break acceptLoop
				default:
					return fmt.Errorf("host accept: %w", err)
				}
			}
			accepted.Add(1)
			handlers.Add(1)
			go func() {
				defer handlers.Done()
				defer func() { <-limit }()
				defer c.Close()
				if err := c.SetDeadline(deadline); err != nil {
					errors <- err
					return
				}
				n, err := io.Copy(c, c)
				if n == 0 {
					empty.Add(1)
				}
				errors <- err
			}()
		}
		select {
		case <-hostStop:
		case <-ctx.Done():
			return fmt.Errorf("host accept limit: %w", ctx.Err())
		}
		handlers.Wait()
		for i := uint64(0); i < accepted.Load(); i++ {
			if err := <-errors; err != nil {
				return fmt.Errorf("host echo: %w", err)
			}
		}
		return nil
	})
	launch(func() error {
		var p [1024]byte
		for i := 0; i < profile.udpRounds; i++ {
			n, from, err := udp.ReadFromUDP(p[:])
			if err != nil {
				select {
				case <-udpDone:
					return nil
				default:
				}
				return err
			}
			if n != len(p) {
				return fmt.Errorf("UDP length: %d", n)
			}
			if _, err := udp.WriteToUDP(p[:n], from); err != nil {
				return err
			}
		}
		return nil
	})
	var mu sync.Mutex
	var handshakes []time.Duration
	var shortLatencies, udpLatencies []time.Duration
	var shortLastStart time.Duration
	transfer := func(payload []byte, repeats int) error {
		started := time.Now()
		c, err := guest.DialContextTCPAddrPort(ctx, target)
		if err != nil {
			return fmt.Errorf("guest dial: %w", err)
		}
		defer c.Close()
		mu.Lock()
		handshakes = append(handshakes, time.Since(started))
		mu.Unlock()
		if err := c.SetDeadline(deadline); err != nil {
			return err
		}
		written := make(chan error, 1)
		go func() {
			var source io.Reader = bytes.NewReader(payload)
			if repeats > 1 {
				source = &mixedRepeatedReader{block: payload, remaining: int64(len(payload)) * int64(repeats)}
			}
			_, err := io.Copy(c, source)
			if err == nil {
				err = c.CloseWrite()
			}
			written <- err
		}()
		// Read concurrently with upload, so the echo service can apply real TCP
		// backpressure without a fixture-induced write/write deadlock.
		var readErr error
		if repeats > 1 {
			readErr = mixedVerifyRepeated(c, payload, repeats)
		} else {
			var got []byte
			got, readErr = io.ReadAll(io.LimitReader(c, int64(len(payload)+1)))
			if readErr == nil && !bytes.Equal(got, payload) {
				readErr = fmt.Errorf("TCP byte mismatch: got=%d want=%d", len(got), len(payload))
			}
		}
		if readErr != nil {
			c.Close()
		}
		writeErr := <-written
		if readErr != nil {
			return readErr
		}
		if writeErr != nil {
			return writeErr
		}
		if repeats > 1 || len(payload) >= 4*1024*1024 {
			t.Logf("MIXED_BULK bytes_each_direction=%d elapsed_us=%d", len(payload)*repeats, time.Since(started).Microseconds())
		} else {
			mu.Lock()
			shortLatencies = append(shortLatencies, time.Since(started))
			shortLastStart = max(shortLastStart, started.Sub(loadStarted))
			mu.Unlock()
		}
		return nil
	}
	start := make(chan struct{})
	for worker := 0; worker < 4; worker++ {
		id := worker
		launch(func() error {
			<-start
			for i := 0; i < profile.shortRounds; i++ {
				if profile.sustained {
					select {
					case <-bulkDone:
						return nil
					default:
					}
				}
				p := bytes.Repeat([]byte{byte(id), byte(i), 0x5a, 0xa5}, 256)
				if err := transfer(p, 1); err != nil {
					return fmt.Errorf("short worker %d request %d: %w", id, i, err)
				}
				time.Sleep(profile.shortPause)
			}
			if profile.sustained {
				return fmt.Errorf("short request safety ceiling reached before bulk completion")
			}
			return nil
		})
	}
	for worker := 0; worker < 2; worker++ {
		id := worker
		launch(func() error {
			<-start
			defer func() {
				if bulkRemaining.Add(-1) == 0 {
					bulkElapsed.Store(time.Since(loadStarted).Nanoseconds())
					close(bulkDone)
				}
			}()
			p := make([]byte, profile.bulkBytes)
			for i := range p {
				p[i] = byte(i*31 + id*17)
			}
			if err := transfer(p, profile.bulkRepeats); err != nil {
				return fmt.Errorf("bulk %d: %w", id, err)
			}
			return nil
		})
	}
	launch(func() error {
		<-start
		defer func() { close(udpDone); udp.Close() }()
		c, err := guest.DialUDPAddrPort(netip.AddrPort{}, udpTarget)
		if err != nil {
			return err
		}
		defer c.Close()
		var got [1024]byte
		for i := 0; i < profile.udpRounds; i++ {
			if profile.sustained {
				select {
				case <-bulkDone:
					return nil
				default:
				}
			}
			begin := time.Now()
			if err := c.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
				return err
			}
			p := bytes.Repeat([]byte{byte(i), byte(i >> 8), 0xa5, 0x5a}, 256)
			if _, err := c.Write(p); err != nil {
				return err
			}
			n, err := c.Read(got[:])
			if err != nil {
				return fmt.Errorf("UDP round %d: %w", i, err)
			}
			if !bytes.Equal(got[:n], p) {
				return fmt.Errorf("UDP mismatch round %d", i)
			}
			udpLatencies = append(udpLatencies, time.Since(begin))
			time.Sleep(profile.udpPause)
		}
		if profile.sustained {
			return fmt.Errorf("UDP safety ceiling reached before bulk completion")
		}
		return nil
	})
	started := time.Now()
	loadStarted = started
	close(start)
	for i := 0; i < 8; i++ {
		select {
		case err := <-results:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal("mixed workload deadline")
		}
	}
	close(hostStop)
	listener.Close()
	if err := <-results; err != nil {
		t.Fatal(err)
	}
	workers.Wait()
	if !profile.sustained && (len(shortLatencies) != 4*profile.shortRounds || len(udpLatencies) != profile.udpRounds) {
		t.Fatal("fixed mixed workload completion count mismatch")
	}
	wantConnections := uint64(len(shortLatencies) + 2)
	if accepted.Load()-empty.Load() != wantConnections {
		t.Fatalf("host payload connection count: accepted=%d empty=%d", accepted.Load(), empty.Load())
	}
	if empty.Load() != 0 {
		t.Fatalf("single-dial handoff left empty host connections: %d", empty.Load())
	}
	sort.Slice(handshakes, func(i, j int) bool { return handshakes[i] < handshakes[j] })
	if len(handshakes) != int(wantConnections) || handshakes[len(handshakes)-1] > 5*time.Second {
		t.Fatalf("handshake bound/count: %v", handshakes)
	}
	if err := s.Stop(); err != nil {
		t.Fatal(err)
	}
	m := s.DetailedMetrics()
	t.Logf("MIXED_ADMISSION counters=%v", m.Admission)
	if m.TCP.ActiveFlows != 0 || m.UDP.ActiveFlows != 0 || m.TCPExt["socket_buffer_bytes"] != 0 || m.TCPExt["dial_reserved"] != 0 || m.TCP.DeliveryRefused != 0 || m.UDP.DeliveryRefused != 0 {
		t.Fatalf("unclean metrics: %+v", m)
	}
	t.Logf("MIXED_RESULTS elapsed_ms=%d handshakes=%d handshake_p50_us=%d handshake_p95_us=%d handshake_max_us=%d buffer_peak=%d host_accepted=%d host_empty=%d async_dials=%d", time.Since(started).Milliseconds(), len(handshakes), handshakes[(len(handshakes)-1)/2].Microseconds(), handshakes[len(handshakes)*95/100].Microseconds(), handshakes[len(handshakes)-1].Microseconds(), m.TCPExt["socket_buffer_peak"], accepted.Load(), empty.Load(), m.TCPExt["dial_start"])
	if profile.sustained {
		elapsed := time.Duration(bulkElapsed.Load())
		if len(shortLatencies) < 64 || len(udpLatencies) < 64 || shortLastStart < elapsed*8/10 {
			t.Fatal("insufficient mixed traffic overlap")
		}
		for reason, count := range m.Admission {
			if reason != "tcp_retransmit_waits" && count != 0 {
				t.Fatalf("unexpected admission refusal: %s=%d", reason, count)
			}
		}
		sort.Slice(shortLatencies, func(i, j int) bool { return shortLatencies[i] < shortLatencies[j] })
		sort.Slice(udpLatencies, func(i, j int) bool { return udpLatencies[i] < udpLatencies[j] })
		bytesEachDirection := int64(2) * int64(profile.bulkBytes) * int64(profile.bulkRepeats)
		t.Logf("SUSTAINED_POOLING_RESULTS bulk_bytes_each_direction=%d bulk_elapsed_us=%d bulk_mib_s_each_direction=%.3f short_requests=%d short_p50_us=%d short_p95_us=%d short_p99_us=%d short_max_us=%d short_last_start_us=%d udp_rounds=%d udp_p95_us=%d udp_p99_us=%d", bytesEachDirection, elapsed.Microseconds(), float64(bytesEachDirection)/(1<<20)/elapsed.Seconds(), len(shortLatencies), shortLatencies[(len(shortLatencies)-1)/2].Microseconds(), shortLatencies[(len(shortLatencies)-1)*95/100].Microseconds(), shortLatencies[(len(shortLatencies)-1)*99/100].Microseconds(), shortLatencies[len(shortLatencies)-1].Microseconds(), shortLastStart.Microseconds(), len(udpLatencies), udpLatencies[(len(udpLatencies)-1)*95/100].Microseconds(), udpLatencies[(len(udpLatencies)-1)*99/100].Microseconds())
	}
}

type mixedRepeatedReader struct {
	block     []byte
	offset    int
	remaining int64
}

func (r *mixedRepeatedReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.block[r.offset:])
	if int64(n) > r.remaining {
		n = int(r.remaining)
	}
	r.offset = (r.offset + n) % len(r.block)
	r.remaining -= int64(n)
	return n, nil
}

func mixedVerifyRepeated(reader io.Reader, block []byte, repeats int) error {
	buffer := make([]byte, len(block))
	for i := 0; i < repeats; i++ {
		if _, err := io.ReadFull(reader, buffer); err != nil {
			return err
		}
		if !bytes.Equal(buffer, block) {
			return fmt.Errorf("TCP bulk block %d mismatch", i)
		}
	}
	var extra [1]byte
	n, err := reader.Read(extra[:])
	if n != 0 || err != io.EOF {
		return fmt.Errorf("TCP bulk trailing bytes or missing EOF: n=%d err=%v", n, err)
	}
	return nil
}
