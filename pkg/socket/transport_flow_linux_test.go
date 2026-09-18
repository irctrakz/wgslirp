package socket

import (
	"bytes"
	"context"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Exercise both SYN-ACK paths after changing the environment, and inspect the
// actual host socket rather than only asserting that configuration was stored.
func TestTransportFlowSnapshot(t *testing.T) {
	for _, async := range []bool{false, true} {
		for _, ccOff := range []bool{false, true} {
			t.Run(map[bool]string{false: "fast", true: "async"}[async]+map[bool]string{false: "-reno", true: "-off"}[ccOff], func(t *testing.T) {
				cfg := DefaultConfig()
				cfg.Protocol = "ip4:tcp"
				cfg.Transport.FastDialMs = 17
				cfg.Transport.WindowScale = 3
				cfg.Transport.EnableSACK = true
				cfg.Transport.InitialCwndMSS = 2
				cfg.Transport.SocketReceiveBuffer = 4096
				cfg.Transport.SocketSendBuffer = 8192
				if ccOff {
					cfg.Transport.CongestionControl = "off"
				}
				s := NewSocketInterface(cfg)
				cp := &captureProcessor{}
				s.SetPacketProcessor(cp)
				if err := s.Start(); err != nil {
					t.Fatal(err)
				}
				defer s.Stop()
				for key, value := range map[string]string{"TCP_FAST_DIAL_MS": "99", "TCP_WS_OUT": "14", "TCP_ENABLE_SACK": "0", "TCP_CC": "off", "TCP_INIT_CWND_MSS": "1", "TCP_SOCK_RCVBUF": "65536", "TCP_SOCK_SNDBUF": "65536"} {
					t.Setenv(key, value)
				}
				client, _ := tcpBudgetPair(t)
				var calls atomic.Int32
				s.tcp.dial = func(_ context.Context, _ string, timeout time.Duration) (*net.TCPConn, error) {
					n := calls.Add(1)
					if n == 1 && timeout != 17*time.Millisecond {
						t.Errorf("fast dial timeout = %v", timeout)
					}
					if async && n == 1 {
						return nil, &net.DNSError{IsTimeout: true}
					}
					return client, nil
				}
				syn := buildIPv4TCP([4]byte{10, 0, 0, 2}, [4]byte{127, 0, 0, 1}, 40000, 80, 1, 0, 2, nil)
				if err := s.tcp.HandleOutbound(syn); err != nil {
					t.Fatal(err)
				}
				deadline := time.Now().Add(2 * time.Second)
				var reply []byte
				for time.Now().Before(deadline) {
					for _, p := range cp.snapshot() {
						if len(p) >= 40 && p[33]&0x12 == 0x12 {
							reply = p
							break
						}
					}
					if reply != nil {
						break
					}
					time.Sleep(time.Millisecond)
				}
				if reply == nil {
					t.Fatal("no SYN-ACK")
				}
				opts := reply[40 : 20+int(reply[32]>>4)*4]
				if !bytes.Contains(opts, []byte{3, 3, 3}) || !bytes.Contains(opts, []byte{4, 2}) {
					t.Fatalf("wrong SYN-ACK options: %v", opts)
				}
				flows := s.tcp.flowSnapshot()
				if len(flows) != 1 {
					t.Fatalf("flows: %d", len(flows))
				}
				f := flows[0]
				f.stateMu.Lock()
				if f.wsOut != 3 || f.ccEnabled == ccOff {
					t.Error("flow ignored snapshot")
				}
				if !ccOff && f.cc.Cwnd() != 2*f.mss {
					t.Errorf("cwnd=%d MSS=%d", f.cc.Cwnd(), f.mss)
				}
				f.stateMu.Unlock()
				for {
					f.stateMu.Lock()
					connected := f.conn != nil
					f.stateMu.Unlock()
					if connected {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("host dial did not finish")
					}
					time.Sleep(time.Millisecond)
				}
				raw, err := client.SyscallConn()
				if err != nil {
					t.Fatal(err)
				}
				err = raw.Control(func(fd uintptr) {
					for opt, want := range map[int]int{syscall.SO_RCVBUF: 8192, syscall.SO_SNDBUF: 16384} {
						got, err := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, opt)
						// Linux doubles the requested size for bookkeeping.
						if err != nil || got != want {
							t.Errorf("socket option %d = %d (%v); want %d", opt, got, err, want)
						}
					}
				})
				if err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
