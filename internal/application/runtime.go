// Package application owns the resources of one wgslirp runtime per process.
package application

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/irctrakz/wgslirp/pkg/core"
	"github.com/irctrakz/wgslirp/pkg/socket"
	wg "github.com/irctrakz/wgslirp/pkg/wireguard"
)

// Config contains the explicitly selected runtime configuration.
type Config struct {
	Device  wg.DeviceConfig
	Socket  socket.Config
	Tun     wg.TunConfig
	Capture wg.CaptureConfig
	Pool    socket.PoolConfig
	// WireGuardLogOutput selects the dependency logger's destination.
	// Nil preserves the standalone stdout destination.
	WireGuardLogOutput io.Writer
}

// Validate checks settings without acquiring process-wide policies or opening resources.
func (c Config) Validate() error {
	if err := c.Device.Validate(); err != nil {
		return err
	}
	if c.Socket.Destinations != nil {
		if err := c.validateRestricted(); err != nil {
			return err
		}
	}
	switch c.Socket.Protocol {
	case "", "ip4:icmp", "ip4:tcp", "ip4:udp":
	default:
		return fmt.Errorf("unsupported protocol: %q", c.Socket.Protocol)
	}
	if err := c.Socket.Validate(); err != nil {
		return err
	}
	if err := c.Tun.Validate(); err != nil {
		return err
	}
	return c.Capture.Validate()
}

// Observers attach standalone diagnostics to the runtime. Workers must return
// on cancellation. They are joined before the runtime closes their resources.
type Observers struct {
	// RegisterForwardingStop installs a synchronous admission stop before
	// starting the restricted socket. The stop function never joins workers.
	RegisterForwardingStop func(stop func())
	WrapProcessor          func(core.PacketProcessor) core.PacketProcessor
	SocketReady            func(context.Context, *socket.SocketInterface)
	DeviceReady            func(context.Context, *socket.SocketInterface, *wg.WGTun, wg.DeviceHandle)
	// Failure callbacks run before teardown and must return without waiting
	// for runtime operations. They let the process bound cleanup.
	StartFailed    func()
	StateUncertain func()
}

var runtimeClaimed atomic.Bool

// Runtime owns the networking resources acquired by Start.
type Runtime struct {
	ctx            context.Context
	cancel         context.CancelFunc
	readyAt        time.Time
	workers        sync.WaitGroup
	closeOnce      sync.Once
	closeErr       error
	captureOpened  bool
	socket         *socket.SocketInterface
	tun            *wg.WGTun
	device         wg.DeviceHandle
	peerMu         sync.Mutex
	peers          *restrictedPeers
	stateUncertain func()
}

// Start constructs a runtime and returns it after the WireGuard device is up.
// It checks cancellation between startup steps and cleans up any partial start.
// After a successful start the caller owns Close. The context cancels
// observers and closes restricted socket admission. Once acquisition begins,
// restart requires a new process because pooling and capture are process-wide.
func Start(ctx context.Context, cfg Config, observers Observers) (_ *Runtime, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if !runtimeClaimed.CompareAndSwap(false, true) {
		return nil, fmt.Errorf("application runtime already attempted in this process")
	}

	ctx, cancel := context.WithCancel(ctx)
	r := &Runtime{ctx: ctx, cancel: cancel, stateUncertain: observers.StateUncertain}
	var failureOnce sync.Once
	startFailed := func() {
		if observers.StartFailed != nil {
			failureOnce.Do(observers.StartFailed)
		}
	}
	defer func() {
		if err != nil {
			startFailed()
			if cleanupErr := r.Close(); cleanupErr != nil {
				err = errors.Join(err, cleanupErr)
			}
		}
	}()

	if err := socket.ConfigurePooling(cfg.Pool); err != nil {
		return nil, err
	}
	if err := wg.ConfigurePCAP(cfg.Capture); err != nil {
		return nil, err
	}
	r.captureOpened = true
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.socket = socket.NewSocketInterface(cfg.Socket)
	if cfg.Socket.Destinations != nil {
		r.peers = newRestrictedPeers(cfg)
		r.socket.EnablePeerAdmission()
		for _, address := range r.peers.active {
			r.socket.AdmitPeerSource(address.As4())
		}
	}
	r.tun, err = wg.NewWGTunWithConfig("wgmux0", cfg.Device.MTU, r.socket, cfg.Tun)
	if err != nil {
		return nil, err
	}
	var processor core.PacketProcessor = wg.NewWGPacketProcessor(r.tun)
	if observers.WrapProcessor != nil {
		processor = observers.WrapProcessor(processor)
	}
	r.socket.SetPacketProcessor(processor)
	if r.peers != nil && observers.RegisterForwardingStop != nil {
		observers.RegisterForwardingStop(func() { r.socket.RequestStop() })
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := r.socket.Start(); err != nil {
		return nil, fmt.Errorf("socket start: %w", err)
	}
	if r.peers != nil && observers.RegisterForwardingStop == nil {
		// Close admission without waiting for the device or an in-flight
		// peer update. The owner still joins cleanup in Close.
		context.AfterFunc(ctx, func() { r.socket.RequestStop() })
	}
	if observers.SocketReady != nil {
		r.workers.Add(1)
		go func() {
			defer r.workers.Done()
			observers.SocketReady(ctx, r.socket)
		}()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if cfg.WireGuardLogOutput == nil {
		r.device, err = wg.StartDevice(cfg.Device, r.tun)
	} else {
		r.device, err = wg.StartDeviceWithFailureHook(cfg.Device, r.tun, cfg.WireGuardLogOutput, startFailed)
	}
	if err != nil {
		return nil, fmt.Errorf("wireguard start: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.readyAt = time.Now()
	if observers.DeviceReady != nil {
		r.workers.Add(1)
		go func() {
			defer r.workers.Done()
			observers.DeviceReady(ctx, r.socket, r.tun, r.device)
		}()
	}
	return r, nil
}

// Close cancels observers and releases all acquired resources. Concurrent
// callers wait for the same shutdown and receive the same result.
func (r *Runtime) Close() error {
	r.peerMu.Lock()
	defer r.peerMu.Unlock()
	return r.close()
}

func (r *Runtime) close() error {
	r.closeOnce.Do(func() {
		r.cancel()
		var socketDone <-chan struct{}
		if r.socket != nil {
			// A WireGuard receiver can be inside a synchronous socket write
			// waiting on a host dial. Cancel socket work before joining it.
			socketDone = r.socket.RequestStop()
		}
		r.workers.Wait()
		if r.device != nil {
			r.closeErr = errors.Join(r.closeErr, r.device.Close())
		}
		if socketDone != nil {
			<-socketDone
		}
		if r.tun != nil {
			r.closeErr = errors.Join(r.closeErr, r.tun.Close())
		}
		if r.captureOpened {
			r.closeErr = errors.Join(r.closeErr, wg.ClosePCAP())
		}
	})
	return r.closeErr
}

// Run starts the runtime and owns its shutdown when ctx is cancelled.
func Run(ctx context.Context, cfg Config, observers Observers) error {
	r, err := Start(ctx, cfg, observers)
	if err != nil {
		return err
	}
	<-ctx.Done()
	return r.Close()
}
