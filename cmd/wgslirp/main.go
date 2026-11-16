package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/irctrakz/wgslirp/internal/application"
	"github.com/irctrakz/wgslirp/pkg/core"
	"github.com/irctrakz/wgslirp/pkg/logging"
	"github.com/irctrakz/wgslirp/pkg/socket"
	wg "github.com/irctrakz/wgslirp/pkg/wireguard"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	cfg, err := loadApplicationConfig(snapshotEnvironment(os.Environ()))
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if cfg.Device.Options.Debug {
		logging.SetLevel(logging.DebugLevel)
		logging.Infof("DEBUG enabled: verbose logging")
	} else if cfg.Metrics {
		logging.SetLevel(logging.InfoLevel)
	} else {
		logging.SetLevel(logging.WarnLevel)
	}

	for _, warning := range cfg.Warnings {
		logging.Warnf("%s", warning)
	}
	if cfg.PrintConfig {
		log.Printf("effective configuration: %s", cfg.effectiveSummary())
	}
	observers := application.Observers{}
	if cfg.Health.Enabled {
		hc := newHealthSink()
		observers.WrapProcessor = func(primary core.PacketProcessor) core.PacketProcessor {
			return newTeeProcessor(primary, hc)
		}
		observers.SocketReady = func(ctx context.Context, si *socket.SocketInterface) {
			var workers sync.WaitGroup
			workers.Add(1)
			go func() {
				defer workers.Done()
				runSlirpDNSHealth(ctx, si, hc, cfg.Health)
			}()
			runDirectEgressHealth(ctx, cfg.Health)
			workers.Wait()
		}
	}
	if cfg.Metrics {
		observers.DeviceReady = func(ctx context.Context, si *socket.SocketInterface, tun *wg.WGTun, dev wg.DeviceHandle) {
			runMetricsReporter(ctx, cfg.MetricsInterval, si, tun, dev, cfg.MetricsFormat)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err = application.Run(ctx, cfg.Config, observers)
	if err == context.Canceled {
		// A signal during startup is a clean shutdown if cleanup succeeded.
		return nil
	}
	return err
}
