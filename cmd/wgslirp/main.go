package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/irctrakz/wgslirp/pkg/core"
	"github.com/irctrakz/wgslirp/pkg/logging"
	"github.com/irctrakz/wgslirp/pkg/socket"
	wg "github.com/irctrakz/wgslirp/pkg/wireguard"
	// wtun removed (no dynamic flow rate hooks)
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	defer wg.ClosePCAP()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg, err := loadApplicationConfig(snapshotEnvironment(os.Environ()))
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	debugOn := cfg.Device.Options.Debug
	metricsEnabled := cfg.Metrics
	interval := cfg.MetricsInterval
	if debugOn {
		logging.SetLevel(logging.DebugLevel)
		core.SetDebugMode(true)
		logging.Infof("DEBUG enabled: verbose logging and packet copy mode")
	} else {
		// Default to warn to keep runtime quiet unless explicitly enabled
		logging.SetLevel(logging.WarnLevel)
		core.SetDebugMode(false)
		// If metrics are enabled, raise to info so metrics dumps are visible
		if metricsEnabled {
			logging.SetLevel(logging.InfoLevel)
		}
	}

	for _, warning := range cfg.Warnings {
		logging.Warnf("%s", warning)
	}
	if cfg.PrintConfig {
		log.Printf("effective configuration: %s", cfg.effectiveSummary())
	}
	if err := socket.ConfigurePooling(cfg.Pool); err != nil {
		return err
	}
	if err := wg.ConfigurePCAP(cfg.Capture); err != nil {
		return err
	}
	dcfg := cfg.Device
	si := socket.NewSocketInterface(cfg.Socket)

	// Create WG TUN bound to the socket writer
	wgtun, err := wg.NewWGTunWithConfig("wgmux0", dcfg.MTU, si, cfg.Tun)
	if err != nil {
		return err
	}
	defer wgtun.Close()

	// Packet processor: WG + optional health sink
	wgProc := wg.NewWGPacketProcessor(wgtun)
	proc := wgProc
	var hc *healthSink
	// Optional: tee a health-check sink to observe slirp replies
	if cfg.Health.Enabled {
		hc = newHealthSink()
		proc = newTeeProcessor(wgProc, hc)
	}
	si.SetPacketProcessor(proc)
	if err := si.Start(); err != nil {
		return fmt.Errorf("socket start: %w", err)
	}
	defer si.Stop()
	if hc != nil {
		var healthWorkers sync.WaitGroup
		healthWorkers.Add(2)
		defer func() { cancel(); healthWorkers.Wait() }()
		go func() { defer healthWorkers.Done(); runSlirpDNSHealth(ctx, si, hc, cfg.Health) }()
		go func() { defer healthWorkers.Done(); runDirectEgressHealth(ctx, cfg.Health) }()
	}

	// Start the WireGuard device (wg is the default implementation)
	dev, err := wg.StartDevice(dcfg, wgtun)
	if err != nil {
		return fmt.Errorf("wireguard start: %w", err)
	}
	defer dev.Close()

	// Optional periodic metrics reporter
	if metricsEnabled {
		var reporter sync.WaitGroup
		reporter.Add(1)
		go func() { defer reporter.Done(); runMetricsReporter(ctx, interval, si, wgtun, dev, cfg.MetricsFormat) }()
		defer func() { cancel(); reporter.Wait() }()
	}

	// Wait for termination
	sigc := make(chan os.Signal, 2)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigc)
	<-sigc
	return nil
}
