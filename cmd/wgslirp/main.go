package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
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
	// Debug logging toggle via DEBUG env (truthy parser)
	dval := strings.ToLower(strings.TrimSpace(os.Getenv("DEBUG")))
	debugOn := dval == "1" || dval == "true" || dval == "yes" || dval == "on"
	// Detect metrics enabled via env
	metricsEnabled := strings.TrimSpace(os.Getenv("METRICS_LOG")) != "" || strings.TrimSpace(os.Getenv("METRICS_INTERVAL")) != ""
	interval, err := metricsInterval(os.Getenv("METRICS_INTERVAL"))
	if metricsEnabled && err != nil {
		return err
	}
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

	// Load WG config from env
	var dcfg wg.DeviceConfig
	if err := dcfg.LoadFromEnv(); err != nil {
		return fmt.Errorf("config: %w", err)
	}

	// Build socket interface (slirp bridges). Align slirp MTU with WG plaintext MTU
	// so that synthesized packets (e.g., TCP segments) never exceed the WG TUN MTU.
	// This prevents silent truncation/clamping at the tun boundary.
	mtu := dcfg.MTU
	if mtu <= 0 {
		mtu = 1380
	}
	scfg := socket.Config{IPAddress: "0.0.0.0", MTU: mtu, Protocol: "ip4:tcp"}
	si := socket.NewSocketInterface(scfg)

	// Create WG TUN bound to the socket writer
	wgtun := wg.NewWGTun("wgmux0", dcfg.MTU, si)
	defer wgtun.Close()

	// Packet processor: WG + optional health sink
	wgProc := wg.NewWGPacketProcessor(wgtun)
	proc := wgProc
	var hc *healthSink
	// Optional: tee a health-check sink to observe slirp replies
	if strings.TrimSpace(os.Getenv("HEALTHCHECK")) != "" {
		hc = newHealthSink()
		proc = newTeeProcessor(wgProc, hc)
	}
	si.SetPacketProcessor(proc)
	if err := si.Start(); err != nil {
		return fmt.Errorf("socket start: %w", err)
	}
	defer si.Stop()
	if hc != nil {
		go runSlirpDNSHealth(si, hc)
		go runDirectEgressHealth()
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
		go func() { defer reporter.Done(); runMetricsReporter(ctx, interval, si, wgtun, dev) }()
		defer func() { cancel(); reporter.Wait() }()
	}

	// Wait for termination
	sigc := make(chan os.Signal, 2)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigc)
	<-sigc
	return nil
}
