package main

import (
	"context"
	"errors"
	"io"
	"log"
	"os"

	"github.com/irctrakz/wgslirp/internal/application"
	"github.com/irctrakz/wgslirp/pkg/logging"
)

func main() {
	diagnostics := configureDiagnostics()
	// The protocol controller will supply the validated restricted profile.
	err := run(context.Background(), nil, diagnostics)
	if err != nil {
		log.Print(err)
	}
	diagnostics.finish()
	if err != nil {
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg *application.Config, diagnostics io.Writer) error {
	if cfg == nil {
		return errors.New("wgslirp-helper requires a protocol controller")
	}
	return application.Run(ctx, helperConfig(*cfg, diagnostics), application.Observers{})
}

func helperConfig(cfg application.Config, diagnostics io.Writer) application.Config {
	cfg.WireGuardLogOutput = diagnostics
	return cfg
}

func configureDiagnostics() *diagnostics {
	ignoreBrokenPipeSignal()
	sink := newDiagnostics(os.Stderr)
	log.SetOutput(sink)
	logging.SetOutput(sink)
	return sink
}
