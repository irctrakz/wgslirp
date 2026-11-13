package main

import (
	"context"
	"errors"
	"log"
	"os"

	"github.com/irctrakz/wgslirp/internal/application"
	"github.com/irctrakz/wgslirp/pkg/logging"
)

func main() {
	// The protocol controller will supply the validated restricted profile.
	if err := run(context.Background(), nil); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, cfg *application.Config) error {
	configureDiagnostics()
	if cfg == nil {
		return errors.New("wgslirp-helper requires a protocol controller")
	}
	return application.Run(ctx, helperConfig(*cfg), application.Observers{})
}

func helperConfig(cfg application.Config) application.Config {
	cfg.WireGuardLogOutput = os.Stderr
	return cfg
}

func configureDiagnostics() {
	log.SetOutput(os.Stderr)
	logging.SetOutput(os.Stderr)
}
