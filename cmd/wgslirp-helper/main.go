package main

import (
	"context"
	"io"
	"log"
	"os"

	"github.com/irctrakz/wgslirp/internal/application"
	"github.com/irctrakz/wgslirp/internal/helperwire"
	"github.com/irctrakz/wgslirp/pkg/logging"
)

// Set by release builds with -ldflags "-X main.version=...".
var version = "dev"

func binaryVersion() string {
	if versionPattern.MatchString(version) {
		return version
	}
	return "dev"
}

func main() { os.Exit(runMain(os.Args[1:])) }

func runMain(args []string) int {
	if len(args) == 1 && args[0] == "--version" {
		if _, err := io.WriteString(os.Stdout, binaryVersion()+"\n"); err != nil {
			return 1
		}
		return 0
	}
	diagnostics := configureDiagnostics()
	defer diagnostics.finish()
	if len(args) != 0 {
		log.Print("usage: wgslirp-helper [--version]")
		return 1
	}
	output, err := helperwire.NewStdoutOutput()
	if err != nil {
		log.Print("could not initialize helper protocol stdout")
		return 1
	}
	return serve(os.Stdin, output, controller{diagnostics: diagnostics, start: startRuntime}, shutdownTimeout)
}

func startRuntime(ctx context.Context, cfg application.Config, observers application.Observers) (managedRuntime, error) {
	r, err := application.Start(ctx, cfg, observers)
	if err != nil {
		return nil, err
	}
	return r, nil
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
