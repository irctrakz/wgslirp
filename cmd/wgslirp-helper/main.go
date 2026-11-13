package main

import (
	"context"
	"errors"
	"log"

	"github.com/irctrakz/wgslirp/internal/application"
)

func main() {
	// The protocol controller will supply the validated restricted profile.
	if err := run(context.Background(), nil); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, cfg *application.Config) error {
	if cfg == nil {
		return errors.New("wgslirp-helper requires a protocol controller")
	}
	return application.Run(ctx, *cfg, application.Observers{})
}
