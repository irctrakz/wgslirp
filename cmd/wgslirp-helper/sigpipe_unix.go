//go:build unix

package main

import (
	"os/signal"
	"syscall"
)

func ignoreBrokenPipeSignal() {
	// Route EPIPE through normal error handling so the runtime can shut down.
	signal.Ignore(syscall.SIGPIPE)
}
