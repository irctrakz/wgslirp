package main

import "github.com/irctrakz/wgslirp/pkg/socket"

// Explicit environment overrides the library defaults. Parsing happens before
// constructing any sockets, bridges or worker goroutines.
func socketConfig(mtu int, lookup func(string) (string, bool)) (socket.Config, error) {
	cfg := socket.DefaultConfig()
	cfg.MTU = mtu
	cfg.Protocol = "ip4:tcp"
	return socket.ConfigFromEnv(cfg, lookup)
}
