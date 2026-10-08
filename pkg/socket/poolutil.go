package socket

import (
	"fmt"
	"github.com/irctrakz/wgslirp/internal/envconfig"
	"sync/atomic"

	"github.com/irctrakz/wgslirp/pkg/core"
)

// PoolConfig is process-wide because packet pools are shared. Configure it before
// constructing interfaces or creating packets. The first use freezes the policy.
type PoolConfig struct{ Enabled, Wrap bool }

var poolPolicy atomic.Pointer[PoolConfig]

func PoolConfigFromEnv(lookup func(string) (string, bool)) (PoolConfig, error) {
	r := envconfig.Reader{Lookup: lookup}
	c := PoolConfig{r.Bool("POOLING", false), r.Bool("POOL_WRAP", false)}
	return c, r.Err
}

// ConfigurePooling is idempotent for the same policy and rejects live changes.
func ConfigurePooling(c PoolConfig) error {
	if poolPolicy.CompareAndSwap(nil, &c) {
		return nil
	}
	if *poolPolicy.Load() != c {
		return fmt.Errorf("pooling policy is already fixed; configure before constructing interfaces or packets")
	}
	return nil
}

func poolingPolicy() PoolConfig {
	if c := poolPolicy.Load(); c != nil {
		return *c
	}
	poolPolicy.CompareAndSwap(nil, &PoolConfig{})
	return *poolPolicy.Load()
}
func poolingEnabled() bool  { return poolingPolicy().Enabled }
func poolWrapEnabled() bool { return poolingPolicy().Wrap }

// bufMaybePool returns a byte slice of length n, using the pool when enabled.
func bufMaybePool(n int) []byte {
	if poolingEnabled() {
		return pktGet(n)
	}
	return make([]byte, n)
}

// WrapPacket wraps a buffer into a Packet according to the current
// pooling/ownership policy. It always returns a safe Packet for asynchronous
// processing, independently of DEBUG settings. When pooling and wrapping are
// enabled, callers transfer the buffer and must never mutate or reuse it.
//
// Deprecated: use core.NewCopiedPacket for a snapshot, core.NewBorrowedPacket
// for immutable caller storage, or core.NewPooledPacket for explicit release.
// This adapter retains its historical configuration-dependent behavior.
func WrapPacket(b []byte) core.Packet {
	if poolingEnabled() && poolWrapEnabled() {
		return core.NewPooledPacket(b, func(buf []byte) {
			if pktShouldPut(buf) {
				pktPut(buf)
			}
		})
	}
	// Non-pooled wrapper: ensure unique ownership by copying when DEBUG is off
	if !core.IsDebugMode() {
		bb := append([]byte(nil), b...)
		return core.NewPacket(bb)
	}
	return core.NewPacket(b)
}
