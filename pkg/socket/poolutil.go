package socket

import (
	"fmt"
	"github.com/irctrakz/wgslirp/internal/envconfig"
	"sync/atomic"
)

// PoolConfig is process-wide because packet pools are shared. Configure it before
// constructing interfaces or creating packets. The first use freezes the policy.
type PoolConfig struct{ Enabled bool }

var poolPolicy atomic.Pointer[PoolConfig]

func PoolConfigFromEnv(lookup func(string) (string, bool)) (PoolConfig, error) {
	r := envconfig.Reader{Lookup: lookup}
	c := PoolConfig{Enabled: r.Bool("POOLING", true)}
	if _, present := lookup("POOL_WRAP"); present {
		return c, fmt.Errorf("POOL_WRAP was removed; remove this setting and use explicit packet ownership APIs")
	}
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
	poolPolicy.CompareAndSwap(nil, &PoolConfig{Enabled: true})
	return *poolPolicy.Load()
}
func poolingEnabled() bool { return poolingPolicy().Enabled }

// shouldPoolPacket shares frozen-policy eligibility between allocation and
// live-capacity accounting. Buffers above the largest cache class stay exact-sized.
func shouldPoolPacket(n int) bool {
	return poolingEnabled() && n <= pktXL
}

// bufMaybePool returns an eligible pool class, or exact-sized uncached storage.
func bufMaybePool(n int) []byte {
	if shouldPoolPacket(n) {
		return pktGet(n)
	}
	return make([]byte, n)
}
