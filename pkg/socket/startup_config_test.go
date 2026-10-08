package socket

import (
	"os"
	"testing"
)

func TestProcessorConfigSnapshot(t *testing.T) {
	t.Setenv("PROCESSOR_WORKERS", "2")
	t.Setenv("PROCESSOR_QUEUE_CAP", "3")
	cfg, err := ProcessorConfigFromEnv(DefaultProcessorConfig(), os.LookupEnv)
	if err != nil {
		t.Fatal(err)
	}
	s := NewSocketInterface(DefaultConfig())
	p, err := NewSocketPacketProcessorWithConfig(s, cfg)
	if err != nil {
		t.Fatal(err)
	}
	legacy := NewSocketPacketProcessor(s, 1).(*SocketPacketProcessor)
	t.Setenv("PROCESSOR_WORKERS", "99")
	t.Setenv("PROCESSOR_QUEUE_CAP", "999")
	cfg.Workers = 17
	cfg.QueueCapacity = 17
	if p.workerCount != 2 || cap(p.packetCh) != 3 || legacy.workerCount != 2 || cap(legacy.packetCh) != 3 {
		t.Fatal("processor snapshot changed")
	}
	for _, cfg := range []ProcessorConfig{{0, 1}, {257, 1}, {1, 0}, {1, 65537}} {
		if p, err := NewSocketPacketProcessorWithConfig(s, cfg); err == nil || p != nil {
			t.Fatal("invalid processor allocated")
		}
	}
	t.Setenv("PROCESSOR_WORKERS", "invalid")
	if _, err := ProcessorConfigFromEnv(DefaultProcessorConfig(), os.LookupEnv); err == nil {
		t.Fatal("accepted invalid workers")
	}
	legacy = NewSocketPacketProcessor(s, 1).(*SocketPacketProcessor)
	if legacy.workerCount != 4 || cap(legacy.packetCh) != 1000 {
		t.Fatal("legacy invalid fallback")
	}
}

func TestPoolingPolicyIsExplicitAndFrozen(t *testing.T) {
	original := poolPolicy.Swap(nil)
	defer poolPolicy.Store(original)
	t.Setenv("POOLING", "yes")
	t.Setenv("POOL_WRAP", "on")
	cfg, err := PoolConfigFromEnv(os.LookupEnv)
	if err != nil {
		t.Fatal(err)
	}
	if err := ConfigurePooling(cfg); err != nil {
		t.Fatal(err)
	}
	cfg.Enabled = false
	t.Setenv("POOLING", "false")
	t.Setenv("POOL_WRAP", "false")
	if !poolingEnabled() || !poolWrapEnabled() {
		t.Fatal("pooling changed after configuration")
	}
	if err := ConfigurePooling(PoolConfig{true, true}); err != nil {
		t.Fatal("same policy should be idempotent")
	}
	if err := ConfigurePooling(PoolConfig{}); err == nil {
		t.Fatal("allowed live policy change")
	}
	poolPolicy.Store(nil)
	NewSocketInterface(DefaultConfig())
	if err := ConfigurePooling(PoolConfig{true, false}); err == nil {
		t.Fatal("allowed policy change after construction")
	}
	if poolingEnabled() {
		t.Fatal("default must be off")
	}
	for _, key := range []string{"POOLING", "POOL_WRAP"} {
		t.Setenv(key, "maybe")
		if _, err := PoolConfigFromEnv(os.LookupEnv); err == nil {
			t.Fatal("accepted invalid pooling option")
		}
		t.Setenv(key, "false")
	}
}
