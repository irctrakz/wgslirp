package socket

import (
	"strings"
	"testing"
)

func TestRetiredSettingsRequireRemoval(t *testing.T) {
	for _, name := range []string{"POOL_WRAP", "TCP_GATE_LOG"} {
		for _, value := range []string{"", "false", "true", "off", "debug", "private-value"} {
			t.Run(name+"/"+value, func(t *testing.T) {
				lookup := func(key string) (string, bool) { return value, key == name }
				var err error
				if name == "POOL_WRAP" {
					_, err = PoolConfigFromEnv(lookup)
				} else {
					_, err = ConfigFromEnv(DefaultConfig(), lookup)
				}
				if err == nil || !strings.Contains(err.Error(), name) || !strings.Contains(err.Error(), "remove this setting") || strings.Contains(err.Error(), "private-value") {
					t.Fatal("missing sanitized migration error", err)
				}
			})
		}
	}
}
