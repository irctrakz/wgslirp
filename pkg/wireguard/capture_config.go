package wireguard

import (
	"fmt"
	"strconv"
	"strings"
)

type CaptureConfig struct {
	Path     string
	MaxBytes int64
}

func DefaultCaptureConfig() CaptureConfig { return CaptureConfig{MaxBytes: defaultPCAPLimit} }
func (c CaptureConfig) Validate() error {
	if c.MaxBytes < 24 {
		return fmt.Errorf("WG_PCAP_MAX_BYTES must be an integer of at least 24")
	}
	return nil
}
func CaptureConfigFromEnv(lookup func(string) (string, bool)) (CaptureConfig, error) {
	c := DefaultCaptureConfig()
	if v, ok := lookup("WG_PCAP"); ok {
		c.Path = strings.TrimSpace(v)
	}
	if v, ok := lookup("WG_PCAP_MAX_BYTES"); ok {
		n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err != nil {
			return c, fmt.Errorf("WG_PCAP_MAX_BYTES must be an integer of at least 24")
		}
		c.MaxBytes = n
	}
	return c, c.Validate()
}
