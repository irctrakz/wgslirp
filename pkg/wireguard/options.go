package wireguard

import (
	"fmt"
	"github.com/irctrakz/wgslirp/internal/envconfig"
	"net"
)

type DeviceOptions struct {
	Debug               bool
	WGDebug             bool
	OverlayRouting      bool
	OverlayExcludeCIDRs []string
	DisableIPv6         bool
}

func DefaultDeviceOptions() DeviceOptions { return DeviceOptions{DisableIPv6: true} }

func (c DeviceConfig) deviceOptions() DeviceOptions {
	if c.Options == nil {
		return DefaultDeviceOptions()
	}
	options := *c.Options
	options.OverlayExcludeCIDRs = append([]string(nil), options.OverlayExcludeCIDRs...)
	return options
}

func (c DeviceOptions) Validate() error {
	for _, cidr := range c.OverlayExcludeCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("WG_OVERLAY_EXCLUDE_CIDRS must contain valid CIDRs")
		}
	}
	return nil
}

func DeviceOptionsFromEnv(lookup func(string) (string, bool)) (DeviceOptions, error) {
	r := envconfig.Reader{Lookup: lookup}
	c := DefaultDeviceOptions()
	c.Debug = r.Bool("DEBUG", false)
	c.WGDebug = r.Bool("WG_DEBUG", false)
	c.OverlayRouting = r.Bool("WG_OVERLAY_ROUTING", false)
	c.DisableIPv6 = r.Bool("WG_DISABLE_IPV6", true)
	c.OverlayExcludeCIDRs = splitCSV(r.Text("WG_OVERLAY_EXCLUDE_CIDRS", ""))
	if r.Err != nil {
		return c, r.Err
	}
	return c, c.Validate()
}

// TunConfig bounds queue metadata independently of the shared payload budget.
type TunConfig struct{ QueueCapacity int }

func DefaultTunConfig() TunConfig { return TunConfig{QueueCapacity: 1024} }
func (c TunConfig) Validate() error {
	if c.QueueCapacity < 1 || c.QueueCapacity > 65536 {
		return fmt.Errorf("WG_TUN_QUEUE_CAP must be between 1 and 65536")
	}
	return nil
}
func TunConfigFromEnv(lookup func(string) (string, bool)) (TunConfig, error) {
	r := envconfig.Reader{Lookup: lookup}
	c := TunConfig{QueueCapacity: r.Int("WG_TUN_QUEUE_CAP", 1024, 1, 65536)}
	return c, r.Err
}
