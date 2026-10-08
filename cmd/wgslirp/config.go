package main

import (
	"encoding/json"
	"fmt"
	"github.com/irctrakz/wgslirp/internal/envconfig"
	"github.com/irctrakz/wgslirp/pkg/socket"
	wg "github.com/irctrakz/wgslirp/pkg/wireguard"
	"golang.org/x/net/dns/dnsmessage"
	"net"
	"net/url"
	"strings"
	"time"
)

type healthConfig struct {
	Enabled                 bool
	HTTPURL, DNSName, DNSIP string
}
type applicationConfig struct {
	Device          wg.DeviceConfig
	Socket          socket.Config
	Tun             wg.TunConfig
	Capture         wg.CaptureConfig
	Pool            socket.PoolConfig
	Health          healthConfig
	Metrics         bool
	MetricsInterval time.Duration
	MetricsFormat   string
	PrintConfig     bool
	Warnings        []string
}

// snapshotEnvironment provides a stable input to all parsers in this startup.
func snapshotEnvironment(entries []string) func(string) (string, bool) {
	values := make(map[string]string, len(entries))
	for _, entry := range entries {
		if key, value, ok := strings.Cut(entry, "="); ok {
			values[key] = value
		}
	}
	return func(key string) (string, bool) { v, ok := values[key]; return v, ok }
}

func loadApplicationConfig(lookup func(string) (string, bool)) (applicationConfig, error) {
	var c applicationConfig
	var err error
	if c.Device, err = wg.DeviceConfigFromEnv(lookup); err != nil {
		return c, err
	}
	if c.Socket, err = socketConfig(c.Device.MTU, lookup); err != nil {
		return c, err
	}
	if c.Tun, err = wg.TunConfigFromEnv(lookup); err != nil {
		return c, err
	}
	if c.Capture, err = wg.CaptureConfigFromEnv(lookup); err != nil {
		return c, err
	}
	if c.Pool, err = socket.PoolConfigFromEnv(lookup); err != nil {
		return c, err
	}
	r := envconfig.Reader{Lookup: lookup}
	_, intervalPresent := lookup("METRICS_INTERVAL")
	c.Metrics = r.Bool("METRICS_LOG", intervalPresent)
	interval := r.Text("METRICS_INTERVAL", "30s")
	c.MetricsInterval, err = metricsInterval(interval)
	if err != nil || interval == "" {
		r.Invalid("METRICS_INTERVAL", "must be a positive duration")
	}
	c.MetricsFormat = strings.ToLower(r.Text("METRICS_FORMAT", "text"))
	if c.MetricsFormat != "text" && c.MetricsFormat != "json" {
		r.Invalid("METRICS_FORMAT", "must be text or json")
	}
	c.PrintConfig = r.Bool("PRINT_CONFIG", false)
	c.Health = healthConfig{r.Bool("HEALTHCHECK", false), r.Text("HEALTH_HTTP_URL", "https://httpbin.org/ip"), r.Text("HEALTH_DNS_NAME", "example.com"), r.Text("HEALTH_DNS_IP", "1.1.1.1")}
	u, e := url.Parse(c.Health.HTTPURL)
	if e != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		r.Invalid("HEALTH_HTTP_URL", "must be an absolute HTTP(S) URL")
	}
	if net.ParseIP(c.Health.DNSIP).To4() == nil {
		r.Invalid("HEALTH_DNS_IP", "must be an IPv4 address")
	}
	if c.Health.DNSName == "" {
		r.Invalid("HEALTH_DNS_NAME", "must be a DNS name")
	}
	name, e := dnsmessage.NewName(strings.TrimSuffix(c.Health.DNSName, ".") + ".")
	if e == nil {
		message := dnsmessage.Message{Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
		_, e = message.Pack()
	}
	if e != nil {
		r.Invalid("HEALTH_DNS_NAME", "must be a DNS name")
	}
	for _, name := range []string{"PROCESSOR_WORKERS", "PROCESSOR_QUEUE_CAP"} {
		if _, present := lookup(name); present {
			c.Warnings = append(c.Warnings, fmt.Sprintf("%s is inactive in wgslirp's inline path; remove it (library callers can use socket.ProcessorConfig)", name))
		}
	}
	return c, r.Err
}

// effectiveSummary uses an allowlist: keys, peer identities/endpoints, CIDRs,
// capture paths and health URLs/names are deliberately absent.
func (c applicationConfig) effectiveSummary() string {
	summary := struct {
		Socket                                                                socket.Config
		Tun                                                                   wg.TunConfig
		Pool                                                                  socket.PoolConfig
		ListenPort, MTU, PeerCount, OverlayExclusions                         int
		Debug, WGDebug, OverlayRouting, DisableIPv6, Capture, Health, Metrics bool
		CaptureMaxBytes                                                       int64
		MetricsInterval, MetricsFormat                                        string
	}{Socket: c.Socket, Tun: c.Tun, Pool: c.Pool, ListenPort: c.Device.ListenPort, MTU: c.Device.MTU, PeerCount: len(c.Device.Peers),
		OverlayExclusions: len(c.Device.Options.OverlayExcludeCIDRs), Debug: c.Device.Options.Debug, WGDebug: c.Device.Options.WGDebug,
		OverlayRouting: c.Device.Options.OverlayRouting, DisableIPv6: c.Device.Options.DisableIPv6, Capture: c.Capture.Path != "",
		Health: c.Health.Enabled, Metrics: c.Metrics, CaptureMaxBytes: c.Capture.MaxBytes, MetricsInterval: c.MetricsInterval.String(), MetricsFormat: c.MetricsFormat}
	b, _ := json.Marshal(summary)
	return string(b)
}
