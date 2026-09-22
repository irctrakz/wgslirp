package wireguard

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/irctrakz/wgslirp/pkg/logging"
	"golang.zx2c4.com/wireguard/conn"
	wgdev "golang.zx2c4.com/wireguard/device"
)

type wgHandle struct {
	dev       *wgdev.Device
	done      chan struct{}
	closeOnce sync.Once
	monitor   sync.WaitGroup
}

func (h *wgHandle) Close() error {
	h.closeOnce.Do(func() {
		if h.done != nil {
			close(h.done)
		}
		h.monitor.Wait()
		if h.dev != nil {
			h.dev.Close()
		}
	})
	return nil
}

func (h *wgHandle) IpcGet() (string, error) {
	if h == nil || h.dev == nil {
		return "", fmt.Errorf("nil device")
	}
	return h.dev.IpcGet()
}

// RebindListenPort updates the device's UDP listen port (0 = random) via UAPI.
func (h *wgHandle) RebindListenPort(port int) error {
	if h == nil || h.dev == nil {
		return fmt.Errorf("nil device")
	}
	if port < 0 {
		port = 0
	}
	conf := fmt.Sprintf("listen_port=%d\n", port)
	if err := h.dev.IpcSet(conf); err != nil {
		return fmt.Errorf("IpcSet listen_port: %w", err)
	}
	return nil
}

// monitorWireGuardHandshakes periodically logs handshake status and tunnel events
// to help diagnose connection issues
func monitorWireGuardHandshakes(h *wgHandle) {
	if h == nil || h.dev == nil {
		return
	}
	defer h.monitor.Done()

	// Log handshake status every 30 seconds
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	logging.Infof("WireGuard handshake monitoring started")

	for {
		select {
		case <-h.done:
			return
		case <-ticker.C:
			// Get current device state
			state, err := h.IpcGet()
			if err != nil {
				logging.Warnf("WireGuard handshake monitor: failed to get device state: %v", err)
				continue
			}

			// Parse and log handshake information
			parseAndLogHandshakeStatus(state)
		}
	}
}

// parseAndLogHandshakeStatus parses the WireGuard device state and logs handshake information
func parseAndLogHandshakeStatus(state string) {
	for _, peer := range ParsePeerState(state) {
		logPeerStatus(peer.PublicKey, peer.Handshake, peer.Endpoint, peer.RX, peer.TX)
	}
}

// logPeerStatus logs the status of a WireGuard peer
func logPeerStatus(publicKey string, handshakeTime int64, endpoint string, rx, tx uint64) {
	// Format the handshake time
	handshakeStatus := "never"
	if handshakeTime > 0 {
		lastHandshake := time.Unix(handshakeTime, 0)
		age := time.Since(lastHandshake)
		if age < 0 {
			age = 0
		}

		if age < time.Minute {
			handshakeStatus = fmt.Sprintf("%d seconds ago", int(age.Seconds()))
		} else if age < time.Hour {
			handshakeStatus = fmt.Sprintf("%d minutes ago", int(age.Minutes()))
		} else {
			handshakeStatus = fmt.Sprintf("%d hours ago", int(age.Hours()))
		}
	}

	// Truncate public key for display
	shortKey := publicKey
	if len(shortKey) > 16 {
		shortKey = shortKey[:8] + "..." + shortKey[len(shortKey)-8:]
	}

	// Log the peer status
	logging.Infof("WireGuard peer %s: handshake=%s endpoint=%s transfer=rx:%d/tx:%d bytes",
		shortKey, handshakeStatus, endpoint, rx, tx)
}

// StartDevice starts wireguard-go device bound to cfg.ListenPort using the
// provided WGTun for plaintext exchange. It applies configuration via IpcSet.
func StartDevice(cfg DeviceConfig, tun *WGTun) (DeviceHandle, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if tun == nil {
		return nil, fmt.Errorf("nil tun")
	}
	// Preserve legacy sysctl writes only for explicit opt-in configuration.
	options := cfg.deviceOptions()
	if options.DisableIPv6 {
		disableIPv6Sysctls()
	}
	bind := conn.NewDefaultBind()

	debugOn := options.Debug
	wgDebugOn := options.WGDebug

	// Set log level based on debug flags
	wgLevel := wgdev.LogLevelError
	if wgDebugOn {
		// WG_DEBUG enables the most verbose logging
		wgLevel = wgdev.LogLevelVerbose
		logging.Infof("WireGuard verbose debugging enabled via WG_DEBUG")
	} else if debugOn {
		// Regular DEBUG enables standard verbose logging
		wgLevel = wgdev.LogLevelVerbose
	}

	logger := wgdev.NewLogger(wgLevel, "[wg]")
	dev := wgdev.NewDevice(tun, bind, logger)

	// Compose peer sections (hex-encode public keys when possible)
	peersHex := strings.Builder{}
	for _, p := range cfg.Peers {
		// try base64->hex for public key; fallback to given string
		pubHex := ""
		if raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(p.PublicKey)); err == nil && len(raw) == 32 {
			pubHex = hex.EncodeToString(raw)
		}
		if pubHex != "" {
			peersHex.WriteString(fmt.Sprintf("public_key=%s\n", pubHex))
		} else {
			// fallback to provided value if decode fails (assume already hex)
			peersHex.WriteString(fmt.Sprintf("public_key=%s\n", p.PublicKey))
		}
		for _, ip := range p.AllowedIPs {
			peersHex.WriteString(fmt.Sprintf("allowed_ip=%s\n", ip))
		}
		if p.Endpoint != "" {
			peersHex.WriteString(fmt.Sprintf("endpoint=%s\n", p.Endpoint))
		}
		if p.PersistentKeepaliveSec > 0 {
			peersHex.WriteString(fmt.Sprintf("persistent_keepalive_interval=%d\n", p.PersistentKeepaliveSec))
		}
	}

	// Decode base64 private key and send hex to UAPI to avoid parser complaints
	rawPriv, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cfg.PrivateKey))
	if err != nil || len(rawPriv) != 32 {
		dev.Close()
		return nil, fmt.Errorf("invalid WG_PRIVATE_KEY: must be base64 of 32 bytes")
	}
	keyHex := hex.EncodeToString(rawPriv)
	confHex := fmt.Sprintf("private_key=%s\nlisten_port=%d\nreplace_peers=true\n%s", keyHex, cfg.ListenPort, peersHex.String())

	// Never log UAPI configuration: it contains private key material.
	if debugOn {
		logging.Debugf("Applying WireGuard configuration: listen_port=%d peers=%d", cfg.ListenPort, len(cfg.Peers))
	}
	if err := dev.IpcSet(confHex); err != nil {
		dev.Close()
		return nil, fmt.Errorf("IpcSet: %w", err)
	}
	// Provide peer AllowedIPs to the tun for overlay routing decisions if enabled
	overlayOn := options.OverlayRouting
	if overlayOn {
		var cidrs []string
		for _, p := range cfg.Peers {
			cidrs = append(cidrs, p.AllowedIPs...)
		}
		if err := tun.SetPeerCIDRs(cidrs); err != nil {
			logging.Warnf("WG overlay routing CIDR parse failed: %v", err)
		} else if debugOn {
			logging.Debugf("WG overlay routing enabled for CIDRs: %v", cidrs)
		}

		// Build exclusions: start with system interface subnets (container LANs), plus env WG_OVERLAY_EXCLUDE_CIDRS
		var excludes []string
		ifaces, _ := net.Interfaces()
		for _, iface := range ifaces {
			addrs, _ := iface.Addrs()
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok {
					if ip := ipn.IP.To4(); ip != nil {
						// Skip loopback
						if ip.IsLoopback() {
							continue
						}
						// Use the network (IP&mask)
						excludes = append(excludes, ipn.String())
					}
				}
			}
		}
		excludes = append(excludes, options.OverlayExcludeCIDRs...)
		if err := tun.SetExcludeCIDRs(excludes); err != nil {
			logging.Warnf("WG overlay exclude CIDR parse failed: %v", err)
		} else if debugOn {
			logging.Debugf("WG overlay exclude CIDRs: %v", excludes)
		}
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("device up: %w", err)
	}
	log.Printf("wireguard device up on UDP :%d", cfg.ListenPort)

	logging.Debugf("WireGuard device started: listen_port=%d peers=%d", cfg.ListenPort, len(cfg.Peers))

	// Start handshake monitoring if WG_DEBUG is enabled
	handle := &wgHandle{dev: dev, done: make(chan struct{})}
	if wgDebugOn {
		handle.monitor.Add(1)
		go monitorWireGuardHandshakes(handle)
	}

	return handle, nil
}

// disableIPv6Sysctls attempts to disable IPv6 via procfs sysctls. It logs warnings on failure
// but does not return an error to keep startup resilient in restricted environments.
func disableIPv6Sysctls() {
	paths := []string{
		"/proc/sys/net/ipv6/conf/all/disable_ipv6",
		"/proc/sys/net/ipv6/conf/default/disable_ipv6",
		"/proc/sys/net/ipv6/conf/lo/disable_ipv6",
	}
	okAny := false
	for _, p := range paths {
		if err := os.WriteFile(p, []byte("1"), 0644); err != nil {
			logging.Debugf("WG_DISABLE_IPV6: failed to write %s: %v", p, err)
			continue
		}
		okAny = true
	}
	if okAny {
		logging.Infof("WG_DISABLE_IPV6: IPv6 disabled via sysctls")
	} else {
		logging.Warnf("WG_DISABLE_IPV6 requested but could not apply sysctls; consider Docker sysctls: net.ipv6.conf.*.disable_ipv6=1")
	}
}
