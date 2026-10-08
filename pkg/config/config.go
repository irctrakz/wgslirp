// Package config provides the legacy router JSON/YAML configuration model.
//
// Deprecated: this model is retained for library consumers but does not configure
// cmd/wgslirp. Use socket.ConfigFromEnv and wireguard.DeviceConfigFromEnv for the
// executable's supported environment contract. See CONFIGURATION.md for migration.
// LoadFromFile and LoadFromEnv retain their historical merge and validation behavior.
package config

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/irctrakz/wgslirp/pkg/core"
	"github.com/irctrakz/wgslirp/pkg/logging"
	"gopkg.in/yaml.v3"
)

// Config represents the complete router configuration.
type Config struct {
	// Router contains the router configuration.
	Router core.RouterConfig `json:"router" yaml:"router"`

	// WireGuard contains the WireGuard configuration.
	WireGuard core.WireGuardConfig `json:"wireguard" yaml:"wireguard"`

	// Logging contains the logging configuration.
	Logging LoggingConfig `json:"logging" yaml:"logging"`
}

// LoggingConfig contains configuration for logging.
type LoggingConfig struct {
	// Level is the logging level (debug, info, warn, error).
	Level string `json:"level" yaml:"level"`

	// File is the log file path.
	File string `json:"file" yaml:"file"`

	// MaxSize is the maximum size of the log file in megabytes.
	MaxSize int `json:"maxSize" yaml:"maxSize"`

	// MaxBackups is the maximum number of old log files to retain.
	MaxBackups int `json:"maxBackups" yaml:"maxBackups"`

	// MaxAge is the maximum number of days to retain old log files.
	MaxAge int `json:"maxAge" yaml:"maxAge"`
}

// DefaultConfig returns the default configuration.
func DefaultConfig() *Config {
	return &Config{
		Router: core.RouterConfig{
			TUNName:   "tun0",
			TUNIP:     "192.168.1.1",
			TUNSubnet: "192.168.1.0/24",
			TUNMTU:    1500,
			SocketIP:  "10.0.0.1",
			Debug:     false,
		},
		WireGuard: core.WireGuardConfig{
			ListenPort:              51820,
			Peers:                   []core.WireGuardPeer{},
			DisableSourceValidation: false,
		},
		Logging: LoggingConfig{
			Level:      "info",
			File:       "",
			MaxSize:    10,
			MaxBackups: 3,
			MaxAge:     7,
		},
	}
}

// LoadFromFile loads configuration from a file.
func LoadFromFile(path string, config *Config) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open config file: %w", err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	// Determine file format based on extension
	switch {
	case strings.HasSuffix(path, ".json"):
		if err := json.Unmarshal(data, config); err != nil {
			return fmt.Errorf("failed to parse JSON config: %w", err)
		}
	case strings.HasSuffix(path, ".yaml"), strings.HasSuffix(path, ".yml"):
		if err := yaml.Unmarshal(data, config); err != nil {
			return fmt.Errorf("failed to parse YAML config: %w", err)
		}
	default:
		return fmt.Errorf("unsupported config file format: %s", path)
	}

	return nil
}

// LoadFromEnv loads configuration from environment variables.
func LoadFromEnv(config *Config) {
	// Router config
	if val := os.Getenv("ROUTER_TUN_NAME"); val != "" {
		config.Router.TUNName = val
	}
	if val := os.Getenv("ROUTER_TUN_IP"); val != "" {
		config.Router.TUNIP = val
	}
	if val := os.Getenv("ROUTER_TUN_SUBNET"); val != "" {
		config.Router.TUNSubnet = val
	}
	if val := os.Getenv("ROUTER_TUN_MTU"); val != "" {
		if mtu, err := strconv.Atoi(val); err == nil {
			config.Router.TUNMTU = mtu
		}
	}
	if val := os.Getenv("ROUTER_SOCKET_IP"); val != "" {
		config.Router.SocketIP = val
	}
	if val := os.Getenv("ROUTER_DEBUG"); val != "" {
		config.Router.Debug = val == "true" || val == "1"
	}

	// WireGuard config
	if val := os.Getenv("WIREGUARD_PRIVATE_KEY"); val != "" {
		config.WireGuard.PrivateKey = val
	}
	if val := os.Getenv("WIREGUARD_LISTEN_PORT"); val != "" {
		if port, err := strconv.Atoi(val); err == nil {
			config.WireGuard.ListenPort = port
		}
	}
	if val := os.Getenv("WIREGUARD_DISABLE_SOURCE_VALIDATION"); val != "" {
		config.WireGuard.DisableSourceValidation = val == "true" || val == "1"
	}

	// Logging config
	if val := os.Getenv("LOGGING_LEVEL"); val != "" {
		config.Logging.Level = val
	}
	if val := os.Getenv("LOGGING_FILE"); val != "" {
		config.Logging.File = val
	}
	if val := os.Getenv("LOGGING_MAX_SIZE"); val != "" {
		if maxSize, err := strconv.Atoi(val); err == nil {
			config.Logging.MaxSize = maxSize
		}
	}
	if val := os.Getenv("LOGGING_MAX_BACKUPS"); val != "" {
		if maxBackups, err := strconv.Atoi(val); err == nil {
			config.Logging.MaxBackups = maxBackups
		}
	}
	if val := os.Getenv("LOGGING_MAX_AGE"); val != "" {
		if maxAge, err := strconv.Atoi(val); err == nil {
			config.Logging.MaxAge = maxAge
		}
	}
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	// Validate Router config
	if c.Router.TUNName == "" {
		return fmt.Errorf("TUN name cannot be empty")
	}
	if net.ParseIP(c.Router.TUNIP) == nil {
		return fmt.Errorf("invalid TUN IP address: %s", c.Router.TUNIP)
	}
	// Validate subnet format (CIDR notation)
	_, _, err := net.ParseCIDR(c.Router.TUNSubnet)
	if err != nil {
		return fmt.Errorf("invalid TUN subnet (must be in CIDR notation, e.g., '192.168.1.0/24'): %w", err)
	}
	if c.Router.TUNMTU <= 0 {
		return fmt.Errorf("invalid TUN MTU: %d", c.Router.TUNMTU)
	}
	if net.ParseIP(c.Router.SocketIP) == nil {
		return fmt.Errorf("invalid Socket IP address: %s", c.Router.SocketIP)
	}

	// Validate WireGuard config
	if c.WireGuard.ListenPort <= 0 || c.WireGuard.ListenPort > 65535 {
		return fmt.Errorf("invalid WireGuard listen port: %d", c.WireGuard.ListenPort)
	}

	// Validate Logging config
	switch c.Logging.Level {
	case "debug", "info", "warn", "error":
		// Valid levels
	default:
		return fmt.Errorf("invalid logging level: %s", c.Logging.Level)
	}

	return nil
}

// ApplyLogging applies the logging configuration.
func (c *Config) ApplyLogging() error {
	// Set log level
	var level logging.Level
	switch c.Logging.Level {
	case "debug":
		level = logging.DebugLevel
	case "info":
		level = logging.InfoLevel
	case "warn":
		level = logging.WarnLevel
	case "error":
		level = logging.ErrorLevel
	default:
		level = logging.InfoLevel
	}
	logging.SetLevel(level)

	// Enable file logging if configured
	if c.Logging.File != "" {
		// Extract directory from file path
		dir := "."
		if lastSlash := strings.LastIndex(c.Logging.File, "/"); lastSlash != -1 {
			dir = c.Logging.File[:lastSlash]
		}

		// Get filename
		filename := c.Logging.File
		if lastSlash := strings.LastIndex(c.Logging.File, "/"); lastSlash != -1 {
			filename = c.Logging.File[lastSlash+1:]
		}

		err := logging.EnableFileLogging(
			dir,
			filename,
			c.Logging.MaxSize,
			c.Logging.MaxBackups,
			c.Logging.MaxAge,
		)
		if err != nil {
			return fmt.Errorf("failed to enable file logging: %w", err)
		}
	}

	return nil
}

// SaveToFile saves the configuration to a file.
func (c *Config) SaveToFile(path string) error {
	var data []byte
	var err error

	// Determine file format based on extension
	switch {
	case strings.HasSuffix(path, ".json"):
		data, err = json.MarshalIndent(c, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal config to JSON: %w", err)
		}
	case strings.HasSuffix(path, ".yaml"), strings.HasSuffix(path, ".yml"):
		data, err = yaml.Marshal(c)
		if err != nil {
			return fmt.Errorf("failed to marshal config to YAML: %w", err)
		}
	default:
		return fmt.Errorf("unsupported config file format: %s", path)
	}

	// Write a private temporary file beside the destination, then replace it.
	// Existing files are replaced rather than retaining permissive old modes.
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create configuration directory: %w", err)
	}
	f, err := os.CreateTemp(dir, ".wgslirp-config-*")
	if err != nil {
		return fmt.Errorf("create configuration file: %w", err)
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write configuration: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync configuration: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close configuration: %w", err)
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return fmt.Errorf("replace configuration: %w", err)
	}

	return nil
}
