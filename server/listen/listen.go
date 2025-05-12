package listen

import (
	"fmt"
	"time"

	"github.com/nmeilick/netclip/common/duration"
)

// Default configuration constants
const (
	DefaultHost            = "127.0.0.1"
	DefaultPort            = 8080
	DefaultReadTimeout     = 10 * time.Second
	DefaultWriteTimeout    = 30 * time.Second
	DefaultIdleTimeout     = 120 * time.Second
	DefaultHeaderTimeout   = 5 * time.Second
	DefaultGracefulTimeout = 30 * time.Second
)

// Config defines configuration for server listening
type Config struct {
	// Host is the interface to listen on
	Host string `hcl:"host,optional"`

	// Port is the port to listen on
	Port int `hcl:"port,optional"`

	// DisableServerHeader disables the Server header in responses
	DisableServerHeader bool `hcl:"disable_server_header,optional"`

	// Timeouts configuration
	Timeouts *TimeoutsConfig `hcl:"timeouts,block"`

	// TLS configuration
	TLS *TLSConfig `hcl:"tls,block"`

	// Parsed durations (kept for backward compatibility)
	parsedReadTimeout       time.Duration
	parsedWriteTimeout      time.Duration
	parsedIdleTimeout       time.Duration
	parsedReadHeaderTimeout time.Duration
	parsedGracefulTimeout   time.Duration
}

// TimeoutsConfig defines timeout settings for the server
type TimeoutsConfig struct {
	// ReadTimeout is the maximum duration for reading the entire request
	ReadTimeout string `hcl:"read,optional"`

	// WriteTimeout is the maximum duration before timing out writes of the response
	WriteTimeout string `hcl:"write,optional"`

	// IdleTimeout is the maximum amount of time to wait for the next request
	IdleTimeout string `hcl:"idle,optional"`

	// ReadHeaderTimeout is the amount of time allowed to read request headers
	ReadHeaderTimeout string `hcl:"read_header,optional"`

	// GracefulTimeout is the duration for which the server gracefully waits for existing connections to finish
	GracefulTimeout string `hcl:"graceful,optional"`

	// Parsed durations
	parsedReadTimeout       time.Duration
	parsedWriteTimeout      time.Duration
	parsedIdleTimeout       time.Duration
	parsedReadHeaderTimeout time.Duration
	parsedGracefulTimeout   time.Duration
}

// TLSConfig defines TLS settings for the server
type TLSConfig struct {
	// Cert is the path to the TLS certificate file
	Cert string `hcl:"cert,optional"`

	// Key is the path to the TLS key file
	Key string `hcl:"key,optional"`

	// ClientCA is the path to the client CA certificate file for mutual TLS
	ClientCA string `hcl:"client_ca,optional"`

	// RequireClientCert requires client certificates for mutual TLS
	RequireClientCert bool `hcl:"require_client_cert,optional"`
}

// DefaultConfig returns a new Config with default values
func DefaultConfig() *Config {
	return &Config{
		Host:                DefaultHost,
		Port:                DefaultPort,
		DisableServerHeader: false,
		Timeouts: &TimeoutsConfig{
			ReadTimeout:       duration.String(DefaultReadTimeout),
			WriteTimeout:      duration.String(DefaultWriteTimeout),
			IdleTimeout:       duration.String(DefaultIdleTimeout),
			ReadHeaderTimeout: duration.String(DefaultHeaderTimeout),
			GracefulTimeout:   duration.String(DefaultGracefulTimeout),
		},
		TLS: &TLSConfig{},
	}
}

// Normalize sets default values for vital settings that haven't been set
func (cfg *Config) Normalize() error {
	// Fill in missing values with defaults
	if cfg.Host == "" {
		cfg.Host = DefaultHost
	}
	if cfg.Port <= 0 {
		cfg.Port = DefaultPort
	}

	// Initialize timeouts if not set
	if cfg.Timeouts == nil {
		cfg.Timeouts = &TimeoutsConfig{
			ReadTimeout:       duration.String(DefaultReadTimeout),
			WriteTimeout:      duration.String(DefaultWriteTimeout),
			IdleTimeout:       duration.String(DefaultIdleTimeout),
			ReadHeaderTimeout: duration.String(DefaultHeaderTimeout),
			GracefulTimeout:   duration.String(DefaultGracefulTimeout),
		}
	}

	// Initialize TLS if not set
	if cfg.TLS == nil {
		cfg.TLS = &TLSConfig{}
	}

	// Normalize timeouts
	if err := cfg.normalizeTimeouts(); err != nil {
		return err
	}

	return cfg.Validate()
}

// normalizeTimeouts parses and sets default values for timeouts
func (cfg *Config) normalizeTimeouts() error {
	var err error

	// Parse durations from Timeouts block
	if cfg.Timeouts.ReadTimeout != "" {
		cfg.Timeouts.parsedReadTimeout, err = duration.Parse(cfg.Timeouts.ReadTimeout)
		if err != nil {
			return fmt.Errorf("invalid read timeout: %w", err)
		}
	}
	if cfg.Timeouts.parsedReadTimeout <= 0 {
		cfg.Timeouts.parsedReadTimeout = DefaultReadTimeout
	}

	if cfg.Timeouts.WriteTimeout != "" {
		cfg.Timeouts.parsedWriteTimeout, err = duration.Parse(cfg.Timeouts.WriteTimeout)
		if err != nil {
			return fmt.Errorf("invalid write timeout: %w", err)
		}
	}
	if cfg.Timeouts.parsedWriteTimeout <= 0 {
		cfg.Timeouts.parsedWriteTimeout = DefaultWriteTimeout
	}

	if cfg.Timeouts.IdleTimeout != "" {
		cfg.Timeouts.parsedIdleTimeout, err = duration.Parse(cfg.Timeouts.IdleTimeout)
		if err != nil {
			return fmt.Errorf("invalid idle timeout: %w", err)
		}
	}
	if cfg.Timeouts.parsedIdleTimeout <= 0 {
		cfg.Timeouts.parsedIdleTimeout = DefaultIdleTimeout
	}

	if cfg.Timeouts.ReadHeaderTimeout != "" {
		cfg.Timeouts.parsedReadHeaderTimeout, err = duration.Parse(cfg.Timeouts.ReadHeaderTimeout)
		if err != nil {
			return fmt.Errorf("invalid read header timeout: %w", err)
		}
	}
	if cfg.Timeouts.parsedReadHeaderTimeout <= 0 {
		cfg.Timeouts.parsedReadHeaderTimeout = DefaultHeaderTimeout
	}

	if cfg.Timeouts.GracefulTimeout != "" {
		cfg.Timeouts.parsedGracefulTimeout, err = duration.Parse(cfg.Timeouts.GracefulTimeout)
		if err != nil {
			return fmt.Errorf("invalid graceful timeout: %w", err)
		}
	}
	if cfg.Timeouts.parsedGracefulTimeout <= 0 {
		cfg.Timeouts.parsedGracefulTimeout = DefaultGracefulTimeout
	}

	// Set the main config's parsed durations for backward compatibility
	cfg.parsedReadTimeout = cfg.Timeouts.parsedReadTimeout
	cfg.parsedWriteTimeout = cfg.Timeouts.parsedWriteTimeout
	cfg.parsedIdleTimeout = cfg.Timeouts.parsedIdleTimeout
	cfg.parsedReadHeaderTimeout = cfg.Timeouts.parsedReadHeaderTimeout
	cfg.parsedGracefulTimeout = cfg.Timeouts.parsedGracefulTimeout

	return nil
}

// GetReadTimeout returns the parsed read timeout duration
func (cfg *Config) GetReadTimeout() time.Duration {
	if cfg.Timeouts != nil {
		return cfg.Timeouts.parsedReadTimeout
	}
	return cfg.parsedReadTimeout
}

// GetWriteTimeout returns the parsed write timeout duration
func (cfg *Config) GetWriteTimeout() time.Duration {
	if cfg.Timeouts != nil {
		return cfg.Timeouts.parsedWriteTimeout
	}
	return cfg.parsedWriteTimeout
}

// GetIdleTimeout returns the parsed idle timeout duration
func (cfg *Config) GetIdleTimeout() time.Duration {
	if cfg.Timeouts != nil {
		return cfg.Timeouts.parsedIdleTimeout
	}
	return cfg.parsedIdleTimeout
}

// GetReadHeaderTimeout returns the parsed read header timeout duration
func (cfg *Config) GetReadHeaderTimeout() time.Duration {
	if cfg.Timeouts != nil {
		return cfg.Timeouts.parsedReadHeaderTimeout
	}
	return cfg.parsedReadHeaderTimeout
}

// GetGracefulTimeout returns the parsed graceful timeout duration
func (cfg *Config) GetGracefulTimeout() time.Duration {
	if cfg.Timeouts != nil {
		return cfg.Timeouts.parsedGracefulTimeout
	}
	return cfg.parsedGracefulTimeout
}

// GetTLSCert returns the TLS certificate path
func (cfg *Config) GetTLSCert() string {
	if cfg.TLS != nil {
		return cfg.TLS.Cert
	}
	return ""
}

// GetTLSKey returns the TLS key path
func (cfg *Config) GetTLSKey() string {
	if cfg.TLS != nil {
		return cfg.TLS.Key
	}
	return ""
}

// GetTLSClientCA returns the TLS client CA path
func (cfg *Config) GetTLSClientCA() string {
	if cfg.TLS != nil {
		return cfg.TLS.ClientCA
	}
	return ""
}

// GetTLSRequireClientCert returns whether client certificates are required
func (cfg *Config) GetTLSRequireClientCert() bool {
	if cfg.TLS != nil {
		return cfg.TLS.RequireClientCert
	}
	return false
}

// Validate checks the listen configuration for errors
func (cfg *Config) Validate() error {
	// Validate port range
	if cfg.Port <= 0 || cfg.Port > 65535 {
		return fmt.Errorf("invalid port number: %d (must be between 1 and 65535)", cfg.Port)
	}

	// Validate TLS configuration if provided
	if cfg.TLS != nil {
		if cfg.TLS.Cert != "" && cfg.TLS.Key == "" {
			return fmt.Errorf("TLS key file must be specified when TLS certificate is provided")
		}
		if cfg.TLS.Key != "" && cfg.TLS.Cert == "" {
			return fmt.Errorf("TLS certificate file must be specified when TLS key is provided")
		}

		// Validate mutual TLS configuration
		if cfg.TLS.RequireClientCert && cfg.TLS.ClientCA == "" {
			return fmt.Errorf("client CA certificate must be specified when client certificates are required")
		}
	}

	return nil
}
