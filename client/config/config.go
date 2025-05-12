package config

import (
	"fmt"
	"time"

	"github.com/xhit/go-str2duration/v2"
)

// Default configuration constants
const (
	DefaultServerURL         = "https://localhost:8080"
	DefaultConnectionTimeout = 20 * time.Second
	DefaultMetadataTimeout   = 10 * time.Second
)

// Config holds the client-specific configuration
type Config struct {
	ServerURL         string `hcl:"server_url,optional"`
	APIKey            string `hcl:"api_key,optional"`
	UpdateToken       string `hcl:"update_token,optional"`
	Password          string `hcl:"password,optional"`
	PasswordLength    int    `hcl:"password_length,optional"`
	IDLength          int    `hcl:"id_length,optional"`
	UpdateTokenLength int    `hcl:"update_token_length,optional"`
	TLSSkipVerify     bool   `hcl:"tls_skip_verify,optional"`
	TLSCert           string `hcl:"tls_cert,optional"`
	TLSKey            string `hcl:"tls_key,optional"`
	TLSCA             string `hcl:"tls_ca,optional"`
	ProxyURL          string `hcl:"proxy_url,optional"`
	ConnectionTimeout string `hcl:"connection_timeout,optional"`
	MetadataTimeout   string `hcl:"metadata_timeout,optional"`
	DisableQRCode     bool   `hcl:"disable_qr_code,optional"`

	// Parsed durations
	parsedConnectionTimeout time.Duration
	parsedMetadataTimeout   time.Duration
}

// DefaultConfig returns a new Config with default values
func DefaultConfig() *Config {
	return &Config{
		ServerURL:         DefaultServerURL,
		ConnectionTimeout: "20s",
		MetadataTimeout:   "10s",
		DisableQRCode:     false, // Default is to show the QR code
		PasswordLength:    16,    // Default password length
		IDLength:          11,    // Default ID length
		UpdateTokenLength: 15,    // Default update token length

		parsedConnectionTimeout: DefaultConnectionTimeout,
		parsedMetadataTimeout:   DefaultMetadataTimeout,
	}
}

// Normalize sets default values for vital settings that haven't been set
func (c *Config) Normalize() error {
	var err error

	// Set default server URL if not specified
	if c.ServerURL == "" {
		c.ServerURL = DefaultServerURL
	}

	// Parse connection timeout
	if c.ConnectionTimeout != "" {
		c.parsedConnectionTimeout, err = str2duration.ParseDuration(c.ConnectionTimeout)
		if err != nil {
			return fmt.Errorf("invalid connection_timeout: %w", err)
		}
	}
	if c.parsedConnectionTimeout <= 0 {
		c.parsedConnectionTimeout = DefaultConnectionTimeout
	}

	// Parse metadata timeout
	if c.MetadataTimeout != "" {
		c.parsedMetadataTimeout, err = str2duration.ParseDuration(c.MetadataTimeout)
		if err != nil {
			return fmt.Errorf("invalid metadata_timeout: %w", err)
		}
	}
	if c.parsedMetadataTimeout <= 0 {
		c.parsedMetadataTimeout = DefaultMetadataTimeout
	}

	return c.Validate()
}

// GetConnectionTimeout returns the parsed connection timeout duration
func (c *Config) GetConnectionTimeout() time.Duration {
	return c.parsedConnectionTimeout
}

// GetMetadataTimeout returns the parsed metadata timeout duration
func (c *Config) GetMetadataTimeout() time.Duration {
	return c.parsedMetadataTimeout
}

// Validate checks the client configuration for errors
func (c *Config) Validate() error {
	// Validate server URL
	if c.ServerURL == "" {
		return fmt.Errorf("server URL is required")
	}

	// Validate TLS configuration if provided
	if c.TLSCert != "" && c.TLSKey == "" {
		return fmt.Errorf("TLS key file must be specified when TLS certificate is provided")
	}
	if c.TLSKey != "" && c.TLSCert == "" {
		return fmt.Errorf("TLS certificate file must be specified when TLS key is provided")
	}

	return nil
}
