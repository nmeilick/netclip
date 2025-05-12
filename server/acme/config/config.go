package config

import (
	"fmt"
	"time"

	"github.com/nmeilick/netclip/common/duration"
)

// Config defines configuration for ACME certificate providers
type Config struct {
	// Domains is a list of domains to obtain certificates for
	Domains []string `hcl:"domains,optional"`

	// Email is the contact email for the ACME provider
	Email string `hcl:"email,optional"`

	// CacheDir is where certificates are stored
	CacheDir string `hcl:"cache_dir,optional"`

	// DirectoryURL is the ACME directory URL for custom ACME providers
	DirectoryURL string `hcl:"directory_url,optional"`

	// UseStaging determines if the staging server should be used
	UseStaging bool `hcl:"use_staging,optional"`

	// RenewBefore is how long before expiry to renew certificates
	RenewBefore string `hcl:"renew_before,optional"`

	// ChallengeType specifies the ACME challenge type (only "http" is supported)
	ChallengeType string `hcl:"challenge_type,optional"`

	// HTTPPort is the port for the HTTP-01 challenge server (default: 80)
	HTTPPort int `hcl:"http_port,optional"`

	// DisableHTTPServer disables the standalone HTTP server for challenges
	DisableHTTPServer bool `hcl:"disable_http_server,optional"`
	
	// Parsed durations
	parsedRenewBefore time.Duration
}

// Normalize sets default values for ACME configuration
func (ac *Config) Normalize() error {
	var err error
	
	// Parse renew before duration
	if ac.RenewBefore != "" {
		ac.parsedRenewBefore, err = duration.Parse(ac.RenewBefore)
		if err != nil {
			return fmt.Errorf("invalid renew_before: %w", err)
		}
	}
	
	// Set default renewal period if not specified
	if ac.parsedRenewBefore <= 0 {
		ac.parsedRenewBefore = 30 * 24 * time.Hour // 30 days
	}

	// Set default challenge type to HTTP-01
	if ac.ChallengeType == "" || ac.ChallengeType != "http" {
		ac.ChallengeType = "http"
	}

	// Set default HTTP port if not specified
	if ac.HTTPPort <= 0 {
		ac.HTTPPort = 80
	}

	return ac.Validate()
}

// GetRenewBefore returns the parsed renew before duration
func (ac *Config) GetRenewBefore() time.Duration {
	return ac.parsedRenewBefore
}

// Validate checks the ACME configuration for errors
func (ac *Config) Validate() error {
	if len(ac.Domains) == 0 {
		return fmt.Errorf("at least one domain must be specified when ACME is enabled")
	}

	// Validate HTTP port is in valid range
	if ac.HTTPPort <= 0 || ac.HTTPPort > 65535 {
		return fmt.Errorf("invalid HTTP port: %d (must be between 1 and 65535)", ac.HTTPPort)
	}

	// Validate challenge type
	if ac.ChallengeType != "http" {
		return fmt.Errorf("unsupported challenge type: %s (only 'http' is supported)", ac.ChallengeType)
	}

	return nil
}
