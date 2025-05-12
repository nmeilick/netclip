package security

import (
	"fmt"
	"time"

	"github.com/nmeilick/netclip/common/duration"
)

// Default security configuration constants
const (
	DefaultHSTSMaxAge            = 180 * 24 * time.Hour // 180 days
	DefaultHSTSIncludeSubdomains = true
	DefaultXContentTypeOptions   = true
	DefaultCacheControl          = "no-store, max-age=0"
)

// SecurityConfig defines the configuration for basic security headers
type SecurityConfig struct {
	// HSTS settings
	HSTSMaxAge            string `hcl:"hsts_max_age,optional"`
	HSTSIncludeSubdomains bool   `hcl:"hsts_include_subdomains,optional"`

	// X-Content-Type-Options
	XContentTypeOptions bool `hcl:"x_content_type_options,optional"`

	// Cache-Control
	CacheControl string `hcl:"cache_control,optional"`
	
	// Parsed durations
	parsedHSTSMaxAge time.Duration
}

// DefaultConfig returns a new SecurityConfig with default values
func DefaultConfig() *SecurityConfig {
	return &SecurityConfig{
		HSTSMaxAge:            duration.String(DefaultHSTSMaxAge),
		HSTSIncludeSubdomains: DefaultHSTSIncludeSubdomains,
		XContentTypeOptions:   DefaultXContentTypeOptions,
		CacheControl:          DefaultCacheControl,
	}
}

// Normalize sets default values for vital settings that haven't been set
func (cfg *SecurityConfig) Normalize() error {
	var err error
	
	// Parse HSTS max age
	if cfg.HSTSMaxAge != "" {
		cfg.parsedHSTSMaxAge, err = duration.Parse(cfg.HSTSMaxAge)
		if err != nil {
			return fmt.Errorf("invalid hsts_max_age: %w", err)
		}
	}
	
	// Set default HSTS settings
	if cfg.parsedHSTSMaxAge <= 0 {
		cfg.parsedHSTSMaxAge = DefaultHSTSMaxAge
	}
	if !cfg.HSTSIncludeSubdomains {
		cfg.HSTSIncludeSubdomains = DefaultHSTSIncludeSubdomains
	}

	// Set default X-Content-Type-Options
	if !cfg.XContentTypeOptions {
		cfg.XContentTypeOptions = DefaultXContentTypeOptions
	}

	// Set default Cache-Control
	if cfg.CacheControl == "" {
		cfg.CacheControl = DefaultCacheControl
	}

	return cfg.Validate()
}

// GetHSTSMaxAge returns the parsed HSTS max age duration
func (cfg *SecurityConfig) GetHSTSMaxAge() time.Duration {
	return cfg.parsedHSTSMaxAge
}

// Validate checks the security configuration for errors
func (cfg *SecurityConfig) Validate() error {
	// No validation needed for security config
	return nil
}
