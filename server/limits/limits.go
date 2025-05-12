package limits

import (
	"fmt"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/xhit/go-str2duration/v2"
)

// Default limits constants
const (
	DefaultMaxFileSize = 1 * 1024 * 1024 * 1024 // 1GB
	DefaultMaxAge      = 7 * 24 * time.Hour     // 7 days
)

// Limits defines resource limits for clips
type Limits struct {
	MaxFileSize string `hcl:"max_file_size,optional"`
	MaxAge      string `hcl:"max_age,optional"`

	// Parsed values (not serialized to HCL)
	parsedMaxFileSize int64
	parsedMaxAge      time.Duration
	parsed            bool
}

// DefaultConfig returns a new Limits struct with default values
func DefaultConfig() *Limits {
	return &Limits{
		MaxFileSize: humanize.Bytes(DefaultMaxFileSize),
		MaxAge:      DefaultMaxAge.String(),
	}
}

// Normalize sets default values for unset fields and validates the configuration
func (l *Limits) Normalize() error {
	// Set default values if not specified
	if l.MaxFileSize == "" {
		l.MaxFileSize = humanize.Bytes(DefaultMaxFileSize)
	}
	if l.MaxAge == "" {
		l.MaxAge = DefaultMaxAge.String()
	}

	// Validate the configuration
	return l.Validate()
}

// Validate checks if the limits are valid and parses the values
func (l *Limits) Validate() error {
	var err error

	if l.MaxFileSize != "" {
		l.parsedMaxFileSize, err = l.ParseMaxFileSize()
		if err != nil {
			return err
		}
	} else {
		l.parsedMaxFileSize = DefaultMaxFileSize
	}

	if l.MaxAge != "" {
		l.parsedMaxAge, err = l.ParseMaxAge()
		if err != nil {
			return err
		}
	} else {
		l.parsedMaxAge = DefaultMaxAge
	}

	l.parsed = true
	return nil
}

// GetMaxFileSize returns the parsed max file size
func (l *Limits) GetMaxFileSize() int64 {
	if !l.parsed {
		if err := l.Validate(); err != nil {
			// Return default on error
			return DefaultMaxFileSize
		}
	}
	return l.parsedMaxFileSize
}

// GetMaxAge returns the parsed max age
func (l *Limits) GetMaxAge() time.Duration {
	if !l.parsed {
		if err := l.Validate(); err != nil {
			// Return default on error
			return DefaultMaxAge
		}
	}
	return l.parsedMaxAge
}

// ParseMaxFileSize parses the MaxFileSize string into bytes
func (l *Limits) ParseMaxFileSize() (int64, error) {
	if l.MaxFileSize == "" {
		return DefaultMaxFileSize, nil
	}

	bytes, err := humanize.ParseBytes(l.MaxFileSize)
	if err != nil {
		return 0, fmt.Errorf("invalid max_file_size: %w", err)
	}

	return int64(bytes), nil
}

// ParseMaxAge parses the MaxAge string into a duration
func (l *Limits) ParseMaxAge() (time.Duration, error) {
	if l.MaxAge == "" {
		return DefaultMaxAge, nil
	}

	// Use str2duration for more flexible parsing
	duration, err := str2duration.ParseDuration(l.MaxAge)
	if err != nil {
		return 0, fmt.Errorf("invalid max_age: %w", err)
	}

	return duration, nil
}
