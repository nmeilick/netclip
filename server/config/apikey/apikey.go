package apikey

import (
	"fmt"

	"github.com/nmeilick/netclip/server/limits"
)

// APIKey represents an API key configuration
type APIKey struct {
	Key      string         `hcl:"key,label"`
	Prefixes []string       `hcl:"prefixes,optional"`
	Admin    bool           `hcl:"admin,optional"`
	Limits   *limits.Limits `hcl:"limits,block"`
}

// Normalize sets default values for vital settings that haven't been set
func (ak *APIKey) Normalize() {
	// No default values needed for API keys

	// Normalize limits if present
	if ak.Limits != nil {
		if err := ak.Limits.Validate(); err == nil {
			// Only normalize if validation passes
			// (Validate also sets parsed values)
		}
	}
}

// Validate checks the API key configuration for errors
func (ak *APIKey) Validate() error {
	if ak.Key == "" {
		return fmt.Errorf("API key cannot be empty")
	}

	// Validate limits if present
	if ak.Limits != nil {
		if err := ak.Limits.Validate(); err != nil {
			return fmt.Errorf("invalid limits for API key %s: %w", ak.Key, err)
		}
	}

	return nil
}
