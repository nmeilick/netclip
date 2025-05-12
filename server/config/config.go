package config

import (
	"errors"
	"fmt"
	"time"

	"github.com/nmeilick/netclip/common/duration"
	acmeconfig "github.com/nmeilick/netclip/server/acme/config"
	"github.com/nmeilick/netclip/server/config/apikey"
	"github.com/nmeilick/netclip/server/limits"
	"github.com/nmeilick/netclip/server/listen"
	"github.com/nmeilick/netclip/server/log"
	"github.com/nmeilick/netclip/server/queue"
	"github.com/nmeilick/netclip/server/security"
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
	DefaultStoragePath     = ""
	DefaultDefaultTTL      = 24 * time.Hour
	DefaultCleanupEvery    = 10 * time.Minute
	DefaultMaxFileSize     = "1GB"
	DefaultMaxAge          = "168h" // 7 days
	DefaultLogDir          = ""
	DefaultAccessLog       = "access.log"
	DefaultErrorLog        = "error.log"
	DefaultLogMaxSize      = 100 // MB
	DefaultLogMaxBackups   = 5
	DefaultLogMaxAge       = 30 // days
	DefaultLogCompress     = true
)

// RequestQueue holds the request-queue configurations
type RequestQueue struct {
	Global *queue.QueueConfig `hcl:"global,block"`
	IP     *queue.QueueConfig `hcl:"ip,block"`
}

// Validate RequestQueue configuration
func (rq *RequestQueue) Validate() error {
	if rq == nil {
		return errors.New("RequestQueue is nil")
	}

	if rq.Global != nil {
		if err := rq.Global.Validate(); err != nil {
			return err
		}
	}
	if rq.IP != nil {
		if err := rq.IP.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// Normalize RequestQueue configuration
func (rq *RequestQueue) Normalize() error {
	if rq != nil {
		if rq.Global != nil {
			if err := rq.Global.Normalize(); err != nil {
				return err
			}
		}
		if rq.IP != nil {
			if err := rq.IP.Normalize(); err != nil {
				return err
			}
		}
	}
	return rq.Validate()
}

// DefaultConfig returns a server configuration with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Listen:         listen.DefaultConfig(),
		StoragePath:    DefaultStoragePath,
		DefaultTTL:     duration.String(DefaultDefaultTTL),
		CleanupEvery:   duration.String(DefaultCleanupEvery),
		Limits:         limits.DefaultConfig(),
		Log:            log.DefaultConfig(),
		Security:       security.DefaultConfig(),
		APIPrefix:      "",
		DisableSwagger: false,
	}
}

// Config holds the server-specific configuration
type Config struct {
	Listen         *listen.Config           `hcl:"listen,block"`
	StoragePath    string                   `hcl:"storage_path,optional"`
	DefaultTTL     string                   `hcl:"default_ttl,optional"`
	CleanupEvery   string                   `hcl:"cleanup_every,optional"`
	ACME           *acmeconfig.Config       `hcl:"acme,block"`
	Log            *log.LogConfig           `hcl:"log,block"`
	APIPrefix      string                   `hcl:"api_prefix,optional"`
	DisableSwagger bool                     `hcl:"disable_swagger,optional"`
	RequireAPIKey  bool                     `hcl:"require_api_key,optional"`
	Security       *security.SecurityConfig `hcl:"security,block"`
	Limits         *limits.Limits           `hcl:"limits,block"`
	APIKeys        []apikey.APIKey          `hcl:"api_key,block"`
	RequestQueue   *RequestQueue            `hcl:"requestqueue,block"`

	// Parsed durations
	parsedDefaultTTL   time.Duration
	parsedCleanupEvery time.Duration
}

// Normalize sets default values for vital settings that haven't been set
// and then validates the configuration
func (sc *Config) Normalize() error {
	// Set default storage path if not specified
	if sc.StoragePath == "" {
		sc.StoragePath = DefaultStoragePath
	}

	// Set default Listen configuration if not specified
	if sc.Listen == nil {
		sc.Listen = &listen.Config{}
	}
	// Normalize Listen config
	sc.Listen.Normalize()

	// Parse and set default TTL values
	var err error
	if sc.DefaultTTL != "" {
		sc.parsedDefaultTTL, err = duration.Parse(sc.DefaultTTL)
		if err != nil {
			return fmt.Errorf("invalid default_ttl: %w", err)
		}
	}
	if sc.parsedDefaultTTL <= 0 {
		sc.parsedDefaultTTL = DefaultDefaultTTL
	}

	if sc.CleanupEvery != "" {
		sc.parsedCleanupEvery, err = duration.Parse(sc.CleanupEvery)
		if err != nil {
			return fmt.Errorf("invalid cleanup_every: %w", err)
		}
	}
	if sc.parsedCleanupEvery <= 0 {
		sc.parsedCleanupEvery = DefaultCleanupEvery
	}

	// Set default Limits if not specified
	if sc.Limits == nil {
		sc.Limits = &limits.Limits{
			MaxFileSize: DefaultMaxFileSize,
			MaxAge:      DefaultMaxAge,
		}
	}
	// Normalize limits
	sc.Limits.Normalize()

	// Set default Log configuration if not specified
	if sc.Log == nil {
		sc.Log = &log.LogConfig{}
	}
	// Normalize Log config
	sc.Log.Normalize()

	// Set default Security config if not specified
	if sc.Security == nil {
		sc.Security = &security.SecurityConfig{}
	}
	// Normalize Security config
	sc.Security.Normalize()

	// Normalize ACME config if present
	if sc.ACME != nil {
		sc.ACME.Normalize()
	}

	// Normalize request queue config if present
	if sc.RequestQueue != nil {
		if sc.RequestQueue.Global != nil {
			sc.RequestQueue.Global.Normalize()
		}
		if sc.RequestQueue.IP != nil {
			sc.RequestQueue.IP.Normalize()
		}
	}

	// Normalize API keys
	for i := range sc.APIKeys {
		sc.APIKeys[i].Normalize()
	}

	// Validate the configuration after normalization
	return sc.Validate()
}

// GetDefaultTTL returns the parsed default TTL duration
func (sc *Config) GetDefaultTTL() time.Duration {
	return sc.parsedDefaultTTL
}

// GetCleanupEvery returns the parsed cleanup interval duration
func (sc *Config) GetCleanupEvery() time.Duration {
	return sc.parsedCleanupEvery
}

// Validate checks the server configuration for errors or missing required settings
func (sc *Config) Validate() error {
	// Check for required storage path
	if sc.StoragePath == "" {
		return fmt.Errorf("storage_path is required")
	}

	// Validate Listen configuration
	if sc.Listen == nil {
		return fmt.Errorf("listen configuration is required")
	}
	if err := sc.Listen.Validate(); err != nil {
		return fmt.Errorf("listen configuration error: %w", err)
	}

	// Validate ACME configuration if enabled
	if sc.ACME != nil {
		if err := sc.ACME.Validate(); err != nil {
			return fmt.Errorf("ACME configuration error: %w", err)
		}

		// Check for conflicts with static TLS certificates
		if sc.Listen.GetTLSCert() != "" || sc.Listen.GetTLSKey() != "" {
			return fmt.Errorf("cannot specify both ACME and static TLS certificates")
		}
	}

	// Validate Log configuration
	if sc.Log == nil {
		return fmt.Errorf("log configuration is required")
	}
	if err := sc.Log.Validate(); err != nil {
		return fmt.Errorf("log configuration error: %w", err)
	}

	// Validate Limits
	if sc.Limits != nil {
		if err := sc.Limits.Validate(); err != nil {
			return fmt.Errorf("limits validation error: %w", err)
		}
	}

	// Validate Security configuration
	if sc.Security != nil {
		if err := sc.Security.Validate(); err != nil {
			return fmt.Errorf("security configuration error: %w", err)
		}
	}

	// Validate RequestQueue configuration
	if sc.RequestQueue != nil {
		if err := sc.RequestQueue.Validate(); err != nil {
			return fmt.Errorf("request queue configuration error: %w", err)
		}
	}

	// Validate API keys
	apiKeyMap := make(map[string]bool)
	for i, key := range sc.APIKeys {
		// Check for duplicate API keys
		if apiKeyMap[key.Key] {
			return fmt.Errorf("duplicate API key: %s", key.Key)
		}
		apiKeyMap[key.Key] = true

		// Validate API key
		if err := sc.APIKeys[i].Validate(); err != nil {
			return fmt.Errorf("API key validation error: %w", err)
		}
	}

	return nil
}
