package log

import "fmt"

// Default configuration constants
const (
	DefaultLogDir        = "/var/log/netclip"
	DefaultAccessLog     = "access.log"
	DefaultErrorLog      = "error.log"
	DefaultLogMaxSize    = 100 // MB
	DefaultLogMaxBackups = 5
	DefaultLogMaxAge     = 30 // days
	DefaultLogCompress   = true
)

// LogConfig defines configuration for server logging
type LogConfig struct {
	// LogDir is the directory where log files are stored
	LogDir string `hcl:"log_dir,optional"`

	// AccessLog is the filename for the access log
	AccessLog string `hcl:"access_log,optional"`

	// ErrorLog is the filename for the error log
	ErrorLog string `hcl:"error_log,optional"`

	// LogMaxSize is the maximum size of log files in megabytes before rotation
	LogMaxSize int `hcl:"log_max_size,optional"`

	// LogMaxBackups is the maximum number of old log files to retain
	LogMaxBackups int `hcl:"log_max_backups,optional"`

	// LogMaxAge is the maximum number of days to retain old log files
	LogMaxAge int `hcl:"log_max_age,optional"`

	// LogCompress determines if rotated log files should be compressed
	LogCompress bool `hcl:"log_compress,optional"`
}

// DefaultConfig returns a new LogConfig with default values
func DefaultConfig() *LogConfig {
	return &LogConfig{
		LogDir:        DefaultLogDir,
		AccessLog:     DefaultAccessLog,
		ErrorLog:      DefaultErrorLog,
		LogMaxSize:    DefaultLogMaxSize,
		LogMaxBackups: DefaultLogMaxBackups,
		LogMaxAge:     DefaultLogMaxAge,
		LogCompress:   DefaultLogCompress,
	}
}

// Normalize sets default values for vital settings that haven't been set
func (cfg *LogConfig) Normalize() error {
	// Fill in missing values with defaults
	if cfg.LogDir == "" {
		cfg.LogDir = DefaultLogDir
	}
	if cfg.AccessLog == "" {
		cfg.AccessLog = DefaultAccessLog
	}
	if cfg.ErrorLog == "" {
		cfg.ErrorLog = DefaultErrorLog
	}
	if cfg.LogMaxSize <= 0 {
		cfg.LogMaxSize = DefaultLogMaxSize
	}
	if cfg.LogMaxBackups <= 0 {
		cfg.LogMaxBackups = DefaultLogMaxBackups
	}
	if cfg.LogMaxAge <= 0 {
		cfg.LogMaxAge = DefaultLogMaxAge
	}
	if !cfg.LogCompress {
		cfg.LogCompress = DefaultLogCompress
	}
	return cfg.Validate()
}

// Validate checks the log configuration for errors
func (cfg *LogConfig) Validate() error {
	if cfg.LogDir == "" {
		return fmt.Errorf("log directory is required")
	}
	return nil
}
