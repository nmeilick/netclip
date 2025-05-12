package log

// GetSampleConfig returns a sample configuration for logging
func GetSampleConfig() string {
	return `  # Logging configuration
  log {
    log_dir = "/var/log/netclip"    # Directory for log files
    access_log = "access.log"       # Access log filename
    error_log = "error.log"         # Error log filename
    log_max_size = 100              # Maximum size in MB before rotation
    log_max_backups = 5             # Number of old log files to keep
    log_max_age = 30                # Days to keep old log files
    log_compress = true             # Compress rotated log files with gzip
  }`
}
