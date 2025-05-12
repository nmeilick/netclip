package limits

// GetSampleConfig returns a sample configuration for limits
func GetSampleConfig() string {
	return `  # Resource limits configuration
  limits {
    max_file_size = "1GB"    # Human readable format (1 gigabyte)
    max_age = "30d"          # Human readable format (30 days)
                             # Can also use "720h", "1m", etc.
  }`
}
