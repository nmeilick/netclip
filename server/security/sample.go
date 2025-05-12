package security

// GetSampleConfig returns a sample configuration for security settings
func GetSampleConfig() string {
	return `  # Security headers configuration
  security {
    # HTTP Strict Transport Security (HSTS) - only sent over HTTPS
    hsts_max_age = "180d"            # How long browsers should remember to use HTTPS
    hsts_include_subdomains = true   # Apply HSTS to subdomains as well
    
    # X-Content-Type-Options header
    x_content_type_options = true    # Adds "nosniff" to prevent MIME type sniffing
    
    # Cache-Control header for API responses
    cache_control = "no-store, max-age=0"  # Prevent caching of sensitive data
  }`
}
