package acme

// GetSampleConfig returns a sample configuration for ACME
func GetSampleConfig() string {
	return `  # ACME automatic certificates
  acme {
    domains = ["example.com", "www.example.com"]
    email = "admin@example.com"  # Optional but recommended
    cache_dir = "/var/lib/netclip/certs/acme"

    # ACME directory URL (optional, defaults to Let's Encrypt)
    # directory_url = "https://acme.zerossl.com/v2/DV90"  # Example for ZeroSSL

    use_staging = false  # Set to true for testing
    renew_before = "720h"  # 30 days

    # Challenge configuration (optional)
    challenge_type = "http"  # Only HTTP-01 challenge is supported

    # HTTP challenge options
    http_port = 80  # Custom port for HTTP challenge server
    disable_http_server = false  # Set to true to disable standalone HTTP server
  }`
}
