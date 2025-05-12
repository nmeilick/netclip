# netclip configuration file
# This is a sample configuration demonstrating many available options.

# Server configuration block
server {
  # Server listening configuration
  listen {
    host = "0.0.0.0"            # Interface to listen on (e.g., "0.0.0.0" for all, "127.0.0.1" for local only)
    port = 8080                 # Port to listen on

    # Timeouts are now in the timeouts block

    # TLS configuration (optional, for HTTPS)
    tls {
      # cert = "/etc/netclip/certs/server.crt" # Path to TLS certificate file
      # key = "/etc/netclip/certs/server.key"  # Path to TLS private key file
      # client_ca = "/etc/netclip/certs/ca.crt" # Path to CA cert for client certificate validation (mTLS)
      # require_client_cert = false            # Require client certificates (mTLS)
    }

    # Timeouts configuration
    timeouts {
      read = "10s"        # Max duration for reading the entire request
      write = "30s"       # Max duration before timing out writes of the response
      idle = "120s"       # Max time to wait for the next request on a keep-alive connection
      read_header = "5s"  # Max time allowed to read request headers
      graceful = "30s"    # Time allowed for existing connections to finish during shutdown
    }

    # Misc options
    disable_server_header = false # Set to true to hide the 'Server: netclip/x.y.z' header
  }

  # Path where clip data and metadata will be stored
  storage_path = "/var/lib/netclip"

  # Default time-to-live for clips if not specified during upload
  default_ttl = "24h" # e.g., "7d", "30m", "never"

  # How often the server checks for and removes expired clips
  cleanup_every = "1h"

  ## ACME automatic certificates (optional, alternative to static tls_cert/tls_key)
  #acme {
  #  # Enable ACME by providing domains
  #  domains = ["example.com", "www.example.com"] # Domains to obtain certificates for
  #  email = "admin@example.com"                  # Contact email for ACME provider (recommended)
  #  cache_dir = "/var/lib/netclip/certs/acme"    # Directory to store ACME certificates
  #
  #  # ACME directory URL (optional, defaults to Let's Encrypt production)
  #  # directory_url = "https://acme-staging-v02.api.letsencrypt.org/directory" # Let's Encrypt staging
  #  # directory_url = "https://acme.zerossl.com/v2/DV90"                      # Example for ZeroSSL
  #
  #  use_staging = false  # Set to true for testing against the ACME staging environment
  #  renew_before = "720h" # Renew certificate 30 days (720h) before expiry
  #
  #  # Challenge configuration
  #  challenge_type = "http" # Only HTTP-01 challenge is supported currently
  #
  #  # HTTP challenge options
  #  http_port = 80             # Port for the temporary HTTP server used for challenges
  #  disable_http_server = false # Set true if another process handles challenges on http_port
  #}

  # Logging configuration
  log {
    log_dir = "/var/log/netclip" # Directory for log files
    access_log = "access.log"    # Access log filename
    error_log = "error.log"      # Error log filename
    log_max_size = 100           # Maximum size in MB before rotation
    log_max_backups = 5          # Number of old log files to keep
    log_max_age = 30             # Days to keep old log files
    log_compress = true          # Compress rotated log files (e.g., with gzip)
  }

  # Optional prefix for all API endpoints (e.g., "/netclip")
  api_prefix = ""

  # Set to true to disable the Swagger UI endpoint (/swagger/index.html)
  disable_swagger = false

  # Set to true to require a valid API key for all requests
  # When enabled, any request without a valid API key will be rejected with 401 Unauthorized
  require_api_key = false

  # Basic security headers configuration
  security {
    # HTTP Strict Transport Security (HSTS) - only sent over HTTPS
    hsts_max_age = "365d"            # How long browsers should remember to only use HTTPS (e.g., "365d")
    hsts_include_subdomains = true   # Apply HSTS to subdomains as well

    # X-Content-Type-Options header (adds "nosniff")
    x_content_type_options = true

    # Cache-Control header for API responses
    cache_control = "no-store, max-age=0" # Default: prevent caching
  }

  # Default resource limits (can be overridden per API key)
  limits {
    max_file_size = "1GB" # Max allowed upload size (e.g., "100MB", "2GB")
    max_age = "30d"       # Max allowed expiration time (e.g., "7d", "90d", "never")
  }

  # API keys for authentication and authorization
  # The label ("admin_key", "user_key") is just an identifier in the config.
  #api_key "admin_key" {
  #  key = "your_secure_admin_api_key_here" # The actual API key string
  #  admin = true                           # Grants administrative privileges
  #  # prefixes = ["admin-"]                # Optional: Restrict this key to IDs starting with "admin-"
  #  # Optional per-key limits override server defaults
  #  # limits {
  #  #   max_file_size = "10GB"
  #  #   max_age = "never"
  #  # }
  #}

  #api_key "user_key" {
  #  key = "another_secure_user_api_key"
  #  admin = false
  #  prefixes = ["user-", "projectX-"] # Allow this key for IDs starting with "user-" or "projectX-"
  #  # Example of key-specific limits
  #  limits {
  #    max_file_size = "500MB"
  #    max_age = "7d"
  #  }
  #}

  # Request queue settings (optional)
  requestqueue {
    # Global queue settings (applied to all non-admin requests first)
    global {
      max_concurrent = 1000     # Max concurrent requests server-wide
      max_queue_size = 5000     # Max requests waiting in the global queue
      max_wait_time = "30s"     # Max time a request waits in the global queue
    }

    # Per-IP queue settings (applied after global queue)
    ip {
      max_concurrent = 20       # Max concurrent requests per source IP address
      max_queue_size = 100      # Max requests waiting in the queue for a single IP
      max_wait_time = "15s"     # Max time a request waits in the per-IP queue
    }
  }
}

# Client configuration block
# Most parameters can be overridden on the command line or via env variables.
client {
  # URL of the netclip server
  server_url = "https://localhost:8080" # Use the actual server URL

  # Default API key to use for client operations
  # api_key = "user_key"

  # Default update token to use for updating existing clips
  # update_token = "some_update_token"

  # Default password (used if --encrypt is specified without --password)
  # password = "secret"

  # Default lengths for generated values
  password_length = 12
  id_length = 11
  update_token_length = 15

  tls_skip_verify = false    # Set true to disable server certificate verification (INSECURE!)

  # Client TLS configuration (for mutual TLS)
  # tls_cert = "/etc/netclip/client/cert.pem"  # Path to client certificate
  # tls_key = "/etc/netclip/client/key.pem"    # Path to client private key
  # tls_ca = "/etc/netclip/client/ca.pem"      # Path to CA certificate for server verification

  # Proxy configuration
  # proxy_url = "http://proxy.example.com:8080" # HTTP/HTTPS proxy URL

  # Timeouts
  connection_timeout = "10s" # Timeout for establishing a connection
  metadata_timeout = "20s"   # Timeout for metadata requests

  # UI options
  disable_qr_code = false    # Set true to disable QR code output by default
}
