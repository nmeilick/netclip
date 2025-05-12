package apikey

// GetSampleConfig returns a sample configuration for API keys
func GetSampleConfig() string {
	return `  # API keys
  api_key "admin_key" {
    key = "your_secure_admin_key"  # The actual API key value
    admin = true                   # Grant admin privileges
    # Optional per-key limits
    # limits {
    #   max_file_size = "1GB"      # Human readable format
    #   max_age = "90d"            # 90 days
    # }
  }

  api_key "user_key" {
    key = "your_secure_user_key"   # The actual API key value
    prefixes = ["user-"]           # Restrict to IDs with these prefixes
    # Example of key-specific limits
    # limits {
    #   max_file_size = "50MB"     # Human readable format
    #   max_age = "7d"             # 7 days
    # }
  }`
}
