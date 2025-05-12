package queue

// GetSampleConfig returns a sample configuration for request queue
func GetSampleConfig() string {
	return `  # Request queue settings
  requestqueue {
    # Global queue settings (applied to all non-admin requests)
    global {
      max_concurrent = 1000     # Maximum concurrent requests server-wide
      max_queue_size = 5000     # Maximum requests waiting in the global queue
      max_wait_time = "30s"     # Maximum time a request waits in the global queue
    }
    
    # Per-IP queue settings (applied after global queue)
    ip {
      max_concurrent = 20       # Maximum concurrent requests per source IP
      max_queue_size = 100      # Maximum requests waiting per IP queue
      max_wait_time = "15s"     # Maximum time a request waits in the per-IP queue
    }
  }`
}
