package response

// LimitsResponse represents the server limits response
type LimitsResponse struct {
	MaxFileSize int64 `json:"max_file_size"`
	MaxAgeSecs  int64 `json:"max_age_seconds,omitempty"`
}
