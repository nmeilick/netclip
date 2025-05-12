package response

const (
	defaultErrorMessage = "unknown error"
)

// Error represents a standardized API error response
type Error struct {
	Error struct {
		Message   string `json:"message"`
		RequestID string `json:"requestId"`
	} `json:"error"`
}

// NewError creates a new error response with the given message
func NewError(requestID string, message string) Error {
	resp := Error{}
	resp.Error.Message = message
	resp.Error.RequestID = requestID

	return resp
}
