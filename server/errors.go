package server

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/nmeilick/netclip/response"
)

// ErrorHandler is a helper function to return standardized error responses
func ErrorHandler(c *gin.Context, statusCode int, message string) {
	if message == "" {
		if message = http.StatusText(statusCode); message == "" {
			message = "unknown error"
		}
	}
	requestID := c.GetString(RequestIDHeader)
	c.JSON(statusCode, response.NewError(requestID, message))
}

// This function is exported for use by the clip package
func GetRequestIDHeader() string {
	return RequestIDHeader
}
