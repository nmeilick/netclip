package server

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/nmeilick/netclip/common"
	"github.com/nmeilick/netclip/server/config/apikey"
)

const (
	// RequestIDHeader is the header key for request ID
	RequestIDHeader = "X-Request-ID"
	APIKeyHeader    = "X-API-Key"
)

// RequestIDMiddleware adds a unique request ID to each request
func (s *Server) RequestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Generate a new UUID for the request
		requestID := uuid.New().String()
		c.Request.Header.Set(RequestIDHeader, requestID)

		// Set the request ID in the context for handlers to use
		c.Set("requestID", requestID)

		// Add the request ID to the response headers
		c.Writer.Header().Set(RequestIDHeader, requestID)

		// Add Server header with app name and version unless disabled
		disableServerHeader := s.Config.Listen.DisableServerHeader

		if !disableServerHeader {
			c.Writer.Header().Set("Server", fmt.Sprintf("%s/%s", common.AppName, common.Version))
		}

		c.Next()
	}
}

// ValidateIDMiddleware validates the ID parameter in the request
func (s *Server) ValidateIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		if id == "" {
			s.logger.Warn().Str("id", id).Msg("Missing ID")
			ErrorHandler(c, http.StatusBadRequest, "Missing ID")
			c.Abort()
			return
		}

		if !common.IsValidID(id) {
			s.logger.Warn().Str("id", id).Msg("Invalid ID format")
			ErrorHandler(c, http.StatusBadRequest, "Invalid ID format")
			c.Abort()
			return
		}

		c.Next()
	}
}

// APIKeyMiddleware validates the API key in the request and sets effective limits
func (s *Server) APIKeyMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.Config.Limits != nil {
			if configMaxFileSize := s.Config.Limits.GetMaxFileSize(); configMaxFileSize > 0 {
				c.Set("max_file_size", configMaxFileSize)
			}
			if configMaxAge := s.Config.Limits.GetMaxAge(); configMaxAge > 0 {
				c.Set("max_age", configMaxAge)
			}
		}

		apiKey := c.GetHeader(APIKeyHeader)
		if apiKey == "" {
			// If API key is required but not provided, reject the request
			if s.Config.RequireAPIKey {
				s.logger.Warn().Str("path", c.Request.URL.Path).Msg("API key required but not provided")
				ErrorHandler(c, http.StatusUnauthorized, "API key required")
				c.Abort()
				return
			}
			c.Next()
			return
		}

		// Verify API key exists
		var keyConfig *apikey.APIKey
		for i := range s.Config.APIKeys {
			k := &s.Config.APIKeys[i] // Use pointer to avoid copying
			if k.Key == apiKey {
				keyConfig = k
				break
			}
		}

		if keyConfig == nil {
			s.logger.Warn().Str("api_key", apiKey).Msg("Invalid API key")
			ErrorHandler(c, http.StatusUnauthorized, "Invalid API key")
			c.Abort()
			return
		}

		// Store API key info in context for later use
		c.Set("api_key", keyConfig)

		// Set API key specific limits if available
		if keyConfig.Limits != nil {
			// Only override if the API key has specific limits set
			if keyMaxFileSize := keyConfig.Limits.GetMaxFileSize(); keyMaxFileSize > 0 {
				c.Set("max_file_size", keyMaxFileSize)
			}
			if keyMaxAge := keyConfig.Limits.GetMaxAge(); keyMaxAge > 0 {
				c.Set("max_age", keyMaxAge)
			}
		}

		c.Next()
	}
}

// RequireAdminMiddleware ensures the request has a valid admin API key
func (s *Server) RequireAdminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		keyConfig, exists := c.Get("api_key")
		if !exists {
			s.logger.Warn().Str("path", c.Request.URL.Path).Msg("Admin privileges required")
			ErrorHandler(c, http.StatusUnauthorized, "Admin privileges required")
			c.Abort()
			return
		}

		apiKey := keyConfig.(*apikey.APIKey)
		if !apiKey.Admin {
			s.logger.Warn().
				Str("api_key", apiKey.Key).
				Str("path", c.Request.URL.Path).
				Msg("Insufficient privileges")
			ErrorHandler(c, http.StatusForbidden, "Admin privileges required")
			c.Abort()
			return
		}

		c.Next()
	}
}
