package server

import (
	"fmt"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nmeilick/netclip/common/duration"
	"github.com/nmeilick/netclip/server/security"
)

// For compatibility with existing code
type SecurityConfig = security.SecurityConfig

// DefaultSecurityConfig returns a security configuration with sensible defaults
func DefaultSecurityConfig() *SecurityConfig {
	return &SecurityConfig{
		// HSTS defaults
		HSTSMaxAge:            duration.String(180 * 24 * time.Hour), // 180 days
		HSTSIncludeSubdomains: true,

		// X-Content-Type-Options defaults
		XContentTypeOptions: true,

		// Cache-Control defaults
		CacheControl: "no-store, max-age=0",
	}
}

// buildHSTSHeader builds the Strict-Transport-Security header value
func buildHSTSHeader(sc *SecurityConfig) string {
	maxAge := int64(sc.GetHSTSMaxAge().Seconds())
	value := "max-age=" + fmt.Sprintf("%d", maxAge)

	if sc.HSTSIncludeSubdomains {
		value += "; includeSubDomains"
	}

	return value
}

// SecurityMiddleware returns a Gin middleware that adds security headers
func (s *Server) SecurityMiddleware() gin.HandlerFunc {
	// Use default config if not configured
	var securityConfig *SecurityConfig
	if s.Config.Security != nil {
		securityConfig = s.Config.Security
	} else {
		securityConfig = DefaultSecurityConfig()
	}

	return func(c *gin.Context) {
		// Add Strict-Transport-Security header if using HTTPS
		if c.Request.TLS != nil || strings.HasPrefix(c.Request.Proto, "HTTP/2") {
			c.Header("Strict-Transport-Security", buildHSTSHeader(securityConfig))
		}

		// Add X-Content-Type-Options header if enabled
		if securityConfig.XContentTypeOptions {
			c.Header("X-Content-Type-Options", "nosniff")
		}

		// Add Cache-Control header if configured
		if securityConfig.CacheControl != "" {
			c.Header("Cache-Control", securityConfig.CacheControl)
		}

		c.Next()
	}
}
