package server

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/handlers"
	"github.com/mattn/go-colorable"
	"github.com/nmeilick/netclip/common"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gopkg.in/natefinch/lumberjack.v2"
)

// SetupLogging configures request and error logging
func (s *Server) SetupLogging() error {
	// Get log configuration
	if s.Config.Log == nil {
		return fmt.Errorf("log configuration is missing")
	}

	logDir := s.Config.Log.LogDir
	accessLog := s.Config.Log.AccessLog
	errorLog := s.Config.Log.ErrorLog
	logMaxSize := s.Config.Log.LogMaxSize
	logMaxBackups := s.Config.Log.LogMaxBackups
	logMaxAge := s.Config.Log.LogMaxAge
	logCompress := s.Config.Log.LogCompress

	// Create log directory if it doesn't exist
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	// Setup access log
	accessLogPath := filepath.Join(logDir, accessLog)
	s.accessLogger = &lumberjack.Logger{
		Filename:   accessLogPath,
		MaxSize:    logMaxSize,
		MaxBackups: logMaxBackups,
		MaxAge:     logMaxAge,
		Compress:   logCompress,
	}

	// Setup error log
	errorLogPath := filepath.Join(logDir, errorLog)
	s.errorLogger = &lumberjack.Logger{
		Filename:   errorLogPath,
		MaxSize:    logMaxSize,
		MaxBackups: logMaxBackups,
		MaxAge:     logMaxAge,
		Compress:   logCompress,
	}

	// Configure zerolog
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zerolog.TimestampFunc = func() time.Time {
		return time.Now().UTC()
	}

	// Setup console writer with colors if stdout is a TTY
	var consoleWriter io.Writer
	if common.IsTTY(os.Stdout) {
		consoleWriter = zerolog.ConsoleWriter{
			Out:        colorable.NewColorableStdout(),
			TimeFormat: "2006-01-02 15:04:05.000",
			NoColor:    false,
		}
	} else {
		consoleWriter = os.Stdout
	}

	// Create multi-writer for console and file
	multi := zerolog.MultiLevelWriter(consoleWriter, s.errorLogger)

	// Set global logger
	log.Logger = zerolog.New(multi).With().
		Timestamp().
		Str("service", "netclip").
		Logger()

	// Set server logger
	s.logger = log.Logger

	// Log startup message
	s.logger.Info().Msg("Server starting up")

	return nil
}

// LoggingMiddleware adds request logging
func (s *Server) LoggingMiddleware(handler http.Handler) http.Handler {
	return handlers.LoggingHandler(s.accessLogger, handler)
}

// GinLogger returns a gin middleware for request logging
func (s *Server) GinLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery

		c.Next()

		end := time.Now()

		clientIP := c.ClientIP()
		method := c.Request.Method
		statusCode := c.Writer.Status()

		if query != "" {
			path = path + "?" + query
		}

		// Log in Common Log Format to the access logger
		fmt.Fprintf(s.accessLogger, "%s - - [%s] \"%s %s %s\" %d %d \"%s\" \"%s\"\n",
			clientIP,
			end.Format("02/Jan/2006:15:04:05 -0700"),
			method,
			path,
			c.Request.Proto,
			statusCode,
			c.Writer.Size(),
			c.Request.Referer(),
			c.Request.UserAgent(),
		)
	}
}

// LogError logs an error message
func (s *Server) LogError(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	s.logger.Error().Msg(msg)
}
