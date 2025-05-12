// Package server provides the HTTP server implementation for the netclip application
//
//	@title			netclip API
//	@version		1.0
//	@description	API for netclip - a secure file sharing service
//	@termsOfService	http://swagger.io/terms/
//	@contact.name	API Support
//	@contact.email	support@netclip.io
//	@license.name	Apache 2.0
//	@license.url	http://www.apache.org/licenses/LICENSE-2.0.html
//	@host			localhost:8080
//	@BasePath		/api/v1
package server

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	swaggerFiles "github.com/swaggo/files"     // swagger embed files
	ginSwagger "github.com/swaggo/gin-swagger" // gin-swagger middleware

	"github.com/gin-gonic/gin"
	"github.com/nmeilick/netclip/config"
	_ "github.com/nmeilick/netclip/docs/swagger"
	"github.com/nmeilick/netclip/response"
	"github.com/nmeilick/netclip/server/acme"
	"github.com/nmeilick/netclip/server/certs"
	"github.com/nmeilick/netclip/server/clip"
	serverconfig "github.com/nmeilick/netclip/server/config"
	"github.com/nmeilick/netclip/server/config/apikey"
	"github.com/nmeilick/netclip/server/limits"
	"github.com/nmeilick/netclip/server/queue"

	"github.com/rs/zerolog"
	"github.com/urfave/cli/v2"
)

// Commands returns the CLI commands for the server functionality
func Commands() *cli.Command {
	return &cli.Command{
		Name:    "server",
		Aliases: []string{"s"},
		Usage:   "Run the netclip server",
		Subcommands: []*cli.Command{
			{
				Name:  "start",
				Usage: "Start the server",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "config",
						Usage: "Path to config file",
						Value: config.DefaultConfigFile,
					},
					&cli.BoolFlag{
						Name:    "foreground",
						Aliases: []string{"f"},
						Usage:   "Run in foreground",
					},
					&cli.BoolFlag{
						Name:    "generate-cert",
						Aliases: []string{"g"},
						Usage:   "Auto-generate TLS certificate if needed",
					},
				},
				Action: func(c *cli.Context) error {
					return startServer(c)
				},
			},
			certs.Commands(),
		},
		Action: func(c *cli.Context) error {
			return cli.ShowSubcommandHelp(c)
		},
	}
}

// Server represents the netclip server
type Server struct {
	Config          *serverconfig.Config
	Router          *gin.Engine
	StopCleanup     chan struct{}
	accessLogger    io.WriteCloser
	errorLogger     io.WriteCloser
	logger          zerolog.Logger
	configPath      string
	httpServer      *http.Server
	acmeMgr         *acme.Manager
	clipManager     *clip.Manager
	mainQueue       *queue.Queue
	perIPQueues     map[string]*queue.Queue
	perIPQueueMutex sync.Mutex
}

func startServer(c *cli.Context) error {
	// Set Gin to release mode in production
	if os.Getenv("DEBUG") != "1" {
		gin.SetMode(gin.ReleaseMode)
	}

	// Load configuration
	cfg, configPath, err := config.LoadServerConfig(c)
	if err != nil {
		return err
	}

	// Auto-generate TLS certificate if requested and TLS is configured
	var serverTLSCert, serverTLSKey string
	if cfg.Listen != nil {
		serverTLSCert = cfg.Listen.GetTLSCert()
		serverTLSKey = cfg.Listen.GetTLSKey()
	}

	if c.Bool("generate-cert") && serverTLSCert != "" && serverTLSKey != "" {
		// Check if certificate files already exist
		certExists := false
		keyExists := false

		if _, err := os.Stat(serverTLSCert); err == nil {
			certExists = true
		}
		if _, err := os.Stat(serverTLSKey); err == nil {
			keyExists = true
		}

		// Generate certificate if either file is missing
		if !certExists || !keyExists {
			fmt.Println("Auto-generating TLS certificate...")
			// Create directories if needed
			if err := os.MkdirAll(filepath.Dir(serverTLSCert), 0750); err != nil {
				return fmt.Errorf("failed to create certificate directory: %w", err)
			}
			if err := os.MkdirAll(filepath.Dir(serverTLSKey), 0750); err != nil {
				return fmt.Errorf("failed to create key directory: %w", err)
			}

			if err := certs.GenerateCertificateBundle(cfg); err != nil {
				return fmt.Errorf("failed to generate certificate: %w", err)
			}
		} else {
			fmt.Println("TLS certificate and key already exist, skipping generation")
		}
	}

	// Create server instance
	server := &Server{
		Config:      cfg,
		Router:      gin.New(),
		StopCleanup: make(chan struct{}),
		configPath:  configPath,
	}

	// Setup logging
	if err := server.SetupLogging(); err != nil {
		return fmt.Errorf("failed to setup logging: %w", err)
	}

	// Initialize server
	if err := server.initialize(); err != nil {
		return err
	}

	// Setup routes
	server.setupRoutes()

	// Start cleanup goroutine
	go server.cleanupRoutine()

	// Initialize ACME if configured
	if ac := cfg.ACME; ac != nil {
		mgr, err := acme.NewManager(cfg.ACME, server.logger)
		if err != nil {
			return fmt.Errorf("failed to initialize ACME: %w", err)
		}
		server.acmeMgr = mgr

		// Determine provider name based on directory URL
		providerName := "Default ACME provider"
		if ac.DirectoryURL != "" {
			providerName = "Custom ACME provider"
		} else if ac.UseStaging {
			providerName = "Default ACME provider (staging)"
		}

		server.logger.Info().
			Strs("domains", ac.Domains).
			Bool("staging", ac.UseStaging).
			Str("cache_dir", ac.CacheDir).
			Str("provider", providerName).
			Msg("ACME enabled")
	}

	// Create HTTP server
	// Get listen configuration
	if server.Config.Listen == nil {
		return fmt.Errorf("listen configuration is missing")
	}

	host := server.Config.Listen.Host
	port := server.Config.Listen.Port
	readTimeout := server.Config.Listen.GetReadTimeout()
	writeTimeout := server.Config.Listen.GetWriteTimeout()
	idleTimeout := server.Config.Listen.GetIdleTimeout()
	readHeaderTimeout := server.Config.Listen.GetReadHeaderTimeout()
	serverTLSCert = server.Config.Listen.GetTLSCert()
	serverTLSKey = server.Config.Listen.GetTLSKey()

	addr := fmt.Sprintf("%s:%d", host, port)
	server.httpServer = &http.Server{
		Addr:              addr,
		Handler:           server.Router,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		ReadHeaderTimeout: readHeaderTimeout,
	}

	// Setup signal handling
	server.HandleSignals(server.httpServer)

	// Start the server
	server.logger.Info().Str("address", addr).Msg("Starting server")

	var serverErr error

	// Determine which TLS mode to use
	if server.acmeMgr != nil && server.acmeMgr.IsEnabled() {
		// Use ACME
		server.httpServer.TLSConfig = server.acmeMgr.GetTLSConfig()
		server.logger.Info().Msg("Using ACME for TLS")
		serverErr = server.httpServer.ListenAndServeTLS("", "") // Empty strings because cert is provided by ACME
	} else if serverTLSCert != "" && serverTLSKey != "" {
		// Use static certificates
		server.logger.Info().
			Str("cert", serverTLSCert).
			Str("key", serverTLSKey).
			Msg("TLS enabled with static certificates")
		serverErr = server.httpServer.ListenAndServeTLS(serverTLSCert, serverTLSKey)
	} else {
		// No TLS
		serverErr = server.httpServer.ListenAndServe()
	}

	// If we get here, it's because of an error (or shutdown)
	if !errors.Is(serverErr, http.ErrServerClosed) {
		return serverErr
	}
	return nil
}

func (s *Server) initialize() error {
	// Initialize clip manager
	s.clipManager = clip.NewManager(s.Config, s.logger)

	if err := s.clipManager.Init(); err != nil {
		return fmt.Errorf("failed to initialize ClipManager: %w", err)
	}

	return nil
}

func (s *Server) setupRoutes() {
	// Add global middleware
	s.Router.Use(gin.Recovery())
	s.Router.Use(s.RequestIDMiddleware())
	s.Router.Use(s.SecurityMiddleware())
	s.Router.Use(s.GinLogger())
	s.Router.Use(s.APIKeyMiddleware()) // Apply API key validation to all routes

	// Add request queue middleware if configured
	if s.Config.RequestQueue != nil {
		s.setupRequestQueue()
		s.Router.Use(s.QueueMiddlewares()...)
	}

	// Setup Swagger documentation if not disabled
	if !s.Config.DisableSwagger {
		s.Router.GET("/swagger/*any", func(c *gin.Context) {
			param := c.Param("any")
			if param == "/" || param == "" {
				c.Redirect(http.StatusMovedPermanently, "/swagger/index.html")
				c.Abort()
				return
			}
			ginSwagger.WrapHandler(swaggerFiles.Handler)(c)
		})
	}

	// Determine API prefix
	apiPrefix := "/api/v1"
	if s.Config.APIPrefix != "" {
		prefix := "/" + strings.Trim(s.Config.APIPrefix, "/")
		apiPrefix = filepath.Join(prefix, "/api/v1")
	}

	// API routes
	api := s.Router.Group(apiPrefix)

	// Limits endpoint
	api.GET("/limits", s.handleGetLimits)

	// Clip endpoints with ID validation
	clipRoutes := api.Group("/clips", s.ValidateIDMiddleware())
	clipRoutes.GET("/:id", s.clipManager.HandleDownloadClip)
	clipRoutes.GET("/:id/metadata", s.clipManager.HandleGetMetadata)
	clipRoutes.POST("/:id", s.clipManager.HandleUploadClip)
}

// handleGetLimits godoc
//
//	@Summary		Get applicable limits for the requestor
//	@Description	Returns the limits that apply to the current request based on API key or server defaults
//	@Tags			limits
//	@Accept			json
//	@Produce		json
//	@Param			X-API-Key	header		string					false	"API Key for authentication"
//	@Success		200			{object}	response.LimitsResponse	"Limits for the requestor"
//	@Router			/limits [get]
func (s *Server) handleGetLimits(c *gin.Context) {
	// Create the response struct
	response := response.LimitsResponse{}

	// Determine effective max file size
	var maxFileSize int64

	// Check if we have an API key with specific limits
	keyConfig, hasKey := c.Get("api_key")
	if hasKey {
		apiKey := keyConfig.(*apikey.APIKey)
		if apiKey.Limits != nil {
			maxFileSize = apiKey.Limits.GetMaxFileSize()
		}
	}

	// If no API key specific limit, use server limits
	if maxFileSize == 0 && s.Config.Limits != nil {
		maxFileSize = s.Config.Limits.GetMaxFileSize()
	}

	// Fall back to default if needed
	if maxFileSize == 0 {
		maxFileSize = limits.DefaultMaxFileSize
	}

	response.MaxFileSize = maxFileSize

	// Determine effective max age
	var maxAge time.Duration

	if hasKey {
		apiKey := keyConfig.(*apikey.APIKey)
		if apiKey.Limits != nil {
			maxAge = apiKey.Limits.GetMaxAge()
		}
	}

	// If no API key specific limit, use server limit
	if maxAge == 0 && s.Config.Limits != nil {
		maxAge = s.Config.Limits.GetMaxAge()
	}

	// Set max age in seconds if it's greater than zero
	if maxAge > 0 {
		response.MaxAgeSecs = int64(maxAge.Seconds())
	}

	c.JSON(http.StatusOK, response)
}

// setupRequestQueue initializes the request queue system
func (s *Server) setupRequestQueue() {
	cfg := s.Config.RequestQueue
	if cfg == nil {
		return
	}

	if cfg.Global != nil {
		l := s.logger.With().Str("component", "queue").Logger()
		s.mainQueue = queue.NewQueue("global", queue.WithConfig(cfg.Global), queue.WithLogger(l))
		s.logger.Info().
			Int("max_concurrent", cfg.Global.MaxConcurrent).
			Int("max_queue_size", cfg.Global.MaxQueueSize).
			Str("max_wait_time", cfg.Global.MaxWaitTime).
			Msg("Global request queue initialized")
	}

	if cfg.IP != nil {
		s.perIPQueues = map[string]*queue.Queue{}
		s.logger.Info().
			Int("max_concurrent", cfg.IP.MaxConcurrent).
			Int("max_queue_size", cfg.IP.MaxQueueSize).
			Str("max_wait_time", cfg.IP.MaxWaitTime).
			Msg("Per-IP request queue initialized")
	}
}

func (s *Server) isAdminKey(apiKey string) bool {
	for i := range s.Config.APIKeys {
		k := &s.Config.APIKeys[i]
		if k.Key == apiKey && k.Admin {
			return true
		}
	}
	return false
}

func hasAdminKey(c *gin.Context) bool {
	if apiKey, exists := c.Get("api_key"); exists {
		if key, ok := apiKey.(*apikey.APIKey); ok && key.Admin {
			return true
		}
	}
	return false
}

// QueueMiddleware returns a middleware that applies request queueing
func (s *Server) QueueMiddlewares() []gin.HandlerFunc {
	var funcs []gin.HandlerFunc

	if s.mainQueue != nil {
		funcs = append(funcs, func(c *gin.Context) {
			if hasAdminKey(c) {
				// Skip queue for admin API keys
				c.Next()
				return
			}
			s.mainQueue.Middleware()(c)
		})
	}

	if s.perIPQueues != nil {
		funcs = append(funcs, func(c *gin.Context) {
			if hasAdminKey(c) {
				// Skip queue for admin API keys
				c.Next()
				return
			}

			// Get client IP
			clientIP := c.ClientIP()

			// Get or create per-IP queue
			s.perIPQueueMutex.Lock()
			ipQueue, exists := s.perIPQueues[clientIP]
			if !exists {
				l := s.logger.With().Str("component", "queue").Logger()
				// Create new queue for this IP
				ipQueue = queue.NewQueue("ip:"+clientIP,
					queue.WithConfig(s.Config.RequestQueue.IP),
					queue.WithLogger(l),
				)
				s.perIPQueues[clientIP] = ipQueue
			}
			s.perIPQueueMutex.Unlock()

			// Use the per-IP queue's middleware
			ipQueue.Middleware()(c)
		})
	}
	return funcs
}

func (s *Server) cleanupRoutine() {
	ticker := time.NewTicker(s.Config.GetCleanupEvery())
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.clipManager.Cleanup()
		case <-s.StopCleanup:
			return
		}
	}
}
