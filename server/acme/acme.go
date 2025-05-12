package acme

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	config "github.com/nmeilick/netclip/server/acme/config"
	"github.com/rs/zerolog"
	cryptoacme "golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// Manager manages ACME certificates
type Manager struct {
	config      *config.Config
	certManager *autocert.Manager
	httpServer  *http.Server
	mutex       sync.Mutex
	logger      zerolog.Logger
}

// NewManager creates a new ACME certificate manager
func NewManager(cfg *config.Config, logger zerolog.Logger) (*Manager, error) {
	if cfg == nil {
		cfg = &config.Config{}
		cfg.Normalize()
	}

	// Set default cache directory if not specified
	if cfg.CacheDir == "" {
		// Use "acme" subdirectory in the default cert cache dir
		cacheDir, err := defaultCertCacheDir()
		if err != nil {
			return nil, fmt.Errorf("failed to determine default certificate cache directory: %w", err)
		}
		cfg.CacheDir = filepath.Join(cacheDir, "acme")
	} else if !filepath.IsAbs(cfg.CacheDir) {
		// If it's a relative path, make it absolute using the server's storage path
		storagePath := os.Getenv("NETCLIP_STORAGE_PATH")
		if storagePath == "" {
			// Try to get a reasonable default if environment variable isn't set
			storagePath, err := defaultCertCacheDir()
			if err != nil {
				return nil, fmt.Errorf("failed to determine base directory for relative cache path: %w", err)
			}
			storagePath = filepath.Dir(filepath.Dir(storagePath)) // Go up two levels from certs/acme
		}
		cfg.CacheDir = filepath.Join(storagePath, cfg.CacheDir)
	}

	// Create cache directory if it doesn't exist
	if err := os.MkdirAll(cfg.CacheDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create certificate cache directory %s: %w", cfg.CacheDir, err)
	}

	// Log the actual cache directory path
	logger.Info().Str("cache_dir", cfg.CacheDir).Msg("Using ACME certificate cache directory")

	// Normalize the config to ensure defaults are set
	cfg.Normalize()

	manager := &Manager{
		config: cfg,
		logger: logger.With().Str("component", "acme").Logger(),
	}

	// Initialize the cert manager if domains are configured
	if len(cfg.Domains) > 0 {
		if err := manager.initialize(); err != nil {
			return nil, err
		}
	}

	return manager, nil
}

// initialize sets up the autocert manager
func (m *Manager) initialize() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Validate configuration
	if len(m.config.Domains) == 0 {
		return fmt.Errorf("no domains specified for ACME")
	}

	// Create autocert manager
	certManager := &autocert.Manager{
		Prompt:      autocert.AcceptTOS,
		Cache:       autocert.DirCache(m.config.CacheDir),
		HostPolicy:  autocert.HostWhitelist(m.config.Domains...),
		RenewBefore: m.config.GetRenewBefore(),
	}

	// Set email if provided
	if m.config.Email != "" {
		certManager.Email = m.config.Email
	}

	// Use staging server, custom directory URL, or explicitly set the production URL
	// This ensures we're always using our explicitly defined URLs rather than
	// relying on the default behavior of the autocert library
	certManager.Client = &cryptoacme.Client{
		DirectoryURL: m.getDirectoryURL(),
	}

	m.certManager = certManager

	// Only HTTP-01 challenge is supported
	if !m.config.DisableHTTPServer {
		m.startChallengeServer()
	} else {
		m.logger.Info().Msg("HTTP challenge server disabled by configuration")
	}

	return nil
}

// startChallengeServer starts an HTTP server for ACME HTTP-01 challenge
func (m *Manager) startChallengeServer() {
	port := m.config.HTTPPort
	if port <= 0 {
		port = 80
	}

	m.httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: m.certManager.HTTPHandler(nil),
	}

	go func() {
		m.logger.Info().Int("port", port).Msg("Starting HTTP server for ACME challenges")
		if err := m.httpServer.ListenAndServe(); err != http.ErrServerClosed {
			m.logger.Error().Err(err).Msg("ACME HTTP challenge server error")
		}
	}()
}

// GetTLSConfig returns a TLS configuration using ACME
func (m *Manager) GetTLSConfig() *tls.Config {
	if m == nil || m.certManager == nil {
		return nil
	}

	return &tls.Config{
		GetCertificate: m.certManager.GetCertificate,
		NextProtos:     []string{"h2", "http/1.1"},
	}
}

// Stop stops the ACME manager and challenge server
func (m *Manager) Stop() {
	if m.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		m.httpServer.Shutdown(ctx)
	}
}

// defaultCertCacheDir returns the default directory for storing certificates
func defaultCertCacheDir() (string, error) {
	// Platform-specific defaults
	appName := "netclip" // Hardcoded to avoid import cycle
	switch runtime.GOOS {
	case "windows":
		programData := os.Getenv("ProgramData")
		if programData == "" {
			programData = filepath.Join("C:", "ProgramData")
		}
		return filepath.Join(programData, appName, "certs", "acme"), nil
	case "darwin":
		return filepath.Join("/Library/Application Support", appName, "certs", "acme"), nil
	default:
		// Linux/Unix defaults
		return filepath.Join("/var/lib", appName, "certs", "acme"), nil
	}
}

// IsEnabled returns whether ACME is enabled
func (m *Manager) IsEnabled() bool {
	return m.config != nil && len(m.config.Domains) > 0
}

// Constants for common ACME directory URLs
const (
	// Default production URLs
	DefaultACMEDirectoryURL = "https://acme-v02.api.letsencrypt.org/directory" // Let's Encrypt production

	// Default staging URLs
	DefaultACMEStagingURL = "https://acme-staging-v02.api.letsencrypt.org/directory" // Let's Encrypt staging
)

// getDirectoryURL returns the ACME directory URL
func (m *Manager) getDirectoryURL() string {
	// If a custom directory URL is specified, use it
	if m.config.DirectoryURL != "" {
		return m.config.DirectoryURL
	}

	// Otherwise use default URLs
	if m.config.UseStaging {
		m.logger.Info().Msg("Using staging environment")
		return DefaultACMEStagingURL
	}

	return DefaultACMEDirectoryURL
}
