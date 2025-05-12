package clip

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nmeilick/netclip/common"
	"github.com/nmeilick/netclip/response"
	serverconfig "github.com/nmeilick/netclip/server/config"
	"github.com/nmeilick/netclip/server/limits"
	"github.com/nmeilick/netclip/streampack"
	"github.com/rs/zerolog"
)

const (
	UpdateTokenFile = "update.token"
	MetaFile        = "meta.json"
	ClipFile        = "clip.spak"
)

// Manager handles clip operations
type Manager struct {
	Config      *serverconfig.Config
	Logger      zerolog.Logger
	uploadMutex sync.Map // Map of ID -> *sync.Mutex to protect concurrent uploads
}

// NewManager creates a new clip manager
func NewManager(cfg *serverconfig.Config, logger zerolog.Logger) *Manager {
	return &Manager{
		Config: cfg,
		Logger: logger.With().Str("component", "clip").Logger(),
	}
}

// Create directories for clip storage
func (m *Manager) Init() error {
	return m.ensureDirectories()
}

func (m *Manager) ensureDirectories() error {
	for _, dir := range []string{m.clipsPath()} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("failed to create directory: %q: %w", dir, err)
		}
	}
	return nil
}

// clipsPath returns the path to the clips directory
func (m *Manager) clipsPath(elem ...string) string {
	return filepath.Join(m.Config.StoragePath, "clips", filepath.Join(elem...))
}

func timestamp() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

// newUpload creates a new timestamped directory for an upload
func (m *Manager) newUpload(id string) (string, error) {
	path := m.clipsPath(id, timestamp())
	if err := os.MkdirAll(path, 0700); err != nil {
		return "", err
	}

	return path, nil
}

// ClipExists checks if a clip with the given ID exists
func (m *Manager) ClipExists(id string) bool {
	file := filepath.Join(m.clipsPath(id), "current", MetaFile)
	var meta response.ClipMetadata
	return common.LoadJSON(file, &meta) == nil
}

// HandleDownloadClip handles the request to download a clip
func (m *Manager) HandleDownloadClip(c *gin.Context) {
	id := c.Param("id")

	clipPath := m.clipsPath(id, "current")
	metaFile := filepath.Join(clipPath, MetaFile)
	var meta response.ClipMetadata
	if err := common.LoadJSON(metaFile, &meta); err != nil {
		m.Logger.Warn().Str("id", id).Msg("Clip not found")
		ErrorHandler(c, http.StatusNotFound, "Clip not found")
		return
	}

	if !meta.ExpiresAt.IsZero() && !meta.ExpiresAt.After(time.Now()) {
		m.Logger.Warn().Str("id", id).Msg("Clip is expired")
		ErrorHandler(c, http.StatusNotFound, "Clip is expired")
		return
	}

	clipFile := filepath.Join(clipPath, ClipFile)

	// Open the clip file
	file, err := os.Open(clipFile)
	if err != nil {
		m.Logger.Error().Err(err).Str("id", id).Str("path", clipFile).Msg("Failed to read clip")
		ErrorHandler(c, http.StatusInternalServerError, "Failed to read clip")
		return
	}
	defer file.Close()

	// Set content type header
	c.Header("Content-Type", "application/octet-stream")

	c.Header("X-Source", meta.Archive.Type)
	c.Header("X-Compression-Type", string(meta.Archive.CompressionType))
	c.Header("X-Encryption-Type", string(meta.Archive.EncryptionType))

	// Stream the file to the client
	c.File(clipFile)
}

// HandleUploadClip handles the request to upload a clip
func (m *Manager) HandleUploadClip(c *gin.Context) {
	id := c.Param("id")

	var rid string
	if v, exists := c.Get("requestID"); exists {
		rid, _ = v.(string)
	}
	log := m.Logger.With().Str("id", id).Str("client_ip", c.ClientIP()).Str("requestID", rid).Logger()

	// TODO: Check API key prefix restrictions

	// Acquire mutex for this ID to prevent concurrent uploads
	idMutexValue, _ := m.uploadMutex.LoadOrStore(id, &sync.Mutex{})
	idMutex := idMutexValue.(*sync.Mutex)

	// If we couldn't acquire the lock, another upload is in progress
	if !idMutex.TryLock() {
		log.Warn().Msg("Concurrent upload attempt rejected")
		ErrorHandler(c, http.StatusConflict, "Another upload for this ID is already in progress")
		return
	}

	// Release the mutex when we're done
	defer func() {
		idMutex.Unlock()
		m.uploadMutex.Delete(id)
	}()

	clipPath := m.clipsPath(id)
	// Get update token from header
	updateTokens := common.Tokens(c.GetHeader("X-Update-Token"))
	if len(updateTokens) > 5 {
		updateTokens = updateTokens[:5] // Slow down brute-force attacks
	}
	tokenFile := filepath.Join(clipPath, UpdateTokenFile)
	var updateToken string

	// If the ID directory already exists, check update permissions
	if _, err := os.Stat(clipPath); err == nil {
		// Only allow update with a valid token
		if len(updateTokens) > 0 {
			// Get stored token from ID directory
			storedToken, err := os.ReadFile(tokenFile)

			if err != nil {
				if os.IsNotExist(err) {
					m.Logger.Warn().Str("id", id).Msg("Update attempted but no token exists")
					ErrorHandler(c, http.StatusForbidden, "Update not allowed for this ID")
					return
				}
				m.Logger.Error().Err(err).Str("id", id).Msg("Failed to read update token")
				ErrorHandler(c, http.StatusInternalServerError, "Failed to check update token")
				return
			}

			storedTokenStr := strings.TrimRight(string(storedToken), "\r\n")

			// Check if any of the provided tokens match the stored token
			tokenValid := false
			for _, token := range updateTokens {
				if token == storedTokenStr {
					tokenValid = true
					updateToken = token
					break
				}
			}

			if !tokenValid {
				m.Logger.Warn().
					Str("id", id).
					Int("token_count", len(updateTokens)).
					Msg("Update token mismatch")
				ErrorHandler(c, http.StatusForbidden, "Missing or invalid update token")
				return
			}

			// Token matches, allow the update
			m.Logger.Info().Str("id", id).Msg("Update token verified, allowing update")
		} else {
			// No update token provided but ID exists
			m.Logger.Warn().
				Str("id", id).
				Msg("Attempt to use existing ID without update token")
			ErrorHandler(c, http.StatusForbidden, "ID already exists, update token required")
			return
		}
	}

	if updateToken == "" && len(updateTokens) > 0 {
		updateToken = updateTokens[0]
	}

	uploadPath, err := m.newUpload(id)
	if err != nil {
		log.Err(err).Msg("Failed to create upload directory")
		ErrorHandler(c, http.StatusInternalServerError, "Internal error creating upload directory")
		return
	}

	// Set cleanup function to remove the upload directory on error
	cleanup := func() {
		if c.Writer.Status() >= 400 {
			os.RemoveAll(uploadPath)
		}
	}
	defer func() { cleanup() }()

	// Create clip file in the timestamped directory
	clipFile := filepath.Join(uploadPath, ClipFile)
	file, err := os.Create(clipFile)
	if err != nil {
		m.Logger.Error().Err(err).Str("id", id).Str("path", clipFile).Msg("Failed to create clip file")
		ErrorHandler(c, http.StatusInternalServerError, "Failed to create clip file")
		return
	}
	defer file.Close()

	// Limit the reader to max_file_size to prevent excessive resource usage
	var reader io.Reader = c.Request.Body

	// Get max file size from context (set by APIKeyMiddleware)
	var maxFileSize int64 = limits.DefaultMaxFileSize
	if m.Config.Limits != nil {
		maxFileSize = m.Config.Limits.GetMaxFileSize()
	}

	if maxFileSizeAny, exists := c.Get("max_file_size"); exists {
		if size, ok := maxFileSizeAny.(int64); ok {
			maxFileSize = size
		}
	}

	if maxFileSize > 0 {
		reader = io.LimitReader(c.Request.Body, maxFileSize+1)
	}

	// Copy clip to file
	written, err := io.Copy(file, reader)
	if err != nil {
		m.Logger.Error().Err(err).Str("id", id).Msg("Failed to save clip")
		ErrorHandler(c, http.StatusInternalServerError, "Failed to save clip")
		return
	}

	// Handle expiration time
	now := time.Now()

	var expiresAt time.Time

	// Check if client specified an expiration time
	if expiresHeader := c.GetHeader("X-Expires"); expiresHeader == "" {
		expiresAt = now.Add(m.Config.GetDefaultTTL())
	} else if seconds, err := strconv.ParseInt(expiresHeader, 10, 64); err != nil {
		m.Logger.Error().Err(err).Str("id", id).Str("expiresHeader", expiresHeader).Msg("Invalid expires header")
		ErrorHandler(c, http.StatusBadRequest, "Invalid X-Expires header: "+expiresHeader)
		return
	} else {
		if seconds <= 0 {
		} else {
			expiresAt = now.Add(time.Duration(seconds) * time.Second)
		}
	}

	// Apply max_age from API key limits if present
	if maxAge, exists := c.Get("max_age"); exists {
		d := maxAge.(time.Duration)
		if d > 0 {
			maxExpires := now.Add(d)
			if expiresAt.After(maxExpires) {
				expiresAt = maxExpires
			}
		}
	}


	meta := response.ClipMetadata{
		ID:        id,
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
		Size:      written,
		Comment:   c.GetHeader("X-Comment"), // Read comment from header
	}
	if s := c.GetHeader("X-Uncompressed-Size"); s != "" {
		if n, err := strconv.ParseInt(s, 10, 64); err == nil && n >= 0 {
			meta.UncompressedSize = n
		}
	}

	// Extract metadata from the spak file
	spakFile, err := os.Open(clipFile)
	if err == nil {
		defer spakFile.Close()

		header, _, err := streampack.ReadHeader(spakFile)
		if err != nil {
			m.Logger.Warn().
				Err(err).
				Str("id", id).
				Str("client_ip", c.ClientIP()).
				Msg("Invalid SPAK format")
			ErrorHandler(c, http.StatusBadRequest, "Data not in SPAK format")
			return
		}
		meta.Archive = *header

		// Log the detected archive format
		m.Logger.Debug().
			Str("id", id).
			Str("archive_type", header.Type).
			Str("compression", string(header.CompressionType)).
			Bool("encrypted", header.EncryptionType != "").
			Msg("Detected archive format")
	}

	meta.Encrypted = (meta.Archive.EncryptionType != "")

	// Save metadata to the timestamped directory
	metaFile := filepath.Join(uploadPath, MetaFile)
	if err := common.SaveJSON(metaFile, meta); err != nil {
		m.Logger.Error().Err(err).Str("id", id).Msg("Failed to save metadata")
		ErrorHandler(c, http.StatusInternalServerError, "Failed to save metadata")
		return
	}

	// If update token was provided, save it in the parent ID directory
	if updateToken != "" {
		if err := common.Save([]byte(updateToken), tokenFile); err != nil {
			m.Logger.Error().Err(err).Str("id", id).Msg("Failed to save update token")
			ErrorHandler(c, http.StatusInternalServerError, "Failed to store data")
			return
		}
	}

	// Replace existing symlink with new one pointing to the timestamped directory
	currentLink := filepath.Join(clipPath, "current")
	tmpLink := currentLink + ".tmp"
	_ = os.Remove(tmpLink) // Ignore error if it doesn't exist
	if err := os.Symlink(filepath.Base(uploadPath), tmpLink); err != nil {
		log.Error().Err(err).Msg("Failed to create symbolic link")
		ErrorHandler(c, http.StatusInternalServerError, "Failed to create symbolic link")
		return
	}
	if err := os.Rename(tmpLink, currentLink); err != nil {
		log.Error().Err(err).Msg("Failed to rename symbolic link")
		ErrorHandler(c, http.StatusInternalServerError, "Failed to rename symbolic link")
		return
	}

	// Success - cancel cleanup
	cleanup = func() {}

	// Clean up any other directories that aren't the current one
	timestampDirs, err := os.ReadDir(clipPath)
	ts := filepath.Base(uploadPath)
	if err == nil {
		for _, dir := range timestampDirs {
			if !dir.IsDir() {
				continue
			}
			switch dir.Name() {
			case ts, "current":
				continue
			}

			path := filepath.Join(clipPath, dir.Name())

			// Remove other directories
			if err := os.RemoveAll(path); err != nil {
				m.Logger.Warn().Err(err).Str("path", path).Msg("Failed to remove old directory")
			}
		}
	}

	// Log detailed information about the uploaded clip
	logEvent := log.Info().
		Int64("size", written).
		Time("expires_at", expiresAt)

	// Add optional fields when available
	if meta.Archive.CompressionType != "" {
		logEvent.Str("compression", string(meta.Archive.CompressionType))
	}
	if meta.Archive.EncryptionType != "" {
		logEvent.Str("encryption", string(meta.Archive.EncryptionType))
	}
	if meta.UncompressedSize > 0 {
		logEvent.Int64("uncompressed_size", meta.UncompressedSize)
	}
	if updateToken != "" {
		logEvent.Bool("update_token_provided", true)
	}

	logEvent.Msg("Clip uploaded successfully")

	// Return success
	if updateToken != "" {
		c.Header("X-Update-Token", updateToken)
	}

	// Add the actual expiry duration to the response
	expiryDuration := expiresAt.Sub(now)
	c.Header("X-Expires", strconv.FormatInt(int64(expiryDuration.Seconds()), 10))

	logEvent.Msg("Clip expiry set")

	c.JSON(http.StatusCreated, map[string]string{
		"id": id,
	})
}

// HandleGetMetadata handles the request to get metadata for a clip
func (m *Manager) HandleGetMetadata(c *gin.Context) {
	id := c.Param("id")

	// Use the current symlink path
	clipPath := m.clipsPath(id, "current")
	metaFile := filepath.Join(clipPath, MetaFile)

	// Check if metadata exists
	if _, err := os.Stat(metaFile); os.IsNotExist(err) {
		m.Logger.Warn().Str("id", id).Msg("Metadata not found")
		ErrorHandler(c, http.StatusNotFound, "Metadata not found")
		return
	}

	// Read and validate metadata file
	metaData, err := os.ReadFile(metaFile)
	if err != nil {
		m.Logger.Error().Err(err).Str("id", id).Msg("Failed to read metadata")
		ErrorHandler(c, http.StatusInternalServerError, "Failed to read metadata")
		return
	}

	// Validate JSON format
	var meta map[string]interface{}
	if err := json.Unmarshal(metaData, &meta); err != nil {
		m.Logger.Error().Err(err).Str("id", id).Msg("Invalid metadata format")
		ErrorHandler(c, http.StatusInternalServerError, "Invalid metadata format")
		return
	}

	c.Data(http.StatusOK, "application/json", metaData)
}

// Cleanup removes expired clips and orphaned timestamp directories
func (m *Manager) Cleanup() {
	now := time.Now()
	var cleanedCount int
	var brokenLinks []string

	// First pass: Check all timestamp directories in clips/*/
	clipsDir := m.clipsPath()
	idPaths, err := os.ReadDir(clipsDir)
	if err != nil {
		m.Logger.Error().Err(err).Str("path", clipsDir).Msg("Failed to read clips directory during cleanup")
		return
	}

	// Map to track valid directories (those that are current or not expired)
	validPaths := make(map[string]bool)

	// Map to track which directories are pointed to by "current" symlinks
	currentTargets := make(map[string]bool)

	// First, find all "current" symlinks and their targets
	for _, idDirEntry := range idPaths {
		if !idDirEntry.IsDir() {
			continue
		}

		id := idDirEntry.Name()
		idPath := filepath.Join(clipsDir, id)
		currentLinkPath := filepath.Join(idPath, "current")

		// Check if the current symlink exists
		linkInfo, err := os.Lstat(currentLinkPath)
		if err == nil && linkInfo.Mode()&os.ModeSymlink != 0 {
			// Read the symlink to get the actual target directory
			targetDir, err := os.Readlink(currentLinkPath)
			if err == nil {
				// Resolve to absolute path if it's relative
				if !filepath.IsAbs(targetDir) {
					targetDir = filepath.Join(filepath.Dir(currentLinkPath), targetDir)
				}
				// Mark this directory as a current target
				currentTargets[targetDir] = true
				// Also mark it as valid
				validPaths[targetDir] = true
			} else {
				// Broken symlink, mark for removal
				brokenLinks = append(brokenLinks, currentLinkPath)
			}
		}
	}

	// Process all ID directories to check for expired clips and orphaned directories
	for _, idDirEntry := range idPaths {
		if !idDirEntry.IsDir() {
			continue
		}

		id := idDirEntry.Name()
		idPath := filepath.Join(clipsDir, id)

		// Read all timestamp directories
		timestampDirs, err := os.ReadDir(idPath)
		if err != nil {
			continue
		}

		for _, dirEntry := range timestampDirs {
			// Skip non-directories and the "current" symlink
			if !dirEntry.IsDir() || dirEntry.Name() == "current" {
				continue
			}

			dirPath := filepath.Join(idPath, dirEntry.Name())

			// If this directory is a current target, we already marked it as valid
			if currentTargets[dirPath] {
				continue
			}

			// Skip directories newer than 300 seconds (they might still be in use)
			dirInfo, err := dirEntry.Info()
			if err != nil {
				continue
			}

			if time.Since(dirInfo.ModTime()) < 300*time.Second {
				// Mark as valid and skip
				validPaths[dirPath] = true
				continue
			}

			// Check if metadata exists and if it's expired
			metaFile := filepath.Join(dirPath, MetaFile)
			expired := false

			metaData, err := os.Open(metaFile)
			if err != nil {
				// No metadata file, consider it orphaned
				expired = true
			} else {
				var meta struct {
					ExpiresAt time.Time `json:"expires_at"`
				}

				if err := json.NewDecoder(metaData).Decode(&meta); err != nil {
					// Invalid metadata, consider it orphaned
					expired = true
				} else if !meta.ExpiresAt.IsZero() && now.After(meta.ExpiresAt) {
					// Explicitly expired
					expired = true
				} else if !currentTargets[dirPath] {
					// Not expired by time, but not linked by any "current" symlink - it's orphaned
					expired = true
				} else {
					// Valid directory
					validPaths[dirPath] = true
				}
				metaData.Close()
			}

			if expired {
				// Remove expired or orphaned directory
				if err := os.RemoveAll(dirPath); err != nil {
					m.Logger.Warn().Err(err).Str("path", dirPath).Msg("Failed to remove expired/orphaned directory")
				} else {
					cleanedCount++
				}
			}
		}

		// Check if the ID directory is now empty and remove it if so
		remainingEntries, err := os.ReadDir(idPath)
		if err == nil && len(remainingEntries) == 0 {
			if err := os.RemoveAll(idPath); err != nil {
				m.Logger.Warn().Err(err).Str("path", idPath).Msg("Failed to remove empty ID directory")
			}
		}
	}

	// Remove broken symlinks
	for _, linkPath := range brokenLinks {
		if err := os.Remove(linkPath); err != nil {
			m.Logger.Warn().Err(err).Str("path", linkPath).Msg("Failed to remove broken symlink")
		} else {
			cleanedCount++
		}
	}

	if cleanedCount > 0 {
		m.Logger.Info().Int("count", cleanedCount).Msg("Cleaned up expired entries, orphaned directories, and broken links")
	}
}

// ErrorHandler is a helper function to return standardized error responses
func ErrorHandler(c *gin.Context, statusCode int, message string) {
	if message == "" {
		message = http.StatusText(statusCode)
		if message == "" {
			message = "unknown error"
		}
	}
	requestID := c.GetString("X-Request-ID")
	c.JSON(statusCode, response.NewError(requestID, message))
}
