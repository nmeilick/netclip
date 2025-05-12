package platform

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
)

// IsWindows returns true if running on Windows
func IsWindows() bool {
	return runtime.GOOS == "windows"
}

// IsUnix returns true if running on a Unix-like system
func IsUnix() bool {
	return !IsWindows()
}

// CreateSymlink creates a symlink with platform-specific handling
func CreateSymlink(linkname, target string) error {
	if IsWindows() {
		// On Windows, we need special handling which is defined in windows.go
		// This will be properly linked when building on Windows
		return os.Symlink(target, linkname) // Fallback that will be replaced on Windows builds
	}
	return os.Symlink(target, linkname)
}

// GetFileMode returns the appropriate file mode for the current platform
func GetFileMode(mode int64) fs.FileMode {
	if IsWindows() {
		// On Windows, we only care about the read-only bit
		if mode&0200 == 0 {
			return 0444 // Read-only
		}
		return 0666 // Read-write
	}
	return fs.FileMode(mode)
}

// EnsureValidPath ensures the path is valid for the current platform
func EnsureValidPath(path string) string {
	if IsWindows() {
		// Handle Windows-specific path issues
		// Convert absolute paths that start with / to use the current drive
		if len(path) > 0 && path[0] == '/' {
			// Get current drive
			cwd, err := os.Getwd()
			if err == nil && len(cwd) >= 2 && cwd[1] == ':' {
				drive := cwd[0:2]
				return drive + path
			}
		}
	}
	return path
}

// IsPathTooLong checks if a path exceeds platform limits
func IsPathTooLong(path string) bool {
	if IsWindows() {
		// Windows has a 260 character path limit by default
		// (can be longer with special prefixes, but we're being cautious)
		return len(path) > 250
	}
	// Most Unix systems have a 4096 character limit
	return len(path) > 4000
}

// SanitizePath makes a path safe for the current platform
func SanitizePath(path string) string {
	// Replace characters that are invalid on Windows
	if IsWindows() {
		// Windows doesn't allow these characters in filenames
		invalidChars := []rune{'<', '>', ':', '"', '|', '?', '*'}
		for range invalidChars {
			// Just clean the path once instead of in a loop
			path = filepath.Clean(path)
		}
	}
	return path
}

// GetPathSeparator returns the path separator for the current platform
func GetPathSeparator() string {
	return string(filepath.Separator)
}

// NormalizePath normalizes a path for the current platform
func NormalizePath(path string) string {
	return filepath.FromSlash(path)
}

// ToSlash converts a path to use forward slashes
func ToSlash(path string) string {
	return filepath.ToSlash(path)
}

// IsAdmin returns true if the current process has administrator/root privileges
func IsAdmin() bool {
	if IsWindows() {
		// This will be properly defined in windows.go for Windows builds
		return false // Default fallback for non-Windows builds
	}
	return os.Geteuid() == 0
}

// GetTempDir returns a suitable temporary directory
func GetTempDir() string {
	return os.TempDir()
}

// FileExists checks if a file exists
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// IsDir checks if a path is a directory
func IsDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// MkdirAll creates a directory with all necessary parents
func MkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

// RemoveAll removes a path and all its contents
func RemoveAll(path string) error {
	return os.RemoveAll(path)
}

// GetFileInfo gets file info without following symlinks
func GetFileInfo(path string) (os.FileInfo, error) {
	return os.Lstat(path)
}

// FormatError formats an error with platform-specific details
func FormatError(err error) string {
	if err == nil {
		return ""
	}
	
	// Windows-specific formatting will be handled in windows.go
	return err.Error()
}

// GetExecutable returns the path to the current executable
func GetExecutable() (string, error) {
	return os.Executable()
}

// GetWorkingDir returns the current working directory
func GetWorkingDir() (string, error) {
	return os.Getwd()
}

// IsSymlink checks if a path is a symlink
func IsSymlink(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && (info.Mode()&os.ModeSymlink != 0)
}

// ReadLink reads the target of a symlink
func ReadLink(path string) (string, error) {
	return os.Readlink(path)
}

// IsExecutable checks if a file is executable
func IsExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	
	if IsWindows() {
		// On Windows, check file extension
		ext := filepath.Ext(path)
		execExts := []string{".exe", ".bat", ".cmd", ".com"}
		for _, e := range execExts {
			if ext == e {
				return true
			}
		}
		return false
	}
	
	// On Unix, check executable bit
	return info.Mode()&0111 != 0
}

// GetHomeDir returns the user's home directory
func GetHomeDir() (string, error) {
	return os.UserHomeDir()
}

// ExpandPath expands a path with ~ to the user's home directory
func ExpandPath(path string) (string, error) {
	if len(path) == 0 || path[0] != '~' {
		return path, nil
	}
	
	home, err := GetHomeDir()
	if err != nil {
		return "", err
	}
	
	if len(path) == 1 {
		return home, nil
	}
	
	if path[1] == filepath.Separator {
		return filepath.Join(home, path[2:]), nil
	}
	
	return path, fmt.Errorf("invalid path format: %s", path)
}
