//go:build windows
// +build windows

package platform

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows-specific constants
const (
	SYMBOLIC_LINK_FLAG_DIRECTORY                 = 0x1
	SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE = 0x2
)

// createWindowsSymlink creates a symlink on Windows
// It handles both file and directory symlinks
func createWindowsSymlink(linkname, target string) error {
	// Convert to absolute paths
	linkname = filepath.Clean(linkname)
	target = filepath.Clean(target)

	// Determine if target is a directory
	// First check if it exists
	targetInfo, err := os.Stat(target)
	isDir := err == nil && targetInfo.IsDir()

	// If target doesn't exist, try to guess from the path
	if os.IsNotExist(err) {
		// If target ends with \ or /, assume it's a directory
		isDir = strings.HasSuffix(target, "\\") || strings.HasSuffix(target, "/")
	}

	// Convert to UTF16 for Windows API
	linkPtr, err := windows.UTF16PtrFromString(linkname)
	if err != nil {
		return err
	}

	targetPtr, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}

	// Set flags based on target type and Windows version
	flags := uint32(0)
	if isDir {
		flags |= SYMBOLIC_LINK_FLAG_DIRECTORY
	}

	// Try to create with unprivileged flag first (Windows 10 1703+)
	flags |= SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE
	err = windows.CreateSymbolicLink(linkPtr, targetPtr, flags)

	if err != nil {
		// If that fails, try without the unprivileged flag
		flags &^= SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE
		err = windows.CreateSymbolicLink(linkPtr, targetPtr, flags)

		if err != nil {
			// If symlink creation fails, try to create a junction point for directories
			if isDir {
				return createJunction(linkname, target)
			}
			return fmt.Errorf("failed to create symlink: %w", err)
		}
	}

	return nil
}

// createJunction creates a junction point (directory symlink) on Windows
func createJunction(linkname, target string) error {
	// Make sure target is absolute
	if !filepath.IsAbs(target) {
		var err error
		target, err = filepath.Abs(target)
		if err != nil {
			return err
		}
	}

	// Create the directory for the junction
	err := os.MkdirAll(linkname, 0755)
	if err != nil {
		return err
	}

	// Convert paths to required format
	linkname = fixLongPath(linkname)
	target = fixLongPath(target)

	// Open handle to the junction directory
	linkHandle, err := windows.CreateFile(
		windows.StringToUTF16Ptr(linkname),
		windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(linkHandle)

	// Prepare reparse data buffer
	target = `\??\` + target
	targetUTF16 := windows.StringToUTF16(target)

	// Calculate buffer size
	reparseDataLength := uint32(len(targetUTF16)*2 + 12) // 12 = sizeof(REPARSE_DATA_BUFFER) - sizeof(PathBuffer)
	bufferLength := reparseDataLength + 8                // 8 = sizeof(REPARSE_DATA_BUFFER) - sizeof(ReparseDataLength)

	// Allocate buffer
	buffer := make([]byte, bufferLength)

	// Set reparse tag (IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003)
	*(*uint32)(unsafe.Pointer(&buffer[0])) = 0xA0000003

	// Set reparse data length
	*(*uint32)(unsafe.Pointer(&buffer[4])) = reparseDataLength

	// Set substitute name offset and length
	*(*uint16)(unsafe.Pointer(&buffer[8])) = 0
	*(*uint16)(unsafe.Pointer(&buffer[10])) = uint16(len(target) * 2)

	// Set print name offset and length
	*(*uint16)(unsafe.Pointer(&buffer[12])) = uint16(len(target)*2 + 2)
	*(*uint16)(unsafe.Pointer(&buffer[14])) = 0

	// Copy target path - need to convert []uint16 to []byte for copying
	for i, val := range targetUTF16 {
		buffer[16+i*2] = byte(val)
		buffer[16+i*2+1] = byte(val >> 8)
	}

	// Issue FSCTL_SET_REPARSE_POINT
	var bytesReturned uint32
	err = windows.DeviceIoControl(
		linkHandle,
		windows.FSCTL_SET_REPARSE_POINT,
		&buffer[0],
		bufferLength,
		nil,
		0,
		&bytesReturned,
		nil,
	)
	if err != nil {
		return err
	}

	return nil
}

// fixLongPath adds the \\?\ prefix to paths if needed
func fixLongPath(path string) string {
	if len(path) < 250 {
		return path
	}
	if strings.HasPrefix(path, "\\\\?\\") {
		return path
	}
	if strings.HasPrefix(path, "\\\\") {
		// UNC path
		return "\\\\?\\UNC\\" + path[2:]
	}
	return "\\\\?\\" + path
}

// isWindowsAdmin checks if the current process has administrator privileges
func isWindowsAdmin() bool {
	var token windows.Token
	process, err := windows.GetCurrentProcess()
	if err != nil {
		return false
	}

	err = windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token)
	if err != nil {
		return false
	}
	defer token.Close()

	// Check if the process has elevated privileges
	var elevation struct {
		TokenIsElevated uint32
	}
	var returnedLen uint32
	err = windows.GetTokenInformation(token, windows.TokenElevation, (*byte)(unsafe.Pointer(&elevation)), uint32(unsafe.Sizeof(elevation)), &returnedLen)
	if err != nil {
		return false
	}

	return elevation.TokenIsElevated != 0
}

// formatWindowsError adds Windows-specific error details
func formatWindowsError(err error) string {
	if err == nil {
		return ""
	}

	// Try to get Windows error code
	if errno, ok := err.(syscall.Errno); ok {
		return fmt.Sprintf("%s (code: %d)", err.Error(), errno)
	}

	return err.Error()
}
