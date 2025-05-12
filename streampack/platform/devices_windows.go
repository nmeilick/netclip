//go:build windows
// +build windows

package platform

import (
	"fmt"
)

// CreateCharDevice creates a character device (not supported on Windows)
func CreateCharDevice(path string, mode int64, major, minor int64) error {
	return fmt.Errorf("character devices are not supported on Windows")
}

// CreateBlockDevice creates a block device (not supported on Windows)
func CreateBlockDevice(path string, mode int64, major, minor int64) error {
	return fmt.Errorf("block devices are not supported on Windows")
}

// CreateNamedPipe creates a named pipe (not supported in this implementation)
func CreateNamedPipe(path string, mode int64) error {
	return fmt.Errorf("named pipes are not supported in this implementation on Windows")
}
