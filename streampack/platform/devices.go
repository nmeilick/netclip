//go:build !windows
// +build !windows

package platform

import (
	"golang.org/x/sys/unix"
)

// CreateCharDevice creates a character device
func CreateCharDevice(path string, mode int64, major, minor int64) error {
	fileMode := uint32(mode) | uint32(unix.S_IFCHR)
	dev := unix.Mkdev(uint32(major), uint32(minor))
	return unix.Mknod(path, fileMode, int(dev))
}

// CreateBlockDevice creates a block device
func CreateBlockDevice(path string, mode int64, major, minor int64) error {
	fileMode := uint32(mode) | uint32(unix.S_IFBLK)
	dev := unix.Mkdev(uint32(major), uint32(minor))
	return unix.Mknod(path, fileMode, int(dev))
}

// CreateNamedPipe creates a named pipe (FIFO)
func CreateNamedPipe(path string, mode int64) error {
	return unix.Mkfifo(path, uint32(mode))
}
