//go:build windows
// +build windows

package platform

import (
	"archive/tar"
	"os"
)

// SetDeviceNumbers is a no-op on Windows
func SetDeviceNumbers(header *tar.Header, info os.FileInfo) {
	// Windows doesn't use the same device number concept
	header.Devmajor = 0
	header.Devminor = 0
}

// SetUnixOwnership is a no-op on Windows
func SetUnixOwnership(header *tar.Header, info os.FileInfo, uidCache map[uint32]string, gidCache map[uint32]string) {
	// Windows doesn't use the same ownership model, so we just set defaults
	header.Uid = 0
	header.Gid = 0
	header.Uname = ""
	header.Gname = ""
}
