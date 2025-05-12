//go:build !windows
// +build !windows

package platform

import (
	"archive/tar"
	"fmt"
	"os"
	"os/user"
	"syscall"
)

// SetDeviceNumbers sets device major/minor numbers in the tar header
func SetDeviceNumbers(header *tar.Header, info os.FileInfo) {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		// Cast stat.Rdev to uint64 for Darwin compatibility
		header.Devmajor = int64(major(uint64(stat.Rdev)))
		header.Devminor = int64(minor(uint64(stat.Rdev)))
	}
}

// Helper functions for device numbers
func major(dev uint64) uint32 {
	return uint32((dev >> 8) & 0xff)
}

func minor(dev uint64) uint32 {
	return uint32(dev & 0xff)
}

// SetUnixOwnership sets Unix ownership information in the tar header
func SetUnixOwnership(header *tar.Header, info os.FileInfo, uidCache map[uint32]string, gidCache map[uint32]string) {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		header.Uid = int(stat.Uid)
		header.Gid = int(stat.Gid)

		// Try to get cached user name, fallback to lookup
		if uname, ok := uidCache[uint32(stat.Uid)]; ok {
			header.Uname = uname
		} else {
			if u, err := user.LookupId(fmt.Sprintf("%d", stat.Uid)); err == nil {
				header.Uname = u.Username
			}
			// Cache the result (empty string if lookup failed)
			uidCache[uint32(stat.Uid)] = header.Uname
		}

		// Try to get cached group name, fallback to lookup
		if gname, ok := gidCache[uint32(stat.Gid)]; ok {
			header.Gname = gname
		} else {
			if g, err := user.LookupGroupId(fmt.Sprintf("%d", stat.Gid)); err == nil {
				header.Gname = g.Name
			}
			// Cache the result (empty string if lookup failed)
			gidCache[uint32(stat.Gid)] = header.Gname
		}
	}
}
