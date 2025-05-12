//go:build !windows
// +build !windows

package platform

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// GetFileOwner gets the owner and group of a file
func GetFileOwner(path string) (uid, gid int, uidName, gidName string, err error) {
	info, err := os.Lstat(path)
	if err != nil {
		return 0, 0, "", "", err
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, "", "", fmt.Errorf("failed to get file stats")
	}

	uid = int(stat.Uid)
	gid = int(stat.Gid)

	// Try to get user name
	u, err := user.LookupId(strconv.Itoa(uid))
	if err == nil {
		uidName = u.Username
	}

	// Try to get group name
	g, err := user.LookupGroupId(strconv.Itoa(gid))
	if err == nil {
		gidName = g.Name
	}

	return uid, gid, uidName, gidName, nil
}

// SetFileOwner sets the owner and group of a file
func SetFileOwner(path string, uid, gid int) error {
	return os.Lchown(path, uid, gid)
}
