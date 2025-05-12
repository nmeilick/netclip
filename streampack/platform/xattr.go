package platform

import (
	"fmt"
	"runtime"
	
	"github.com/pkg/xattr"
)

// XattrSupported returns true if the current platform supports extended attributes
func XattrSupported() bool {
	// Windows doesn't support xattrs in the same way as Unix systems
	return runtime.GOOS != "windows"
}

// GetXattrs gets all extended attributes for a file
func GetXattrs(path string) (map[string][]byte, error) {
	if !XattrSupported() {
		return nil, nil
	}
	
	attrs := make(map[string][]byte)
	
	// List all attribute names
	names, err := xattr.List(path)
	if err != nil {
		return nil, fmt.Errorf("failed to list xattrs: %w", err)
	}
	
	// Get each attribute value
	for _, name := range names {
		value, err := xattr.Get(path, name)
		if err != nil {
			// Skip attributes we can't read
			continue
		}
		attrs[name] = value
	}
	
	return attrs, nil
}

// SetXattrs sets extended attributes for a file
func SetXattrs(path string, attrs map[string][]byte) error {
	if !XattrSupported() || len(attrs) == 0 {
		return nil
	}
	
	var firstErr error
	
	for name, value := range attrs {
		err := xattr.Set(path, name, value)
		if err != nil && firstErr == nil {
			firstErr = fmt.Errorf("failed to set xattr %s: %w", name, err)
		}
	}
	
	return firstErr
}
