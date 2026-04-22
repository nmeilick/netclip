package common

import (
	"path/filepath"
	"strings"
)

const windowsExecutableSuffix = ".exe"

// SetupLinkNames returns the platform-specific helper executable names created by `setup links`.
func SetupLinkNames(goos string) []string {
	names := []string{CopyBinary, PasteBinary, ServerBinary}
	if goos != "windows" {
		return names
	}

	windowsNames := make([]string, len(names))
	for i, name := range names {
		windowsNames[i] = name + windowsExecutableSuffix
	}

	return windowsNames
}

// NormalizeExecutableName strips the Windows executable suffix and normalizes the name for comparisons.
func NormalizeExecutableName(name string) string {
	if ext := filepath.Ext(name); strings.EqualFold(ext, windowsExecutableSuffix) {
		name = name[:len(name)-len(ext)]
	}

	return strings.ToLower(name)
}
