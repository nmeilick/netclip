package streampack

import (
	"archive/tar"
	"fmt"
	"os"
)

// UpdatePolicy defines how existing files should be handled during extraction
type UpdatePolicy int

const (
	// UpdateNone doesn't update any existing files
	UpdateNone UpdatePolicy = iota
	// UpdateAll updates all existing files
	UpdateAll
	// UpdateOlder only updates files that are older than the ones in the archive
	UpdateOlder
	// UpdateInteractive prompts the user for each file
	UpdateInteractive
)

// WithUpdatePolicy sets the policy for updating existing files
func WithUpdatePolicy(policy UpdatePolicy) UnpackerOption {
	return func(u *Unpacker) {
		u.updatePolicy = policy
	}
}

// WithInteractiveConfirmation enables interactive confirmation for file overwrites
func WithInteractiveConfirmation() UnpackerOption {
	return func(u *Unpacker) {
		u.updatePolicy = UpdateInteractive
	}
}

// WithOverwriteCallback sets a callback function for interactive overwrite decisions
func WithOverwriteCallback(callback OverwriteCallback) UnpackerOption {
	return func(u *Unpacker) {
		u.overwriteCallback = callback
	}
}

// shouldOverwrite determines if a file should be overwritten based on the update policy
func (u *Unpacker) shouldOverwrite(destPath string, header *tar.Header) (bool, error) {
	// If force overwrite is enabled, always overwrite
	if u.forceOverwrite {
		if u.verboseCallback != nil {
			u.verboseCallback("Force overwriting", destPath)
		}
		return true, nil
	}

	// Check if file exists
	info, err := os.Lstat(destPath)
	if os.IsNotExist(err) {
		// File doesn't exist, so it's safe to write
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to stat destination file: %w", err)
	}

	// File exists, apply update policy
	switch u.updatePolicy {
	case UpdateNone:
		if u.verboseCallback != nil {
			u.verboseCallback("Skipping (policy: none)", destPath)
		}
		return false, nil
	case UpdateAll:
		if u.verboseCallback != nil {
			u.verboseCallback("Updating (policy: all)", destPath)
		}
		return true, nil
	case UpdateOlder:
		// Compare modification times
		destTime := info.ModTime()
		srcTime := header.ModTime
		shouldUpdate := srcTime.After(destTime)
		if u.verboseCallback != nil {
			if shouldUpdate {
				u.verboseCallback("Updating older file", destPath)
			} else {
				u.verboseCallback("Skipping newer file", destPath)
			}
		}
		return shouldUpdate, nil
	case UpdateInteractive:
		if u.overwriteCallback != nil {
			return u.overwriteCallback(u, destPath, info.ModTime(), header.ModTime, info.Size())
		}
		// If no callback is registered, default to not overwriting
		return false, fmt.Errorf("interactive mode enabled but no callback registered")
	default:
		// Default to not overwriting
		return false, nil
	}
}

// SetUpdatePolicy sets the update policy
func (u *Unpacker) SetUpdatePolicy(policy UpdatePolicy) {
	u.updatePolicy = policy
}
