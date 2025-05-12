package platform

import (
	"fmt"
	"runtime"
)

// ACLSupported returns true if the current platform supports ACLs
func ACLSupported() bool {
	return true // Both Windows and modern Unix systems support ACLs
}

// GetACL gets the ACL for a file in a platform-specific format
func GetACL(path string) ([]byte, error) {
	if !ACLSupported() {
		return nil, nil
	}

	if IsWindows() {
		return getWindowsACL(path)
	}

	return getUnixACL(path)
}

// SetACL sets the ACL for a file from a platform-specific format
func SetACL(path string, aclData []byte) error {
	if !ACLSupported() || len(aclData) == 0 {
		return nil
	}

	if IsWindows() {
		return setWindowsACL(path, aclData)
	}

	return setUnixACL(path, aclData)
}

// getWindowsACL gets the Windows ACL for a file
func getWindowsACL(path string) ([]byte, error) {
	if runtime.GOOS != "windows" {
		return nil, fmt.Errorf("not supported on this platform")
	}

	// This is a placeholder - actual implementation would use Windows API
	// to serialize the security descriptor

	// For a complete implementation, you would use:
	// - windows.GetNamedSecurityInfo to get the security descriptor
	// - windows.ConvertSecurityDescriptorToStringSecurityDescriptor to convert to SDDL
	// - Then store the SDDL string as bytes

	return nil, fmt.Errorf("Windows ACL serialization not implemented")
}

// setWindowsACL sets the Windows ACL for a file
func setWindowsACL(path string, aclData []byte) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("not supported on this platform")
	}

	// This is a placeholder - actual implementation would use Windows API
	// to deserialize and apply the security descriptor

	// For a complete implementation, you would:
	// - Convert the stored bytes back to an SDDL string
	// - Use windows.ConvertStringSecurityDescriptorToSecurityDescriptor to convert from SDDL
	// - Use windows.SetNamedSecurityInfo to apply the security descriptor

	return fmt.Errorf("Windows ACL deserialization not implemented")
}

// getUnixACL gets the Unix ACL for a file
func getUnixACL(path string) ([]byte, error) {
	if runtime.GOOS == "windows" {
		return nil, fmt.Errorf("not supported on this platform")
	}

	// This is a placeholder - actual implementation would use platform-specific
	// tools to get and serialize the ACL

	// For Linux, you might use the "getfacl" command or a library that wraps
	// the acl_get_file function from libacl

	return nil, fmt.Errorf("Unix ACL serialization not implemented")
}

// setUnixACL sets the Unix ACL for a file
func setUnixACL(path string, aclData []byte) error {
	if runtime.GOOS == "windows" {
		return fmt.Errorf("not supported on this platform")
	}

	// This is a placeholder - actual implementation would use platform-specific
	// tools to deserialize and apply the ACL

	// For Linux, you might use the "setfacl" command or a library that wraps
	// the acl_set_file function from libacl

	return fmt.Errorf("Unix ACL deserialization not implemented")
}
