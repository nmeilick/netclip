package streampack

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nmeilick/netclip/streampack/compression"
	"github.com/nmeilick/netclip/streampack/encryption"
	"github.com/nmeilick/netclip/streampack/platform"
)

// OverwriteCallback is a function type for interactive overwrite decisions
type OverwriteCallback func(u *Unpacker, path string, destTime, srcTime time.Time, destSize int64) (bool, error)

// VerboseCallback is a function type for verbose output during extraction
type VerboseCallback func(action, path string)

// Unpacker handles the extraction of compressed and encrypted tar archives
type Unpacker struct {
	input              io.Reader
	inputFilePath      string
	destDir            string
	decryptionEnabled  bool
	decryptionPassword string
	decryptionType     encryption.EncryptionType
	rawDataMode        bool
	rawData            []byte
	forceOverwrite     bool
	updatePolicy       UpdatePolicy
	overwriteCallback  OverwriteCallback
	verboseCallback    VerboseCallback
	// Platform-specific features
	preserveXattrs bool
	preserveACLs   bool
	// Cross-platform compatibility
	platformCompatMode bool
	// Delete files not in archive
	deleteExtraFiles bool
}

// NewUnpacker creates a new Unpacker with the given options
func NewUnpacker(options ...UnpackerOption) *Unpacker {
	u := &Unpacker{
		// Set default update policy to update all files
		updatePolicy: UpdateAll,
		// Enable platform-specific features by default
		preserveXattrs: platform.XattrSupported(),
		preserveACLs:   platform.ACLSupported(),
		// Enable platform compatibility mode by default
		platformCompatMode: true,
	}

	for _, option := range options {
		option(u)
	}

	return u
}

// Unpack extracts a tar archive
func (u *Unpacker) Unpack() error {
	if !u.rawDataMode {
		if u.destDir == "" {
			return fmt.Errorf("no destination directory specified")
		}

		if stat, err := os.Stat(u.destDir); err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("destination directory does not exist: %q", u.destDir)
			} else {
				return fmt.Errorf("error accessing destination directory: %w", err)
			}
		} else if !stat.IsDir() {
			return fmt.Errorf("destination is not a directory: %q", u.destDir)
		}
	}

	// If input file path is specified, open the file
	if u.inputFilePath != "" {
		file, err := os.Open(u.inputFilePath)
		if err != nil {
			return fmt.Errorf("failed to open input file: %w", err)
		}
		defer file.Close()
		u.input = file
	}

	if u.input == nil {
		return fmt.Errorf("no input specified")
	}

	// Read and parse the header
	header, _, err := ReadHeader(u.input)
	if err != nil {
		return fmt.Errorf("failed to read archive header: %w", err)
	}

	// Set up the pipeline: input -> decrypt -> decompress -> untar
	reader := u.input

	// Use compression and encryption settings from the header
	if header.EncryptionType != "" {
		if !u.decryptionEnabled {
			return fmt.Errorf("archive is encrypted but decryption is not enabled")
		}

		// Verify password if verification data is available
		if header.PasswordVerification != nil {
			pv := header.PasswordVerification
			params := PasswordVerificationParams{
				Iterations: pv.Iterations,
				Memory:     pv.Memory,
				Threads:    pv.Threads,
				KeyLength:  uint32(len(pv.VerificationKey)),
			}

			if !VerifyPassword(u.decryptionPassword, pv.Salt, pv.VerificationKey, params) {
				return fmt.Errorf("invalid password")
			}
		}

		// Setup decryption
		encType := header.EncryptionType
		encryptor, err := encryption.GetEncryptor(encType)
		if err != nil {
			return fmt.Errorf("encryption error: %w", err)
		}

		decReader, err := encryptor.Decrypt(reader, u.decryptionPassword)
		if err != nil {
			return fmt.Errorf("failed to create decryption reader: %w", err)
		}
		defer decReader.Close()
		reader = decReader
	}

	// Apply decompression based on header
	if header.CompressionType != compression.NoCompression {
		compressor, err := compression.GetCompressor(compression.CompressionType(header.CompressionType))
		if err != nil {
			return fmt.Errorf("compression error: %w", err)
		}
		if compressor == nil {
			return fmt.Errorf("no compressor available for type: %s", header.CompressionType)
		}

		decompReader, err := compressor.Decompress(reader)
		if err != nil {
			return fmt.Errorf("failed to create decompression reader: %w", err)
		}
		defer decompReader.Close()
		reader = decompReader
	}

	// Handle different archive types
	switch header.Type {
	case TypeRaw:
		if u.rawDataMode {
			_, err := io.Copy(os.Stdout, reader)
			return err
		} else {
			// Raw data mode but no raw data output requested
			return fmt.Errorf("archive contains raw data but raw data output mode is not enabled")
		}
	case TypeTar:
		// Continue below with tar extraction
	default:
		return fmt.Errorf("unsupported archive type: %s", header.Type)
	}

	// Create tar reader
	tarReader := tar.NewReader(reader)

	// Check if running as root
	isRoot := os.Geteuid() == 0

	// Collect errors but continue extraction
	var extractErrors []error

	// Track extracted paths for delete mode
	var extractedPaths []string

	// Extract files
	for {
		header, err := tarReader.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("failed to read tar header: %w", err)
		}

		// Store the relative path for delete mode
		if u.deleteExtraFiles {
			extractedPaths = append(extractedPaths, header.Name)
		}

		target := filepath.Join(u.destDir, header.Name)

		// Create parent directory if it doesn't exist
		// TODO: This fails when the target's parent is a file. Delete upwards and retry?
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return fmt.Errorf("failed to create parent directory for %s: %w", target, err)
		}

		if stat, err := os.Lstat(target); err == nil {
			if !u.forceOverwrite && !stat.IsDir() {
				// Check update policy
				shouldOverwrite, err := u.shouldOverwrite(target, header)
				if err != nil {
					return err
				}
				if !shouldOverwrite {
					// Skip this file
					continue
				}
			}
			// Regular files will be overwritten on open, but other file types should be deleted.
			if !stat.IsDir() && !stat.Mode().IsRegular() {
				os.Remove(target)
			}
		}

		switch header.Typeflag {
		case tar.TypeDir:
			// Create directory with proper permissions
			if u.verboseCallback != nil {
				u.verboseCallback("Creating directory", target)
			}
			if err := os.MkdirAll(target, platform.GetFileMode(header.Mode)); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", target, err)
			}

		case tar.TypeReg, tar.TypeRegA:
			// Create regular file
			if u.verboseCallback != nil {
				u.verboseCallback("Creating file", target)
			}
			
			// Check if the file exists and is read-only
			if stat, err := os.Lstat(target); err == nil && !stat.Mode().IsDir() {
				// If file exists and is read-only, temporarily make it writable
				if stat.Mode().Perm()&0200 == 0 {
					if err := os.Chmod(target, stat.Mode().Perm()|0200); err != nil {
						return fmt.Errorf("failed to make file writable %s: %w", target, err)
					}
					// Restore original permissions after we're done
					defer os.Chmod(target, stat.Mode().Perm())
				}
			}
			
			file, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, platform.GetFileMode(header.Mode))
			if err != nil {
				return fmt.Errorf("failed to create file %s: %w", target, err)
			}

			// Copy contents
			if _, err := io.Copy(file, tarReader); err != nil {
				file.Close()
				return fmt.Errorf("failed to write file %s: %w", target, err)
			}
			file.Close()

		case tar.TypeSymlink:
			// Create symbolic link with platform-specific handling
			if u.verboseCallback != nil {
				u.verboseCallback("Creating symlink", fmt.Sprintf("%s -> %s", target, header.Linkname))
			}
			if err := platform.CreateSymlink(target, header.Linkname); err != nil {
				return fmt.Errorf("failed to create symlink %s -> %s: %w", target, header.Linkname, err)
			}

		case tar.TypeLink:
			// Create hard link
			linkTarget := filepath.Join(u.destDir, header.Linkname)
			if u.verboseCallback != nil {
				u.verboseCallback("Creating hard link", fmt.Sprintf("%s -> %s", target, linkTarget))
			}
			if err := os.Link(linkTarget, target); err != nil {
				return fmt.Errorf("failed to create hard link %s -> %s: %w", target, linkTarget, err)
			}

		case tar.TypeChar:
			// Character device
			if u.verboseCallback != nil {
				u.verboseCallback("Creating character device", target)
			}
			if !isRoot {
				extractErrors = append(extractErrors, fmt.Errorf("cannot create character device %s: not running as root", target))
				continue
			}

			if platform.IsUnix() {
				if err := platform.CreateCharDevice(target, header.Mode, header.Devmajor, header.Devminor); err != nil {
					extractErrors = append(extractErrors, fmt.Errorf("failed to create character device %s: %w", target, err))
				}
			} else {
				extractErrors = append(extractErrors, fmt.Errorf("character devices not supported on this platform: %s", target))
			}

		case tar.TypeBlock:
			// Block device
			if u.verboseCallback != nil {
				u.verboseCallback("Creating block device", target)
			}
			if !isRoot {
				extractErrors = append(extractErrors, fmt.Errorf("cannot create block device %s: not running as root", target))
				continue
			}

			if platform.IsUnix() {
				if err := platform.CreateBlockDevice(target, header.Mode, header.Devmajor, header.Devminor); err != nil {
					extractErrors = append(extractErrors, fmt.Errorf("failed to create block device %s: %w", target, err))
				}
			} else {
				extractErrors = append(extractErrors, fmt.Errorf("block devices not supported on this platform: %s", target))
			}

		case tar.TypeFifo:
			// Named pipe (FIFO)
			if u.verboseCallback != nil {
				u.verboseCallback("Creating named pipe", target)
			}
			if platform.IsUnix() {
				if err := platform.CreateNamedPipe(target, header.Mode); err != nil {
					return fmt.Errorf("failed to create named pipe %s: %w", target, err)
				}
			} else {
				return fmt.Errorf("named pipes not supported on this platform: %s", target)
			}
		}

		// Set ownership if running as root on Unix
		// TODO: Suppport setting ownership by name
		if platform.IsUnix() && platform.IsAdmin() {
			if err := os.Lchown(target, header.Uid, header.Gid); err != nil {
				// Just log the error but continue
				extractErrors = append(extractErrors, fmt.Errorf("failed to set ownership for %s: %w", target, err))
			}
		}

		// Set modification time for non-symlink files (symlinks don't support it on all platforms)
		if header.Typeflag != tar.TypeSymlink {
			if err := os.Chtimes(target, header.AccessTime, header.ModTime); err != nil {
				extractErrors = append(extractErrors, fmt.Errorf("failed to set modification time for %s: %w", target, err))
			}
		}

		// Process extended attributes if present and supported
		if u.preserveXattrs && platform.XattrSupported() && header.PAXRecords != nil {
			xattrs := make(map[string][]byte)

			// Look for xattr records
			for key, value := range header.PAXRecords {
				if strings.HasPrefix(key, "SCHILY.xattr.") && key != "SCHILY.xattr.count" {
					// Extract the xattr name from the key
					name := strings.TrimPrefix(key, "SCHILY.xattr.")
					xattrs[name] = []byte(value)
				}
			}

			// Set xattrs if any were found
			if len(xattrs) > 0 {
				if err := platform.SetXattrs(target, xattrs); err != nil {
					extractErrors = append(extractErrors, fmt.Errorf("failed to set xattrs for %s: %w", target, err))
				}
			}
		}

		// Process ACLs if present and supported
		if u.preserveACLs && platform.ACLSupported() && header.PAXRecords != nil {
			if aclData, ok := header.PAXRecords["SCHILY.acl.data"]; ok {
				if err := platform.SetACL(target, []byte(aclData)); err != nil {
					extractErrors = append(extractErrors, fmt.Errorf("failed to set ACL for %s: %w", target, err))
				}
			}
		}
	}

	// Delete files not in archive if enabled
	if u.deleteExtraFiles && !u.rawDataMode {
		if u.verboseCallback != nil {
			u.verboseCallback("Checking for files to delete", u.destDir)
		}

		// Create a map of all files in the archive
		archiveFiles := make(map[string]bool)
		for _, path := range extractedPaths {
			archiveFiles[path] = true
		}

		// Walk the destination directory and delete files not in the archive
		err := filepath.Walk(u.destDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			// Skip the destination directory itself
			if path == u.destDir {
				return nil
			}

			// Get the relative path
			relPath, err := filepath.Rel(u.destDir, path)
			if err != nil {
				return err
			}

			// If the file is not in the archive, delete it
			if !archiveFiles[relPath] {
				if u.verboseCallback != nil {
					u.verboseCallback("Deleting", path)
				}

				if info.IsDir() {
					// For directories, check if any of its contents are in the archive
					// by checking if any archive path has this directory as a prefix
					hasContent := false
					prefix := relPath + string(filepath.Separator)
					for archivePath := range archiveFiles {
						if strings.HasPrefix(archivePath, prefix) {
							hasContent = true
							break
						}
					}

					// Only delete empty directories or directories with no files in the archive
					if !hasContent {
						return os.RemoveAll(path)
					}
					// Skip this directory but continue walking
					return filepath.SkipDir
				}

				// Delete the file
				return os.Remove(path)
			}

			return nil
		})

		if err != nil {
			extractErrors = append(extractErrors, fmt.Errorf("error during delete operation: %w", err))
		}
	}

	// Return collected errors if any
	if len(extractErrors) > 0 {
		return &ExtractError{Errors: extractErrors}
	}

	return nil
}

// ExtractError represents multiple errors that occurred during extraction
type ExtractError struct {
	Errors []error
}

func (e *ExtractError) Error() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("encountered %d errors during extraction:\n", len(e.Errors)))
	for i, err := range e.Errors {
		sb.WriteString(fmt.Sprintf("  %d: %s\n", i+1, err.Error()))
	}
	return sb.String()
}

// GetRawData returns the raw data extracted from the archive
// This should only be called after Unpack() and only if raw data mode was enabled
func (u *Unpacker) GetRawData() ([]byte, error) {
	if !u.rawDataMode {
		return nil, fmt.Errorf("raw data mode not enabled")
	}
	if u.rawData == nil {
		return nil, fmt.Errorf("no raw data available, make sure to call Unpack() first")
	}
	return u.rawData, nil
}
