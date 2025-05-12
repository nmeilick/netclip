package streampack

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/nmeilick/netclip/streampack/compression"
	"github.com/nmeilick/netclip/streampack/encryption"
)

// PackerOption is a function that configures a Packer
type PackerOption func(*Packer) error

// WithCompression sets the compression type and level
func WithCompression(compressionType compression.CompressionType, level compression.Level) PackerOption {
	return func(p *Packer) error {
		// Validate compression type
		if compressionType != compression.NoCompression {
			_, err := compression.GetCompressor(compressionType)
			if err != nil {
				return err
			}
		}

		// Validate compression level
		if level < compression.Fast || level > compression.Best {
			return fmt.Errorf("invalid compression level: %d (must be between %d and %d)",
				level, compression.Fast, compression.Best)
		}

		p.compressionType = compressionType
		p.compressionLevel = level
		return nil
	}
}

// WithEncryptionType enables encryption with the given password and type
func WithEncryptionType(password string, encType encryption.EncryptionType) PackerOption {
	return func(p *Packer) error {
		if password == "" {
			return fmt.Errorf("encryption password cannot be empty")
		}
		p.encryptionEnabled = true
		p.encryptionPassword = password
		p.encryptionType = encType
		return nil
	}
}

// WithEncryption enables encryption with the given password using AGE encryption
func WithEncryption(password string) PackerOption {
	return WithEncryptionType(password, encryption.AGEEncryption)
}

// WithOutput sets the output writer
func WithOutput(output io.Writer) PackerOption {
	return func(p *Packer) error {
		if output == nil {
			return fmt.Errorf("output writer cannot be nil")
		}
		if p.outputFile != "" {
			return fmt.Errorf("cannot set both output writer and output file")
		}
		p.output = output
		return nil
	}
}

// WithOutputFile sets the output file path
func WithOutputFile(filePath string) PackerOption {
	return func(p *Packer) error {
		if filePath == "" {
			return fmt.Errorf("output file path cannot be empty")
		}
		if p.output != nil {
			return fmt.Errorf("cannot set both output writer and output file")
		}
		p.outputFile = filePath
		return nil
	}
}

// WithRawDataInput sets the raw data reader to be packed
func WithRawDataInput(reader io.Reader) PackerOption {
	return func(p *Packer) error {
		if reader == nil {
			return fmt.Errorf("raw data reader cannot be nil")
		}
		p.rawDataReader = reader
		return nil
	}
}

// WithMetadata adds arbitrary metadata to the archive header
func WithMetadata(metadata map[string]interface{}) PackerOption {
	return func(p *Packer) error {
		if metadata == nil {
			return fmt.Errorf("metadata cannot be nil")
		}
		p.metadata = metadata
		return nil
	}
}

// WithPreserveXattrs enables or disables extended attribute preservation
func WithPreserveXattrs(preserve bool) PackerOption {
	return func(p *Packer) error {
		p.preserveXattrs = preserve
		return nil
	}
}

// WithPreserveACLs enables or disables ACL preservation
func WithPreserveACLs(preserve bool) PackerOption {
	return func(p *Packer) error {
		p.preserveACLs = preserve
		return nil
	}
}

// WithSource adds one or more files or directories to be packed
func WithSource(paths ...string) PackerOption {
	return func(p *Packer) error {
		if len(paths) == 0 {
			return fmt.Errorf("at least one source path must be specified")
		}
		for _, path := range paths {
			if path == "" {
				return fmt.Errorf("source path cannot be empty")
			}
			path = filepath.FromSlash(path)
			endsWithSep := path[len(path)-1] == filepath.Separator
			path = filepath.Clean(path)
			if endsWithSep && path != string(filepath.Separator) {
				path += string(filepath.Separator)
			}
			// Check if the path exists
			if _, err := os.Stat(path); err != nil {
				return fmt.Errorf("invalid source path %q: %w", path, err)
			}
			p.sources = append(p.sources, path)
		}
		return nil
	}
}

// UnpackerOption is a function that configures an Unpacker
type UnpackerOption func(*Unpacker)

// WithDecryptionType enables decryption with the given password and type
func WithDecryptionType(password string, encType encryption.EncryptionType) UnpackerOption {
	return func(u *Unpacker) {
		u.decryptionEnabled = true
		u.decryptionPassword = password
		u.decryptionType = encType
	}
}

// WithDecryption enables decryption with the given password
func WithDecryption(password string) UnpackerOption {
	return func(u *Unpacker) {
		u.decryptionEnabled = true
		u.decryptionPassword = password
		// Default encryption type will be determined from header
	}
}

// WithDestination sets the destination directory for unpacked files
func WithDestination(destDir string) UnpackerOption {
	return func(u *Unpacker) {
		u.destDir = destDir
	}
}

// WithInput sets the input reader
func WithInput(input io.Reader) UnpackerOption {
	return func(u *Unpacker) {
		u.input = input
	}
}

// WithInputFile sets the input file path
func WithInputFile(filePath string) UnpackerOption {
	return func(u *Unpacker) {
		u.inputFilePath = filePath
	}
}

// WithRawDataOutput enables raw data mode for the unpacker
func WithRawDataOutput() UnpackerOption {
	return func(u *Unpacker) {
		u.rawDataMode = true
	}
}

// WithForceOverwrite enables overwriting existing files during unpacking
func WithForceOverwrite() UnpackerOption {
	return func(u *Unpacker) {
		u.forceOverwrite = true
	}
}

// WithRestoreXattrs enables or disables extended attribute restoration
func WithRestoreXattrs(preserve bool) UnpackerOption {
	return func(u *Unpacker) {
		u.preserveXattrs = preserve
	}
}

// WithRestoreACLs enables or disables ACL restoration
func WithRestoreACLs(preserve bool) UnpackerOption {
	return func(u *Unpacker) {
		u.preserveACLs = preserve
	}
}

// WithPlatformCompatMode enables or disables platform compatibility mode
func WithPlatformCompatMode(enable bool) UnpackerOption {
	return func(u *Unpacker) {
		u.platformCompatMode = enable
	}
}

// WithDeleteExtraFiles enables deletion of files in destination that are not in the archive
func WithDeleteExtraFiles() UnpackerOption {
	return func(u *Unpacker) {
		u.deleteExtraFiles = true
	}
}

// WithVerboseCallback sets a callback function for verbose output during extraction
func WithVerboseCallback(callback VerboseCallback) UnpackerOption {
	return func(u *Unpacker) {
		u.verboseCallback = callback
	}
}
