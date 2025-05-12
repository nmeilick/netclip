package streampack

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/nmeilick/netclip/streampack/compression"
	"github.com/nmeilick/netclip/streampack/encryption"
	"github.com/nmeilick/netclip/streampack/platform"
)

// Packer handles the creation of compressed and encrypted tar archives
type Packer struct {
	sources            []string
	rawDataReader      io.Reader
	output             io.Writer
	outputFile         string
	compressionType    compression.CompressionType
	compressionLevel   compression.Level
	encryptionEnabled  bool
	encryptionPassword string
	encryptionType     encryption.EncryptionType
	uidCache           map[uint32]string
	gidCache           map[uint32]string
	metadata           map[string]interface{}
	// Platform-specific features
	preserveXattrs bool
	preserveACLs   bool
	// File attribute maps
	xattrMap map[string]map[string][]byte // path -> name -> value
	aclMap   map[string][]byte            // path -> serialized ACL

	UncompressedSize int64
}

// fileToProcess represents a file to be added to the archive
type fileToProcess struct {
	path        string
	baseDir     string
	stripPrefix bool
}

// NewPacker creates a new Packer with the given options
func NewPacker(options ...PackerOption) (*Packer, error) {
	p := &Packer{
		sources:            []string{},
		rawDataReader:      nil,
		output:             nil,
		outputFile:         "",
		compressionType:    compression.Lz4Compression,
		compressionLevel:   compression.Medium,
		encryptionEnabled:  false,
		encryptionPassword: "",
		encryptionType:     encryption.AGEEncryption, // Default to AGE
		uidCache:           make(map[uint32]string),
		gidCache:           make(map[uint32]string),
		metadata:           nil,
		// Enable platform-specific features by default
		preserveXattrs: platform.XattrSupported(),
		preserveACLs:   platform.ACLSupported(),
		// Initialize maps
		xattrMap: make(map[string]map[string][]byte),
		aclMap:   make(map[string][]byte),
	}

	for _, option := range options {
		if err := option(p); err != nil {
			return nil, fmt.Errorf("invalid option: %w", err)
		}
	}

	return p, nil
}

// Pack creates a tar archive from the specified directories and files
func (p *Packer) Pack() error {
	if p.rawDataReader == nil && len(p.sources) == 0 {
		return fmt.Errorf("no input specified")
	}

	// If output file path is specified, create the file
	if p.outputFile != "" {
		if p.output != nil {
			return fmt.Errorf("outputFile and output may not both be set")
		}
		file, err := os.OpenFile(p.outputFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer file.Close()
		p.output = file
	}

	if p.output == nil {
		return fmt.Errorf("no output specified")
	}

	// Write header with archive metadata
	header := ArchiveHeader{
		Type:            TypeTar,
		CompressionType: p.compressionType,
		Metadata:        p.metadata,
		Platform:        runtime.GOOS,
	}
	if p.encryptionEnabled {
		header.EncryptionType = p.encryptionType

		// Generate password verification data
		params := DefaultVerificationParams()
		salt, verificationKey, err := GenerateVerificationData(p.encryptionPassword, params)
		if err != nil {
			return fmt.Errorf("failed to generate password verification data: %w", err)
		}

		// Add verification data to header
		header.PasswordVerification = &PasswordVerificationHeader{
			Salt:            salt,
			VerificationKey: verificationKey,
			Algorithm:       "argon2id",
			Iterations:      params.Iterations,
			Memory:          params.Memory,
			Threads:         params.Threads,
		}
	}
	if p.rawDataReader != nil {
		header.Type = TypeRaw
	}

	// Set feature flags
	header.Features.Xattrs = p.preserveXattrs
	header.Features.ACLs = p.preserveACLs

	if _, err := WriteHeader(p.output, header); err != nil {
		return fmt.Errorf("failed to write archive header: %w", err)
	}

	// Set up the pipeline: tar -> compress -> encrypt -> output
	var writer io.WriteCloser = nopWriteCloser{p.output}
	var closers []io.Closer

	// Add encryption if enabled
	if p.encryptionEnabled {
		encryptor, err := encryption.GetEncryptor(p.encryptionType)
		if err != nil {
			return fmt.Errorf("encryption error: %w", err)
		}
		encWriter, err := encryptor.Encrypt(writer, p.encryptionPassword)
		if err != nil {
			return fmt.Errorf("failed to create encryption writer: %w", err)
		}
		closers = append(closers, encWriter)
		writer = encWriter
	}

	// Add compression if enabled
	if p.compressionType != compression.NoCompression {
		compressor, err := compression.GetCompressor(compression.CompressionType(p.compressionType))
		if err != nil {
			return fmt.Errorf("compression error: %w", err)
		}
		if compressor == nil {
			return fmt.Errorf("no compressor available for type: %s", p.compressionType)
		}
		compWriter, err := compressor.Compress(writer, compression.Level(p.compressionLevel))
		if err != nil {
			return fmt.Errorf("failed to create compression writer: %w", err)
		}
		closers = append(closers, compWriter)
		writer = compWriter
	}

	// Handle raw data mode
	if p.rawDataReader != nil {
		// In raw data mode, we don't use tar format
		// Create a counting reader to track uncompressed size
		countingReader := &countingReader{r: p.rawDataReader}
		if _, err := io.Copy(writer, countingReader); err != nil {
			return fmt.Errorf("failed to write raw data: %w", err)
		}
		p.UncompressedSize = countingReader.bytesRead
	} else {
		// Create tar writer
		tarWriter := tar.NewWriter(writer)
		closers = append(closers, tarWriter)

		// Reset uncompressed size counter
		p.UncompressedSize = 0

		// Process each input path
		for _, path := range p.sources {
			info, err := os.Lstat(path)
			if err != nil {
				return fmt.Errorf("failed to stat path %s: %w", path, err)
			}

			if !info.IsDir() {
				// It's a single file or other non-directory entity, add it directly
				if err := p.addToTar(path, tarWriter, "", true); err != nil {
					return err
				}
				continue
			}

			// It's a directory
			stripPrefix := false
			baseDir := path

			// Check if path ends with separator
			if strings.HasSuffix(path, string(filepath.Separator)) {
				stripPrefix = true
				baseDir = strings.TrimSuffix(path, string(filepath.Separator))
			}

			// Process the directory using a custom directory walker
			if err := p.processDirectory(path, tarWriter, baseDir, stripPrefix); err != nil {
				return err
			}
		}
	}

	// Close all writers in reverse order
	for i := len(closers) - 1; i >= 0; i-- {
		if err := closers[i].Close(); err != nil {
			return fmt.Errorf("failed to close writer: %w", err)
		}
	}

	return nil
}

// addToTar adds a file system entity to the tar archive
func (p *Packer) addToTar(path string, tarWriter *tar.Writer, baseDir string, stripPrefix bool) error {
	// Get file info without following symlinks
	info, err := platform.GetFileInfo(path)
	if err != nil {
		return fmt.Errorf("failed to lstat %s: %w", path, err)
	}

	// Create header based on file type
	var header *tar.Header
	switch {
	case info.Mode()&os.ModeSymlink != 0:
		// It's a symbolic link
		link, err := platform.ReadLink(path)
		if err != nil {
			return fmt.Errorf("failed to read symlink %s: %w", path, err)
		}
		header, err = tar.FileInfoHeader(info, link)
		if err != nil {
			return fmt.Errorf("failed to create tar header for symlink %s: %w", path, err)
		}
	case info.Mode()&os.ModeDevice != 0, info.Mode()&os.ModeCharDevice != 0:
		// It's a device file
		header, err = tar.FileInfoHeader(info, "")
		if err != nil {
			return fmt.Errorf("failed to create tar header for device %s: %w", path, err)
		}
		// Set device numbers (platform-specific)
		if platform.IsUnix() {
			platform.SetDeviceNumbers(header, info)
		}
	case info.Mode()&os.ModeNamedPipe != 0:
		// It's a named pipe
		header, err = tar.FileInfoHeader(info, "")
		if err != nil {
			return fmt.Errorf("failed to create tar header for named pipe %s: %w", path, err)
		}
	default:
		// Regular file or directory
		header, err = tar.FileInfoHeader(info, "")
		if err != nil {
			return fmt.Errorf("failed to create tar header for %s: %w", path, err)
		}
	}

	// Set owner and group
	if platform.IsUnix() {
		platform.SetUnixOwnership(header, info, p.uidCache, p.gidCache)
	} else if platform.IsWindows() {
		// On Windows, we don't have the same UID/GID concept
		// But we can try to get the owner name for informational purposes
		// This is not used during extraction on Windows
		header.Uname = getWindowsOwner(path)
	}

	// Get and store extended attributes if enabled
	if p.preserveXattrs && platform.XattrSupported() && !info.Mode().IsDir() {
		xattrs, err := platform.GetXattrs(path)
		if err == nil && len(xattrs) > 0 {
			// Store in PAX records
			if header.PAXRecords == nil {
				header.PAXRecords = make(map[string]string)
			}

			// Also store in our map for later reference
			p.xattrMap[path] = xattrs

			// Mark that this file has xattrs
			header.PAXRecords["SCHILY.xattr.count"] = fmt.Sprintf("%d", len(xattrs))

			// Store each xattr in a PAX record
			for name, value := range xattrs {
				// Use a special prefix to identify xattrs
				header.PAXRecords["SCHILY.xattr."+name] = string(value)
			}
		}
	}

	// Get and store ACLs if enabled
	if p.preserveACLs && platform.ACLSupported() {
		aclData, err := platform.GetACL(path)
		if err == nil && len(aclData) > 0 {
			// Store in PAX records
			if header.PAXRecords == nil {
				header.PAXRecords = make(map[string]string)
			}

			// Also store in our map for later reference
			p.aclMap[path] = aclData

			// Store ACL data in a PAX record
			header.PAXRecords["SCHILY.acl.data"] = string(aclData)
		}
	}

	// Determine the name to use in the tar archive
	if stripPrefix {
		// Strip the entire prefix path
		header.Name = filepath.ToSlash(filepath.Base(path))
	} else if baseDir != "" {
		// Use the last directory name as the prefix
		relPath, err := filepath.Rel(filepath.Dir(baseDir), path)
		if err != nil {
			return fmt.Errorf("failed to get relative path for %s: %w", path, err)
		}
		header.Name = filepath.ToSlash(relPath)
	} else {
		// Use the full path
		header.Name = filepath.ToSlash(path)
	}

	// Write header
	if err := tarWriter.WriteHeader(header); err != nil {
		return fmt.Errorf("failed to write tar header for %s: %w", path, err)
	}

	// If it's a regular file, copy its contents
	if info.Mode().IsRegular() {
		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("failed to open file %s: %w", path, err)
		}
		defer file.Close()

		// Track the size of the file
		written, err := io.Copy(tarWriter, file)
		if err != nil {
			return fmt.Errorf("failed to copy file %s to tar: %w", path, err)
		}

		// Add to the total uncompressed size
		p.UncompressedSize += written
	}

	return nil
}

// getWindowsOwner gets the owner of a file on Windows
func getWindowsOwner(path string) string {
	if !platform.IsWindows() {
		return ""
	}

	// This is a simplified implementation
	// A full implementation would use the Windows API to get the owner SID
	// and then look up the account name
	return ""
}

// processDirectory processes a directory and its contents, adding them to the tar archive
func (p *Packer) processDirectory(dirPath string, tarWriter *tar.Writer, baseDir string, stripPrefix bool) error {
	// First, add the directory itself if it's not the root of a strip-prefix path
	if !stripPrefix {
		if err := p.addToTar(dirPath, tarWriter, baseDir, stripPrefix); err != nil {
			return err
		}
	}

	// Read directory entries
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return fmt.Errorf("failed to read directory %s: %w", dirPath, err)
	}

	// Sort entries alphabetically
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	// Process each entry
	for _, entry := range entries {
		entryPath := filepath.Join(dirPath, entry.Name())

		// If it's a directory, process it recursively
		if entry.IsDir() {
			if err := p.processDirectory(entryPath, tarWriter, baseDir, stripPrefix); err != nil {
				return err
			}
		} else {
			// Otherwise, add the file to the tar
			if err := p.addToTar(entryPath, tarWriter, baseDir, stripPrefix); err != nil {
				return err
			}
		}
	}

	return nil
}

// nopWriteCloser wraps an io.Writer to provide a no-op Close method
type nopWriteCloser struct {
	io.Writer
}

func (nopWriteCloser) Close() error { return nil }

// countingReader wraps an io.Reader to count bytes read
type countingReader struct {
	r         io.Reader
	bytesRead int64
}

func (cr *countingReader) Read(p []byte) (n int, err error) {
	n, err = cr.r.Read(p)
	cr.bytesRead += int64(n)
	return
}
