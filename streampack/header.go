package streampack

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/nmeilick/netclip/streampack/compression"
	"github.com/nmeilick/netclip/streampack/encryption"
)

const (
	// MagicHeader is the identifier for streampack archives
	MagicHeader = "SPAK01"
)

const (
	TypeTar = "tar"
	TypeRaw = "raw"
)

// PasswordVerificationHeader contains info to quickly verify the password
type PasswordVerificationHeader struct {
	Salt            []byte `json:"s,omitempty"` // Random salt
	VerificationKey []byte `json:"v,omitempty"` // Derived verification key
	Algorithm       string `json:"a,omitempty"` // KDF algorithm (e.g., "argon2id")
	Iterations      uint32 `json:"i,omitempty"` // Number of iterations
	Memory          uint32 `json:"m,omitempty"` // Memory in KiB
	Threads         uint8  `json:"t,omitempty"` // Number of threads
}

// ArchiveHeader contains metadata about the archive
type ArchiveHeader struct {
	Type            string                      `json:"t"`            // "tar" or "raw"
	CompressionType compression.CompressionType `json:"ct"`           // compression type
	EncryptionType  encryption.EncryptionType   `json:"et,omitempty"` // encryption type (if present, encryption is enabled)
	Metadata        map[string]interface{}      `json:"m,omitempty"`  // optional metadata
	// Password verification data
	PasswordVerification *PasswordVerificationHeader `json:"pv,omitempty"`
	// Platform information
	Platform string `json:"platform,omitempty"` // Platform where archive was created
	// Feature flags
	Features struct {
		Xattrs bool `json:"xattrs,omitempty"` // Archive contains xattr data
		ACLs   bool `json:"acls,omitempty"`   // Archive contains ACL data
	} `json:"features,omitempty"`
}

// WriteHeader writes the archive header to the given writer
func WriteHeader(w io.Writer, header ArchiveHeader) ([]byte, error) {
	var buf bytes.Buffer

	// Write magic header
	if _, err := buf.Write([]byte(MagicHeader)); err != nil {
		return nil, fmt.Errorf("failed to write magic header: %w", err)
	}

	// Marshal header to JSON
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal header: %w", err)
	}

	// Write JSON header followed by newline
	if _, err := buf.Write(headerJSON); err != nil {
		return nil, fmt.Errorf("failed to write header JSON: %w", err)
	}
	if _, err := buf.Write([]byte("\n")); err != nil {
		return nil, fmt.Errorf("failed to write header newline: %w", err)
	}

	if _, err := w.Write(buf.Bytes()); err != nil {
		return nil, fmt.Errorf("failed to write header: %w", err)
	}

	return buf.Bytes(), nil
}

// ReadHeader reads and parses the archive header from the given reader
func ReadHeader(r io.Reader) (*ArchiveHeader, []byte, error) {
	var header *ArchiveHeader
	var rawHeader bytes.Buffer

	// Read magic header
	magicBuf := make([]byte, len(MagicHeader))
	if _, err := io.ReadFull(r, magicBuf); err != nil {
		return nil, nil, fmt.Errorf("failed to read magic header: %w", err)
	}
	rawHeader.Write(magicBuf)

	if string(magicBuf) != MagicHeader {
		return nil, nil, fmt.Errorf("invalid magic header: expected %s, got %s", MagicHeader, string(magicBuf))
	}

	// Read header JSON line
	var jsonLine strings.Builder
	buf := make([]byte, 1)
	for {
		if _, err := r.Read(buf); err != nil {
			return nil, nil, fmt.Errorf("failed to read header JSON: %w", err)
		}
		jsonLine.Write(buf)
		if buf[0] == '\n' {
			break
		}
	}

	// Unmarshal header
	if err := json.Unmarshal([]byte(jsonLine.String()), &header); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal header: %w", err)
	}
	rawHeader.Write([]byte(jsonLine.String()))

	return header, rawHeader.Bytes(), nil
}
