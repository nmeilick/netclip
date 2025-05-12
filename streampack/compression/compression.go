package compression

import (
	"fmt"
	"io"
)

// CompressionType identifies the compression algorithm
type CompressionType string

const (
	NoCompression   CompressionType = "none"
	GzipCompression CompressionType = "gzip"
	ZstdCompression CompressionType = "zstd"
	Lz4Compression  CompressionType = "lz4"
)

// Level represents compression level
type Level int

const (
	Fast Level = iota
	Medium
	Best
)

// Compressor defines the interface for compression algorithms
type Compressor interface {
	Compress(w io.Writer, level Level) (io.WriteCloser, error)
	Decompress(r io.Reader) (io.ReadCloser, error)
}

// GetCompressor returns the appropriate compressor based on type
func GetCompressor(compressionType CompressionType) (Compressor, error) {
	switch compressionType {
	case GzipCompression:
		return &GzipCompressor{}, nil
	case ZstdCompression:
		return &ZstdCompressor{}, nil
	case Lz4Compression:
		return &Lz4Compressor{}, nil
	case NoCompression:
		return nil, nil
	default:
		return nil, fmt.Errorf("unknown compression type: %s", compressionType)
	}
}
