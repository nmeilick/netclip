package compression

import (
	"compress/gzip"
	"io"
)

// GzipCompressor implements the Compressor interface for gzip
type GzipCompressor struct{}

// Compress returns a gzip writer
func (c *GzipCompressor) Compress(w io.Writer, level Level) (io.WriteCloser, error) {
	var gzipLevel int
	switch level {
	case Fast:
		gzipLevel = 1 // fast
	case Medium:
		gzipLevel = 5 // medium
	case Best:
		gzipLevel = 9 // best
	default:
		gzipLevel = 5 // default to medium
	}
	return gzip.NewWriterLevel(w, gzipLevel)
}

// Decompress returns a gzip reader
func (c *GzipCompressor) Decompress(r io.Reader) (io.ReadCloser, error) {
	return gzip.NewReader(r)
}
