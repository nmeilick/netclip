package compression

import (
	"io"

	"github.com/pierrec/lz4/v4"
)

// Lz4Compressor implements the Compressor interface for LZ4
type Lz4Compressor struct{}

// Compress returns an LZ4 writer
func (c *Lz4Compressor) Compress(w io.Writer, level Level) (io.WriteCloser, error) {
	lz4Writer := lz4.NewWriter(w)

	var lz4Level lz4.CompressionLevel
	switch level {
	case Fast:
		lz4Level = lz4.Fast
	case Medium:
		lz4Level = lz4.Level5
	case Best:
		lz4Level = lz4.Level9
	default:
		lz4Level = lz4.Level5
	}

	lz4Writer.Apply(lz4.CompressionLevelOption(lz4Level))
	return lz4Writer, nil
}

// Decompress returns an LZ4 reader
func (c *Lz4Compressor) Decompress(r io.Reader) (io.ReadCloser, error) {
	return io.NopCloser(lz4.NewReader(r)), nil
}
