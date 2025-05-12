package compression

import (
	"io"

	"github.com/klauspost/compress/zstd"
)

// ZstdCompressor implements the Compressor interface for Zstandard
type ZstdCompressor struct{}

// Compress returns a zstd writer
func (c *ZstdCompressor) Compress(w io.Writer, level Level) (io.WriteCloser, error) {
	var opts zstd.EOption
	switch level {
	case Fast:
		opts = zstd.WithEncoderLevel(zstd.SpeedFastest)
	case Medium:
		opts = zstd.WithEncoderLevel(zstd.SpeedDefault)
	case Best:
		opts = zstd.WithEncoderLevel(zstd.SpeedBestCompression)
	default:
		opts = zstd.WithEncoderLevel(zstd.SpeedDefault)
	}

	encoder, err := zstd.NewWriter(w, opts)
	if err != nil {
		return nil, err
	}

	return encoder, nil
}

// Decompress returns a zstd reader
func (c *ZstdCompressor) Decompress(r io.Reader) (io.ReadCloser, error) {
	decoder, err := zstd.NewReader(r)
	if err != nil {
		return nil, err
	}

	return io.NopCloser(decoder), nil
}
