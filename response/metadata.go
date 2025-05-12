package response

import (
	"time"

	"github.com/nmeilick/netclip/streampack"
)

// ClipMetadata represents metadata for a clip
type ClipMetadata struct {
	ID               string                   `json:"id"`
	CreatedAt        time.Time                `json:"created_at"`
	ExpiresAt        time.Time                `json:"expires_at"`
	Size             int64                    `json:"size"`
	UncompressedSize int64                    `json:"uncompressedSize,omitempty"`
	Archive          streampack.ArchiveHeader `json:"archive"`
	IsStdin          bool                     `json:"is_stdin,omitempty"`
	Encrypted        bool                     `json:"encrypted,omitempty"`
	Comment          string                   `json:"comment,omitempty"`
}
