package duration

import (
	"fmt"
	"time"

	"github.com/hako/durafmt"
	"github.com/xhit/go-str2duration/v2"
)

// Parse parses a duration string with fallbacks to multiple formats
func Parse(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}

	// Try str2duration parsing first (handles more formats)
	d, err := str2duration.ParseDuration(s)
	if err == nil {
		return d, nil
	}

	// Try durafmt as fallback for more human-readable formats
	duration, err := durafmt.ParseString(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration format: %w", err)
	}

	return duration.Duration(), nil
}

// String returns a human-readable string representation of a duration
func String(d time.Duration) string {
	return durafmt.Parse(d).String()
}
