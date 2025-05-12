package common

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/mattn/go-colorable"
	"github.com/mattn/go-isatty"
	"github.com/rs/zerolog"
	"github.com/urfave/cli/v2"
)

const (
	keySeparator = ":"
	tagSeparator = "@"
)

var (
	validIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*[a-zA-Z0-9]$|^[a-zA-Z0-9]$`)
)

// ExitWithError prints an error message and exits
func ExitWithError(err error) {
	fmt.Fprintf(os.Stderr, "Error: %s\n", err)
	os.Exit(1)
}

// GeneratePassword generates a random encryption password
func GeneratePassword(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	b := make([]byte, length)
	for i := range b {
		b[i] = charset[r.Intn(len(charset))]
	}

	return string(b)
}

// ParseIDAndKey parses an ID with optional encryption key
// Deprecated: Use ParseID instead which also handles tags
func ParseIDAndKey(combined string) (id, key string) {
	parts := strings.SplitN(combined, keySeparator, 2)
	id = parts[0]
	if len(parts) > 1 {
		key = parts[1]
	}
	return
}

// ParseID parses an ID string into its components: id, key, and tag
// Key is indicated by a leading : and tag by a leading @
func ParseID(combined string) (id, key, tag string) {
	if regexp.MustCompile(`(:[^@]*)`).FindString(combined); key != "" {
		combined = strings.Replace(combined, key, "", 1)
		key = strings.TrimSpace(key[1:])
	}

	if regexp.MustCompile(`(@[^:]*)`).FindString(combined); tag != "" {
		combined = strings.Replace(combined, tag, "", 1)
		tag = strings.TrimSpace(tag[1:])
	}
	id = strings.TrimSpace(combined)

	return id, key, tag
}

// CombineIDAndKey combines an ID and encryption key
func CombineIDAndKey(id, key string) string {
	if key == "" {
		return id
	}
	return id + keySeparator + key
}

// HasPrefix checks if an ID contains a prefix (has a period)
func HasPrefix(id string) bool {
	return strings.Contains(id, ".")
}

// GetPrefix extracts the prefix from an ID
func GetPrefix(id string) string {
	if !HasPrefix(id) {
		return ""
	}
	parts := strings.SplitN(id, ".", 2)
	return parts[0]
}

// IsValidID checks if an ID is valid and file-system compatible
func IsValidID(id string) bool {
	if id == "" {
		return false
	}

	// Use regexp to validate the ID format
	return validIDPattern.MatchString(id)
}

// IsTTY checks if the given file is a TTY
func IsTTY(file *os.File) bool {
	return isatty.IsTerminal(file.Fd()) || isatty.IsCygwinTerminal(file.Fd())
}

// NewLogger creates a new zerolog logger with appropriate settings
// It configures colorful output when stderr is a TTY and sets the log level
// based on the verbose flag from the CLI context
func NewLogger(c *cli.Context) zerolog.Logger {
	// Set time format with millisecond precision
	zerolog.TimeFieldFormat = "2006-01-02 15:04:05.000"

	// Set global time function to use UTC
	zerolog.TimestampFunc = func() time.Time {
		return time.Now().UTC()
	}

	// Determine log level based on verbose flag
	level := zerolog.FatalLevel
	if c.Bool("verbose") {
		level = zerolog.InfoLevel
	}

	// Create console writer with colors if stderr is a TTY
	var consoleWriter io.Writer
	if IsTTY(os.Stderr) {
		consoleWriter = zerolog.ConsoleWriter{
			Out:        colorable.NewColorableStderr(),
			TimeFormat: "2006-01-02 15:04:05.000",
			NoColor:    false,
		}
	} else {
		consoleWriter = os.Stderr
	}

	// Create and return configured logger
	return zerolog.New(consoleWriter).
		Level(level).
		With().
		Timestamp().
		Str("component", c.Command.Name).
		Logger()
}

// Save safely writes data to a file by first writing to a temporary file
// in the same directory and then renaming it to the destination file.
func Save(data []byte, destPath string) error {
	// Create the directory if it doesn't exist
	dir := filepath.Dir(destPath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Create a temporary file in the same directory
	tempFile, err := ioutil.TempFile(dir, filepath.Base(destPath)+".tmp.*")
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	tempPath := tempFile.Name()

	// Ensure the temp file is removed if we don't complete successfully
	defer func() {
		tempFile.Close()
		// Only attempt to remove if the rename wasn't successful
		if _, err := os.Stat(tempPath); err == nil {
			os.Remove(tempPath)
		}
	}()

	// Write data to the temporary file
	if _, err := tempFile.Write(data); err != nil {
		return fmt.Errorf("failed to write to temporary file: %w", err)
	}

	// Close the file before renaming
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("failed to close temporary file: %w", err)
	}

	// Rename the temporary file to the destination
	if err := os.Rename(tempPath, destPath); err != nil {
		return fmt.Errorf("failed to rename temporary file: %w", err)
	}

	return nil
}

func LoadJSON(path string, v interface{}) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return json.NewDecoder(file).Decode(v)
}

func SaveJSON(path string, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return Save(data, path)
}

func EndOfDay(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 23, 59, 59, 0, t.Location())
}

// CountReader wraps an io.Reader and counts the number of bytes read
type CountReader struct {
	Reader io.Reader
	Count  uint64
}

// Read implements the io.Reader interface
func (cr *CountReader) Read(p []byte) (n int, err error) {
	n, err = cr.Reader.Read(p)
	cr.Count += uint64(n)
	return
}

var reTokenSep = regexp.MustCompile(`[, ]+`)

func Tokens(list ...string) (tokens []string) {
	seen := map[string]bool{}
	for _, s := range list {
		for _, t := range reTokenSep.Split(strings.ToLower(s), -1) {
			if t = strings.TrimSpace(t); t != "" && !seen[t] {
				seen[t] = true
			}
			tokens = append(tokens, t)
		}
	}
	return
}
