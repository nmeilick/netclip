package paste

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	clientconfig "github.com/nmeilick/netclip/client/config"
	"github.com/nmeilick/netclip/common"
	"github.com/nmeilick/netclip/config"
	"github.com/nmeilick/netclip/response"
	"github.com/nmeilick/netclip/streampack"
	"github.com/rs/zerolog"
	"github.com/schollz/progressbar/v3"
	"github.com/urfave/cli/v2"
	"golang.org/x/term"
)

// Environment variable names
var (
	envPrefix     = strings.ToUpper(common.AppName) + "_"
	envPassword   = envPrefix + "PASSWORD"
	envAPIKey     = envPrefix + "API_KEY"
	envConfigPath = envPrefix + "CONFIG"
)

// Commands returns the CLI commands for the paste functionality
func Commands() *cli.Command {
	return &cli.Command{
		Name:    "paste",
		Aliases: []string{"p"},
		Usage:   "Paste files from the network clipboard",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "password",
				Aliases: []string{"p"},
				Usage:   "Decrypt the data with the given password",
				EnvVars: []string{envPassword},
			},
			&cli.StringFlag{
				Name:    "key",
				Aliases: []string{"k"},
				Usage:   "API key",
				EnvVars: []string{envAPIKey},
			},
			&cli.StringFlag{
				Name:    "config",
				Aliases: []string{"c"},
				Usage:   "Path to config file",
				EnvVars: []string{envConfigPath},
			},
			&cli.BoolFlag{
				Name:    "verbose",
				Aliases: []string{"v"},
				Usage:   "Enable verbose output",
			},
			&cli.BoolFlag{
				Name:    "force",
				Aliases: []string{"f"},
				Usage:   "Overwrite existing files",
			},
			&cli.StringFlag{
				Name:    "update",
				Aliases: []string{"u"},
				Usage:   "Control which existing files are updated; UPDATE={all,none,older} (if not specified, interactive mode is used)",
				Value:   "",
			},
			&cli.BoolFlag{
				Name:  "skip-tls-verify",
				Usage: "Skip TLS certificate verification",
			},
			&cli.BoolFlag{
				Name:    "no-xattrs",
				Aliases: []string{"X"},
				Usage:   "Disable extended attribute restoration",
			},
			&cli.BoolFlag{
				Name:    "no-acls",
				Aliases: []string{"A"},
				Usage:   "Disable ACL restoration",
			},
			&cli.BoolFlag{
				Name:  "no-platform-compat",
				Usage: "Disable platform compatibility mode",
			},
			&cli.BoolFlag{
				Name:    "delete",
				Aliases: []string{"d"},
				Usage:   "Delete files in destination that are not in the archive",
			},
		},
		Action: func(c *cli.Context) error {
			return runPaste(c)
		},
	}
}

// downloadMetadata downloads and parses the metadata for a clip
func downloadMetadata(client *http.Client, serverURL string, id string, apiKey string) (response.ClipMetadata, error) {
	var meta response.ClipMetadata

	// Ensure server URL doesn't have trailing slash
	baseURL := strings.TrimSuffix(serverURL, "/")
	metaURL := fmt.Sprintf("%s/api/v1/clips/%s/metadata", baseURL, id)
	metaReq, err := http.NewRequest("GET", metaURL, nil)
	if err != nil {
		return meta, fmt.Errorf("failed to create metadata request: %w", err)
	}

	// Set User-Agent header
	common.SetUserAgent(metaReq)

	if apiKey != "" {
		metaReq.Header.Set("X-API-Key", apiKey)
	}

	metaResp, err := client.Do(metaReq)
	if err != nil {
		return meta, fmt.Errorf("failed to download metadata: %w", err)
	}
	defer metaResp.Body.Close()

	if metaResp.StatusCode != http.StatusOK {
		// Try to parse error from response body
		var errorResp response.Error

		if err := json.NewDecoder(metaResp.Body).Decode(&errorResp); err == nil && errorResp.Error.Message != "" {
			return meta, fmt.Errorf("server error: %s", errorResp.Error.Message)
		}

		// Fallback to status code based error
		switch metaResp.StatusCode {
		case http.StatusNotFound:
			return meta, fmt.Errorf("clip not found: %s", id)
		case http.StatusForbidden:
			return meta, fmt.Errorf("access denied for clip: %s", id)
		default:
			return meta, fmt.Errorf("server returned error: %s", metaResp.Status)
		}
	}

	// Successfully retrieved metadata
	if err := json.NewDecoder(metaResp.Body).Decode(&meta); err != nil {
		return meta, fmt.Errorf("failed to parse metadata: %w", err)
	}

	return meta, nil
}

func runPaste(c *cli.Context) error {
	// Initialize logger
	log := common.NewLogger(c)
	if os.Getenv("DEBUG") == "1" {
		log = log.Level(zerolog.DebugLevel)
	}

	// Load configuration
	cfg, _, err := config.LoadClientConfig(c)
	if err != nil {
		log.Error().Err(err).Msg("Failed to load configuration")
		return err
	}

	// Get arguments
	args := c.Args().Slice()
	if len(args) < 1 {
		return fmt.Errorf("missing ID argument")
	}

	// Parse ID and optional password
	combinedID := args[0]
	id, password := common.ParseIDAndKey(combinedID)

	if len(args) > 2 {
		return fmt.Errorf("too many arguments")
	}

	// Check if password was provided via command line or env
	if pwd := c.String("password"); pwd != "" {
		password = pwd
	}

	// Otherwise use the configured password
	if !c.IsSet("password") && password == "" {
		password = cfg.Password
	}

	// Get API key from command line or config
	apiKey := cfg.APIKey
	if c.IsSet("key") {
		apiKey = c.String("key")
	}

	verbose := c.Bool("verbose")
	force := c.Bool("force")
	update := c.String("update")
	skipTLSVerify := c.Bool("skip-tls-verify") || cfg.TLSSkipVerify

	// Create a copy of the client config with the skip verify flag applied
	clientCfg := *cfg
	clientCfg.TLSSkipVerify = clientCfg.TLSSkipVerify || skipTLSVerify

	client := common.CreateHTTPClient(&clientCfg)

	log.Info().Str("id", id).Msg("Downloading clip metadata")

	// Download metadata to check if the clip exists and get information
	meta, err := downloadMetadata(client, cfg.ServerURL, id, apiKey)
	if err != nil {
		log.Error().Err(err).Str("id", id).Msg("Failed to download metadata")
		return err
	}

	log.Debug().
		Str("id", meta.ID).
		Time("created", meta.CreatedAt).
		Time("expires", meta.ExpiresAt).
		Int64("size", meta.Size).
		Bool("encrypted", meta.Encrypted).
		Msg("Received metadata")

	// Check if we need to decrypt but don't have a key
	if meta.Encrypted && password == "" {
		// If stdin is a terminal, prompt interactively for the password
		if common.IsTTY(os.Stdin) {
			fmt.Print("Password: ")
			passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
			fmt.Println() // Add a newline after password input

			if err != nil {
				log.Error().Err(err).Msg("Failed to read password")
				return fmt.Errorf("failed to read password: %w", err)
			}

			if len(passwordBytes) > 0 {
				password = string(passwordBytes)
				log.Debug().Msg("Password provided interactively")
			} else {
				log.Error().Msg("Empty password provided")
				return fmt.Errorf("no password provided")
			}
		} else {
			log.Error().Msg("Data is encrypted but no password provided")
			return fmt.Errorf("data is encrypted but no password provided")
		}
	}

	// Verify password if verification data is available
	if meta.Archive.PasswordVerification != nil && password != "" {
		log.Debug().Msg("Verifying password using KDF")

		pv := meta.Archive.PasswordVerification
		params := streampack.PasswordVerificationParams{
			Iterations: pv.Iterations,
			Memory:     pv.Memory,
			Threads:    pv.Threads,
			KeyLength:  uint32(len(pv.VerificationKey)),
		}

		if !streampack.VerifyPassword(password, pv.Salt, pv.VerificationKey, params) {
			log.Error().Msg("Invalid password")
			return fmt.Errorf("invalid password")
		}

		log.Debug().Msg("Password verified successfully")
	}

	var destPath string
	// Check archive type and handle accordingly
	switch meta.Archive.Type {
	case streampack.TypeRaw:
		log.Debug().Msg("Archive type: Raw data")
		if len(args) > 1 {
			log.Error().Msg("Raw data can only be output to stdout")
			return fmt.Errorf("raw data can only be output to stdout")
		}
	case streampack.TypeTar:
		log.Debug().Msg("Archive type: TAR archive")
		if len(args) < 2 {
			log.Error().Msg("No destination path specified for archive")
			return fmt.Errorf("please specify a destination path")
		}
		destPath = args[1]
		if destPath == "" {
			log.Error().Msg("Empty destination path")
			return fmt.Errorf("destination path may not be empty")
		}
		stat, err := os.Stat(destPath)
		if err != nil {
			log.Error().Err(err).Str("path", destPath).Msg("Invalid destination path")
			return fmt.Errorf("destination path: %w", err)
		} else if !stat.IsDir() {
			log.Error().Str("path", destPath).Msg("Destination path is not a directory")
			return fmt.Errorf("destination path is not a directory: %s", destPath)
		}
	default:
		log.Error().Str("type", string(meta.Archive.Type)).Msg("Unsupported archive type")
		return fmt.Errorf("unsupported archive type: %s", meta.Archive.Type)
	}

	// Check if stdout is a terminal
	isTTY := common.IsTTY(os.Stdout)

	log.Info().
		Str("id", id).
		Str("destination", destPath).
		Bool("force", force).
		Msg("Downloading and extracting data")

	noXattrs := c.Bool("no-xattrs")
	noACLs := c.Bool("no-acls")
	noPlatformCompat := c.Bool("no-platform-compat")
	deleteExtraFiles := c.Bool("delete")

	_, _, err = streamData(id, destPath, password, force, update, cfg, apiKey, skipTLSVerify, verbose, !isTTY, noXattrs, noACLs, noPlatformCompat, deleteExtraFiles)
	if err != nil {
		log.Error().Err(err).Msg("Failed to stream data")
		return err
	}

	log.Info().Msg("Download complete")
	return nil
}

// streamData downloads and extracts data in a streaming fashion
func streamData(id string, destPath string, password string, force bool, update string, cfg *clientconfig.Config, apiKey string, skipTLSVerify bool, verbose bool, isTTY bool, noXattrs bool, noACLs bool, noPlatformCompat bool, deleteExtraFiles bool) (bool, bool, error) {
	// Create request to server
	baseURL := strings.TrimSuffix(cfg.ServerURL, "/")
	url := fmt.Sprintf("%s/api/v1/clips/%s", baseURL, id)

	// Create HTTP client with proper TLS configuration
	clientCfg := *cfg
	clientCfg.TLSSkipVerify = clientCfg.TLSSkipVerify || skipTLSVerify
	client := common.CreateHTTPClient(&clientCfg)

	// Create request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, false, fmt.Errorf("failed to create request: %w", err)
	}

	// Set User-Agent header
	common.SetUserAgent(req)

	// Add API key if provided
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		return false, false, fmt.Errorf("failed to download data: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Try to parse error from response body
		var errorResp response.Error

		if err := json.NewDecoder(resp.Body).Decode(&errorResp); err == nil && errorResp.Error.Message != "" {
			return false, false, fmt.Errorf("server error: %s", errorResp.Error.Message)
		}

		// Fallback to status code based error
		switch resp.StatusCode {
		case http.StatusNotFound:
			return false, false, fmt.Errorf("clip not found: %s", id)
		case http.StatusForbidden:
			return false, false, fmt.Errorf("access denied for clip: %s", id)
		default:
			return false, false, fmt.Errorf("server returned error: %s", resp.Status)
		}
	}

	header, rawHeader, err := streampack.ReadHeader(resp.Body)
	if err != nil {
		return false, false, fmt.Errorf("failed to read header data: %w", err)
	}

	isRaw := header.Type == streampack.TypeRaw
	isEncrypted := header.EncryptionType != ""

	// Check if we need to decrypt but don't have a key
	if isEncrypted && password == "" {
		return false, false, fmt.Errorf("data is encrypted but no decryption key provided")
	}

	// Get content length if available
	contentLength := resp.ContentLength

	// Create a progress bar if stdout is a TTY and we have content length
	var bar *progressbar.ProgressBar
	if !isRaw && common.IsTTY(os.Stdout) {
		size := contentLength
		if size <= 0 {
			size = -1
		}

		bar = progressbar.NewOptions64(
			size,
			progressbar.OptionSetWriter(os.Stdout),
			progressbar.OptionSetDescription("Pasting"),
			progressbar.OptionShowBytes(true),
			progressbar.OptionSetWidth(40),
			progressbar.OptionClearOnFinish(),
			progressbar.OptionSetTheme(progressbar.ThemeASCII),
		)
	}

	var inputReader io.Reader = io.MultiReader(bytes.NewReader(rawHeader), resp.Body)
	if bar != nil {
		inputReader = io.TeeReader(inputReader, bar)
	}

	// For raw data, handle differently
	if isRaw {
		// Create unpacker options for streaming
		var options []streampack.UnpackerOption
		options = append(options, streampack.WithInput(inputReader))
		options = append(options, streampack.WithRawDataOutput())

		// Add decryption if key is provided
		if password != "" {
			options = append(options, streampack.WithDecryption(password))
		}

		// Create and run unpacker
		unpacker := streampack.NewUnpacker(options...)

		if err := unpacker.Unpack(); err != nil {
			return isRaw, isEncrypted, fmt.Errorf("failed to unpack data: %w", err)
		}
		return isRaw, isEncrypted, nil
	} else {
		if verbose {
			fmt.Fprintf(os.Stderr, "Extracting files to: %s\n", destPath)
		}

		// Create unpacker options for streaming
		var options []streampack.UnpackerOption
		options = append(options, streampack.WithInput(inputReader))
		options = append(options, streampack.WithDestination(destPath))

		// Add decryption if key is provided
		if password != "" {
			options = append(options, streampack.WithDecryption(password))
		}

		// Handle file overwrite options
		if force {
			options = append(options, streampack.WithForceOverwrite())
		} else {
			// Set update policy based on the update flag
			switch strings.ToLower(update) {
			case "all":
				options = append(options, streampack.WithUpdatePolicy(streampack.UpdateAll))
			case "none":
				options = append(options, streampack.WithUpdatePolicy(streampack.UpdateNone))
			case "older":
				options = append(options, streampack.WithUpdatePolicy(streampack.UpdateOlder))
			case "": // No update policy specified
				// Enable interactive confirmation by default when no policy is set
				if common.IsTTY(os.Stdin) && !force {
					options = append(options, streampack.WithInteractiveConfirmation())
					options = append(options, streampack.WithOverwriteCallback(promptOverwrite))
				} else {
					// Default to UpdateAll if not interactive
					options = append(options, streampack.WithUpdatePolicy(streampack.UpdateAll))
				}
			}
		}

		// Handle xattr and ACL options
		if noXattrs {
			options = append(options, streampack.WithRestoreXattrs(false))
			if verbose {
				fmt.Fprintln(os.Stderr, "Extended attribute restoration disabled")
			}
		}

		if noACLs {
			options = append(options, streampack.WithRestoreACLs(false))
			if verbose {
				fmt.Fprintln(os.Stderr, "ACL restoration disabled")
			}
		}

		if noPlatformCompat {
			options = append(options, streampack.WithPlatformCompatMode(false))
			if verbose {
				fmt.Fprintln(os.Stderr, "Platform compatibility mode disabled")
			}
		}

		// Add verbose callback if verbose mode is enabled
		if verbose {
			options = append(options, streampack.WithVerboseCallback(func(action, path string) {
				fmt.Fprintf(os.Stderr, "%s: %s\n", action, path)
			}))
		}

		// Add delete option if enabled
		if deleteExtraFiles {
			options = append(options, streampack.WithDeleteExtraFiles())
			if verbose {
				fmt.Fprintln(os.Stderr, "Delete mode enabled: will remove files not in archive")
			}
		}

		// Create and run unpacker
		unpacker := streampack.NewUnpacker(options...)

		if bar != nil {
			bar.Finish()
		}

		if err := unpacker.Unpack(); err != nil {
			return isRaw, isEncrypted, fmt.Errorf("failed to unpack data: %w", err)
		}
		return isRaw, isEncrypted, nil
	}
}

func processFileData(data *os.File, destPath string, password string, force bool, verbose bool, noXattrs bool, noACLs bool, noPlatformCompat bool, deleteExtraFiles bool) error {
	// Create destination directory if it doesn't exist
	if err := os.MkdirAll(destPath, 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}

	// Create unpacker options
	var options []streampack.UnpackerOption
	options = append(options, streampack.WithInput(data))
	options = append(options, streampack.WithDestination(destPath))

	// Add decryption if key is provided
	if password != "" {
		options = append(options, streampack.WithDecryption(password))
	}

	// Add force overwrite if enabled
	if force {
		options = append(options, streampack.WithForceOverwrite())
	}

	// Handle xattr and ACL options
	if noXattrs {
		options = append(options, streampack.WithRestoreXattrs(false))
	}

	if noACLs {
		options = append(options, streampack.WithRestoreACLs(false))
	}

	if noPlatformCompat {
		options = append(options, streampack.WithPlatformCompatMode(false))
	}

	// Create and run unpacker
	unpacker := streampack.NewUnpacker(options...)

	if verbose {
		fmt.Fprintln(os.Stderr, "Unpacking and extracting files...")
	}

	if err := unpacker.Unpack(); err != nil {
		return fmt.Errorf("failed to unpack data: %w", err)
	}

	// Get list of extracted files for verbose output
	if verbose {
		extractedFiles := []string{}
		err := filepath.Walk(destPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if path != destPath {
				relPath, _ := filepath.Rel(destPath, path)
				extractedFiles = append(extractedFiles, relPath)
			}
			return nil
		})

		if err == nil && len(extractedFiles) > 0 {
			fmt.Fprintln(os.Stderr, "Extracted files:")
			for _, file := range extractedFiles {
				fmt.Fprintf(os.Stderr, "  - %s\n", file)
			}
		}

		fmt.Fprintf(os.Stderr, "Files extracted successfully to: %s\n", destPath)
	} else {
		fmt.Fprintf(os.Stderr, "Data extracted to %s\n", destPath)
	}

	return nil
}
