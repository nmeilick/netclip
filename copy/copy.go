package copy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	uri "net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/adrg/xdg"
	"github.com/dustin/go-humanize"
	"github.com/mdp/qrterminal/v3"
	"github.com/nmeilick/netclip/common"
	"github.com/nmeilick/netclip/common/cache"
	"github.com/nmeilick/netclip/config"
	"github.com/nmeilick/netclip/ids"
	"github.com/nmeilick/netclip/response"
	"github.com/nmeilick/netclip/streampack"
	"github.com/nmeilick/netclip/streampack/compression"
	"github.com/olekukonko/tablewriter"
	"github.com/rs/zerolog"
	"github.com/schollz/progressbar/v3"
	"github.com/urfave/cli/v2"
	"github.com/xhit/go-str2duration/v2"
)

const (
	cacheFileName         = "cache.db"
	defaultIDLength       = 11
	defaultTokenLength    = 15
	defaultPasswordLength = 12
)

// Environment variable names
var (
	envPrefix            = strings.ToUpper(common.AppName) + "_"
	envPassword          = envPrefix + "PASSWORD"
	envAPIKey            = envPrefix + "API_KEY"
	envConfigPath        = envPrefix + "CONFIG"
	envID                = envPrefix + "ID"
	envUpdateToken       = envPrefix + "UPDATE_TOKEN"
	envExpires           = envPrefix + "EXPIRES"
	envCompression       = envPrefix + "COMPRESSION"
	envCompressionLevel  = envPrefix + "COMPRESSION_LEVEL"
	envComment           = envPrefix + "COMMENT"
	envIDLength          = envPrefix + "ID_LENGTH"
	envPasswordLength    = envPrefix + "PASSWORD_LENGTH"
	envUpdateTokenLength = envPrefix + "UPDATE_TOKEN_LENGTH"
)

type clipEntry struct {
	UpdateToken string `json:"ut,omitempty"`
	Password    string `json:"pw,omitempty"`
}

// Commands returns the CLI commands for the copy functionality
func Commands() *cli.Command {
	return &cli.Command{
		Name:    "copy",
		Aliases: []string{"c"},
		Usage:   "Copy files to the network clipboard",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "config",
				Aliases: []string{"c"},
				EnvVars: []string{envConfigPath},
				Usage:   "Path to config file",
			},
			&cli.BoolFlag{
				Name:    "encrypt",
				Aliases: []string{"e"},
				Usage:   "Encrypt the data with a random password",
			},
			&cli.StringFlag{
				Name:    "password",
				Aliases: []string{"p"},
				EnvVars: []string{envPassword},
				Usage:   "Encrypt the data with the given password",
			},
			&cli.StringFlag{
				Name:    "expires",
				Aliases: []string{"x"},
				EnvVars: []string{envExpires},
				Usage:   "Expiration time of the clip (e.g. 4h, 7d, 2w, never)",
				Value:   "7d",
			},
			&cli.StringFlag{
				Name:    "id",
				Aliases: []string{"i"},
				EnvVars: []string{envID},
				Usage:   "Use the given ID instead of generating one",
			},
			&cli.StringFlag{
				Name:    "update",
				Aliases: []string{"u"},
				EnvVars: []string{envUpdateToken},
				Usage:   "Update an existing clip using the given token",
			},
			&cli.StringFlag{
				Name:    "key",
				Aliases: []string{"k"},
				Usage:   "API key",
				EnvVars: []string{envAPIKey},
			},
			&cli.StringFlag{
				Name:    "compression",
				Aliases: []string{"C"},
				EnvVars: []string{envCompression},
				Usage:   "Compression algorithm (none, gzip, zstd, lz4)",
				Value:   "lz4",
			},
			&cli.StringFlag{
				Name:    "level",
				Aliases: []string{"L"},
				EnvVars: []string{envCompressionLevel},
				Usage:   "Compression level (fast, medium, best)",
				Value:   "fast",
			},
			&cli.BoolFlag{
				Name:    "no-xattrs",
				Aliases: []string{"X"},
				Usage:   "Disable extended attribute preservation",
			},
			&cli.BoolFlag{
				Name:    "no-acls",
				Aliases: []string{"A"},
				Usage:   "Disable ACL preservation",
			},
			&cli.BoolFlag{
				Name:    "no-platform-compat",
				Aliases: []string{"npc"},
				Usage:   "Disable platform compatibility mode",
			},
			&cli.StringFlag{
				Name:    "comment",
				Aliases: []string{"m"},
				EnvVars: []string{envComment},
				Usage:   "Add a comment to the clip",
			},
			&cli.BoolFlag{
				Name:  "no-qr",
				Usage: "Disable displaying the QR code",
			},
			&cli.BoolFlag{
				Name:    "list",
				Aliases: []string{"l"},
				Usage:   "List cached clip info",
			},
			&cli.BoolFlag{
				Name:  "clean",
				Usage: "Remove cached clip info",
			},
			&cli.IntFlag{
				Name:    "id-length",
				Aliases: []string{"ilen"},
				EnvVars: []string{envIDLength},
				Usage:   "Length of generated ID",
				Value:   defaultIDLength,
			},
			&cli.IntFlag{
				Name:    "password-length",
				Aliases: []string{"plen"},
				EnvVars: []string{envPasswordLength},
				Usage:   "Length of generated password",
				Value:   defaultPasswordLength,
			},
			&cli.IntFlag{
				Name:    "token-length",
				Aliases: []string{"tlen"},
				EnvVars: []string{envUpdateTokenLength},
				Usage:   "Length of generated update token",
				Value:   defaultTokenLength,
			},
			&cli.BoolFlag{
				Name:    "verbose",
				Aliases: []string{"v"},
				Usage:   "Enable verbose output",
			},
		},
		Action: func(c *cli.Context) error {
			if c.Bool("list") {
				return listCachedClips(c)
			}
			if c.Bool("clean") {
				return cleanCache(c)
			}
			return runCopy(c)
		},
	}
}

func runCopy(c *cli.Context) error {
	log := common.NewLogger(c)
	if os.Getenv("DEBUG") == "1" {
		log = log.Level(zerolog.DebugLevel)
	}

	cfg, _, err := config.LoadClientConfig(c)
	if err != nil {
		log.Error().Err(err).Msg("Failed to load configuration")
		return err
	}

	isTTY := common.IsTTY(os.Stdin)
	args := c.Args().Slice()

	if isTTY {
		if len(args) == 0 {
			return fmt.Errorf("please specify one or more files, or pipe in data")
		}
	} else if len(args) > 0 {
		return fmt.Errorf("please either pipe in data or specify file arguments, not both")
	}

	for _, path := range args {
		if _, err := os.Lstat(path); err != nil {
			return fmt.Errorf("failed to stat path: %w", err)
		}
	}

	// Handle ID, password and tag
	var id, password, tag string
	specifiedID := c.String("id")
	if specifiedID != "" {
		id, password, tag = common.ParseID(specifiedID)
	}

	if tag != "" {
		return fmt.Errorf("@tag support is not implemented yet")
	}

	if id == "" {
		idLength := defaultIDLength
		if c.IsSet("id-length") {
			idLength = c.Int("id-length")
		} else if cfg.IDLength > 0 {
			idLength = cfg.IDLength
		}
		id = ids.SyllableID(idLength)
	}

	apiKey := cfg.APIKey
	if c.IsSet("key") {
		apiKey = c.String("key")
	}

	// Collect update tokens
	var updateTokens []string
	if cmdToken := c.String("update"); cmdToken != "" {
		updateTokens = append(updateTokens, cmdToken)
	}
	if cfgToken := cfg.UpdateToken; cfgToken != "" {
		updateTokens = append(updateTokens, cfgToken)
	}

	var cachedPassword string
	if t, pw, err := loadClipInfo(id); err == nil {
		if t != "" {
			updateTokens = append(updateTokens, t)
		}
		cachedPassword = pw
	}

	if len(updateTokens) == 0 {
		tokenLength := defaultTokenLength
		if c.IsSet("token-length") {
			tokenLength = c.Int("token-length")
		} else if cfg.UpdateTokenLength > 0 {
			tokenLength = cfg.UpdateTokenLength
		}
		updateTokens = append(updateTokens, ids.SyllableID(tokenLength))
	}

	updateToken := strings.Join(common.Tokens(updateTokens...), ",")

	// Handle password/encryption
	var keySource []string
	if password != "" {
		keySource = append(keySource, ":password in id")
	}

	if pwd := c.String("password"); pwd != "" {
		password = pwd
		keySource = append(keySource, "password parameter")
	} else if c.Bool("encrypt") && password == "" {
		if password = cachedPassword; password == "" {
			if password = cfg.Password; password == "" {
				pwdlen := defaultPasswordLength
				if n := c.Int("password-length"); n > 0 {
					pwdlen = n
				} else if cfg.PasswordLength > 0 {
					pwdlen = cfg.PasswordLength
				}
				password = common.GeneratePassword(pwdlen)
			}
		}
	}

	if len(keySource) > 1 {
		return fmt.Errorf("multiple encryption passwords specified (as %s)", strings.Join(keySource, " and "))
	}

	if password != "" {
		log.Info().Msg("Encryption enabled")
	}

	// Parse compression options
	compressionType, err := parseCompressionType(c.String("compression"))
	if err != nil {
		return err
	}
	compressionLevel, err := parseCompressionLevel(c.String("level"))
	if err != nil {
		return err
	}

	// Handle expiration
	var expiresSeconds int64
	switch expires := c.String("expires"); strings.ToLower(expires) {
	case "", "0", "never":
		// No expiration - server will use default
	case "today", "tod":
		expiresSeconds = int64(common.EndOfDay(time.Now()).Sub(time.Now()).Seconds())
	case "tomorrow", "tom":
		expiresSeconds = int64(common.EndOfDay(time.Now()).Add(24 * time.Hour).Sub(time.Now()).Seconds())
	default:
		d, err := str2duration.ParseDuration(expires)
		if err != nil {
			return fmt.Errorf("invalid expiration: %v", err)
		} else if d < 0 {
			return fmt.Errorf("expiration may not be negative")
		}
		expiresSeconds = int64(d.Seconds())
	}

	log.Info().Str("server", cfg.ServerURL).Msg("Uploading data to server")

	// Create pipe for streaming data
	pr, pw := io.Pipe()
	errCh := make(chan error, 1)

	go func() {
		defer pw.Close()

		options := []streampack.PackerOption{
			streampack.WithOutput(pw),
			streampack.WithCompression(compressionType, compressionLevel),
		}

		if !isTTY {
			options = append(options, streampack.WithRawDataInput(os.Stdin))
		} else {
			options = append(options, streampack.WithSource(args...))
		}

		if password != "" {
			options = append(options, streampack.WithEncryption(password))
		}

		packer, err := streampack.NewPacker(options...)
		if err != nil {
			log.Error().Err(err).Msg("Failed to create packer")
			errCh <- fmt.Errorf("failed to create packer: %w", err)
			return
		}

		errCh <- packer.Pack()
	}()

	// Upload the data
	baseURL := strings.TrimSuffix(cfg.ServerURL, "/")
	url := baseURL + "/api/v1/clips/" + id

	startTime := time.Now()
	countReader := &common.CountReader{Reader: pr}
	var reader io.Reader = countReader
	var bar *progressbar.ProgressBar

	if common.IsTTY(os.Stdout) {
		bar = progressbar.NewOptions64(
			-1,
			progressbar.OptionSetWriter(os.Stdout),
			progressbar.OptionSetDescription("Uploading"),
			progressbar.OptionShowBytes(true),
			progressbar.OptionSetWidth(40),
			progressbar.OptionClearOnFinish(),
			progressbar.OptionSetTheme(progressbar.ThemeASCII),
		)
		reader = io.TeeReader(countReader, bar)
	}

	req, err := http.NewRequest("POST", url, reader)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Transfer-Encoding", "chunked")
	common.SetUserAgent(req)

	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	if updateToken != "" {
		req.Header.Set("X-Update-Token", updateToken)
	}
	if comment := c.String("comment"); comment != "" {
		req.Header.Set("X-Comment", comment)
	}

	if expiresSeconds >= 0 {
		req.Header.Set("X-Expires", strconv.FormatInt(expiresSeconds, 10))
	}

	// Apply command-line TLS options if provided
	clientCfg := *cfg
	if c.IsSet("tls-cert") {
		clientCfg.TLSCert = c.String("tls-cert")
	}
	if c.IsSet("tls-key") {
		clientCfg.TLSKey = c.String("tls-key")
	}
	if c.IsSet("tls-ca") {
		clientCfg.TLSCA = c.String("tls-ca")
	}
	if c.IsSet("proxy") {
		clientCfg.ProxyURL = c.String("proxy")
	}

	client := common.CreateHTTPClient(&clientCfg)
	log.Debug().Str("url", url).Msg("Sending HTTP request")

	resp, err := client.Do(req)
	if bar != nil {
		bar.Finish()
	}
	if err != nil {
		log.Error().Err(err).Str("url", url).Msg("Failed to upload data")
		return fmt.Errorf("failed to upload data: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		log.Debug().Int("status", resp.StatusCode).Msg("Upload successful")
	default:
		var errorResp response.Error
		body, _ := io.ReadAll(resp.Body)

		if err := json.Unmarshal(body, &errorResp); err == nil && errorResp.Error.Message != "" {
			log.Error().
				Int("status", resp.StatusCode).
				Str("error", errorResp.Error.Message).
				Msg("Server returned error")
			return fmt.Errorf("server error: %s", errorResp.Error.Message)
		} else {
			log.Error().
				Int("status", resp.StatusCode).
				Str("response", string(body)).
				Msg("Server returned error")
			return fmt.Errorf("server returned error: %s - %s", resp.Status, string(body))
		}
	}

	if s := resp.Header.Get("X-Update-Token"); s != "" {
		updateToken = s
	}

	outputUpdateToken := false
	if err = saveClipInfo(id, updateToken, password); err != nil {
		log.Warn().Err(err).Msg("Failed to save clip info")
		outputUpdateToken = true
	}

	// Check for packing errors
	if err := <-errCh; err != nil {
		log.Error().Err(err).Msg("Failed to pack data")
		return err
	}

	// Output stats
	uploadTime := time.Since(startTime)
	uploadSize := countReader.Count
	sizeStr := humanize.IBytes(uploadSize)

	fmt.Fprintf(os.Stderr, "Uploaded %s in %v (%s/s)\n",
		sizeStr,
		uploadTime.Round(time.Millisecond),
		humanize.IBytes(uint64(float64(uploadSize)/uploadTime.Seconds())),
	)

	result := common.CombineIDAndKey(id, password)

	var showQRCode bool
	if c.IsSet("no-qr") {
		showQRCode = !c.Bool("no-qr")
	} else {
		showQRCode = !cfg.DisableQRCode
	}

	if showQRCode {
		qrConfig := qrterminal.Config{
			HalfBlocks: true,
			Level:      qrterminal.M,
			Writer:     os.Stdout,
		}
		qrurl := "clip+" + url
		if password != "" {
			qrurl += "?key=" + uri.QueryEscape(password)
		}
		qrterminal.GenerateWithConfig(qrurl, qrConfig)
		fmt.Println()
	}

	out := fmt.Sprintf("ID: %s", result)
	if outputUpdateToken {
		out += " (updateToken: " + updateToken + ")"
	}
	fmt.Println(out + "\n")

	log.Info().
		Str("id", id).
		Bool("encrypted", password != "").
		Msg("Upload complete")

	if password != "" {
		log.Info().Msg("Data is encrypted. Keep the full ID (including the part after #) to decrypt.")
	}

	return nil
}

func cleanCache(c *cli.Context) error {
	log := common.NewLogger(c)

	file, err := xdg.CacheFile(filepath.Join(common.AppName, cacheFileName))
	if err != nil {
		log.Error().Err(err).Msg("Failed to determine cache file path")
		return fmt.Errorf("failed to determine cache file path: %w", err)
	}

	if _, err := os.Stat(file); os.IsNotExist(err) {
		fmt.Println("Cache is already empty.")
		return nil
	}

	if err := os.Remove(file); err != nil {
		log.Error().Err(err).Str("path", file).Msg("Failed to remove cache file")
		return fmt.Errorf("failed to remove cache file: %w", err)
	}

	fmt.Println("Cache has been cleared successfully.")
	return nil
}

func parseCompressionType(name string) (compression.CompressionType, error) {
	name = strings.ToLower(name)
	switch name {
	case "none":
		return compression.NoCompression, nil
	case "gzip", "gz":
		return compression.GzipCompression, nil
	case "zstd", "z":
		return compression.ZstdCompression, nil
	case "lz4", "lz":
		return compression.Lz4Compression, nil
	default:
		return compression.NoCompression, fmt.Errorf("invalid compression type: %s (valid options: none, gzip, zstd, lz4)", name)
	}
}

func parseCompressionLevel(level string) (compression.Level, error) {
	level = strings.ToLower(level)
	switch level {
	case "fast", "f":
		return compression.Fast, nil
	case "medium", "m", "med":
		return compression.Medium, nil
	case "best", "b":
		return compression.Best, nil
	default:
		return compression.Medium, fmt.Errorf("invalid compression level: %s (valid options: fast, medium, best)", level)
	}
}

func saveClipInfo(id, updateToken, password string) error {
	if id == "" {
		return nil
	}

	cache, err := cache.PrivateCache()
	if err != nil {
		return err
	}
	defer cache.Close()
	return cache.Set("clips", id, &clipEntry{UpdateToken: updateToken, Password: password})
}

func loadClipInfo(id string) (string, string, error) {
	cache, err := cache.PrivateCache()
	if err != nil {
		return "", "", err
	}
	defer cache.Close()

	var entry clipEntry
	if err = cache.Get("clips", id, &entry); err != nil {
		return "", "", err
	}
	return entry.UpdateToken, entry.Password, nil
}

func listCachedClips(c *cli.Context) error {
	log := common.NewLogger(c)

	cache, err := cache.PrivateCache()
	if err != nil {
		log.Error().Err(err).Msg("Failed to open cache")
		return fmt.Errorf("failed to open cache: %w", err)
	}
	defer cache.Close()

	entries, err := cache.ListEntriesWithTime("clips")
	if err != nil {
		log.Error().Err(err).Msg("Failed to query cache")
		return fmt.Errorf("failed to query cache: %w", err)
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"ID", "Update Token", "Password", "Timestamp"})
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAutoWrapText(false)
	table.SetAutoFormatHeaders(true)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetCenterSeparator("+")
	table.SetColumnSeparator("|")
	table.SetRowSeparator("-")
	table.SetHeaderLine(true)
	table.SetBorder(true)
	table.SetNoWhiteSpace(false)
	table.SetColumnAlignment([]int{
		tablewriter.ALIGN_LEFT,
		tablewriter.ALIGN_LEFT,
		tablewriter.ALIGN_LEFT,
		tablewriter.ALIGN_LEFT,
	})

	count := 0
	for _, item := range entries {
		var entry clipEntry
		if err := json.Unmarshal([]byte(item.Value), &entry); err != nil {
			log.Warn().Err(err).Str("id", item.Key).Msg("Failed to parse cache entry")
			continue
		}

		table.Append([]string{
			item.Key,
			entry.UpdateToken,
			entry.Password,
			item.LastAccessed.Local().Format("2006-01-02 15:04:05"),
		})
		count++
	}

	if count == 0 {
		fmt.Println("No cached clips found.")
	} else {
		table.Render()
	}

	return nil
}
