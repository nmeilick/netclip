package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/nmeilick/netclip/streampack"
	"github.com/nmeilick/netclip/streampack/compression"
	"github.com/nmeilick/netclip/streampack/encryption"
	"github.com/urfave/cli/v2"
)

const (
	appName    = "streampack"
	appVersion = "0.1.0"
)

func main() {
	app := &cli.App{
		Name:    appName,
		Version: appVersion,
		Usage:   "A tool for creating and extracting compressed and encrypted archives",
		Commands: []*cli.Command{
			{
				Name:    "pack",
				Aliases: []string{"p"},
				Usage:   "Create a new archive",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "output",
						Aliases: []string{"o"},
						Usage:   "Output file path",
						Value:   "archive.spak",
					},
					&cli.StringFlag{
						Name:    "compression",
						Aliases: []string{"c"},
						Usage:   "Compression algorithm (none, gzip, zstd, lz4)",
						Value:   "lz4",
					},
					&cli.StringFlag{
						Name:    "level",
						Aliases: []string{"l"},
						Usage:   "Compression level (fast, medium, best)",
						Value:   "medium",
					},
					&cli.StringFlag{
						Name:    "encrypt",
						Aliases: []string{"e"},
						Usage:   "Enable encryption with password",
					},
					&cli.StringFlag{
						Name:  "encrypt-type",
						Usage: "Encryption type (age)",
						Value: "age",
					},
					&cli.StringFlag{
						Name:  "metadata",
						Usage: "Add metadata as JSON string",
					},
					&cli.BoolFlag{
						Name:  "verbose",
						Usage: "Enable verbose output",
					},
					&cli.BoolFlag{
						Name:  "no-xattrs",
						Usage: "Disable extended attribute restoration",
					},
					&cli.BoolFlag{
						Name:  "no-acls",
						Usage: "Disable ACL restoration",
					},
					&cli.BoolFlag{
						Name:    "force",
						Aliases: []string{"f"},
						Usage:   "Force overwrite of existing files",
					},
					&cli.BoolFlag{
						Name:  "no-platform-compat",
						Usage: "Disable platform compatibility mode",
					},
				},
				Action: packAction,
			},
			{
				Name:    "unpack",
				Aliases: []string{"u"},
				Usage:   "Extract an archive",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "input",
						Aliases: []string{"i"},
						Usage:   "Input file path",
					},
					&cli.StringFlag{
						Name:    "output",
						Aliases: []string{"o"},
						Usage:   "Output directory",
						Value:   ".",
					},
					&cli.StringFlag{
						Name:    "decrypt",
						Aliases: []string{"d"},
						Usage:   "Decrypt with password",
					},
					&cli.BoolFlag{
						Name:  "verbose",
						Usage: "Enable verbose output",
					},
				},
				Action: unpackAction,
			},
			{
				Name:  "info",
				Usage: "Display information about an archive",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "input",
						Aliases:  []string{"i"},
						Usage:    "Input file path",
						Required: true,
					},
				},
				Action: infoAction,
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func packAction(c *cli.Context) error {
	verbose := c.Bool("verbose")
	outputPath := c.String("output")
	compressionType := parseCompressionType(c.String("compression"))
	compressionLevel := parseCompressionLevel(c.String("level"))
	encryptionPassword := c.String("encrypt")
	encryptionType := parseEncryptionType(c.String("encrypt-type"))
	metadataStr := c.String("metadata")

	// Check if data is being piped in
	stat, _ := os.Stdin.Stat()
	isPiped := (stat.Mode() & os.ModeCharDevice) == 0

	// If data is piped in, automatically use raw mode
	isRaw := isPiped
	if isPiped && verbose {
		fmt.Println("Detected piped input, using raw mode")
	}

	if verbose {
		fmt.Printf("Creating archive: %s\n", outputPath)
		fmt.Printf("Compression: %s (level: %s)\n", compressionType, c.String("level"))
		if encryptionPassword != "" {
			fmt.Printf("Encryption: %s\n", encryptionType)
		}
	}

	// Prepare packer options
	var options []streampack.PackerOption
	options = append(options, streampack.WithOutputFile(outputPath))
	options = append(options, streampack.WithCompression(compressionType, compressionLevel))

	// Add encryption if password is provided
	if encryptionPassword != "" {
		options = append(options, streampack.WithEncryptionType(encryptionPassword, encryptionType))
	}

	// Add metadata if provided
	if metadataStr != "" {
		metadata, err := parseMetadata(metadataStr)
		if err != nil {
			return fmt.Errorf("invalid metadata: %w", err)
		}
		options = append(options, streampack.WithMetadata(metadata))
	}

	// Handle xattr and ACL options
	if c.Bool("no-xattrs") {
		options = append(options, streampack.WithPreserveXattrs(false))
		if verbose {
			fmt.Println("Extended attribute preservation disabled")
		}
	}

	if c.Bool("no-acls") {
		options = append(options, streampack.WithPreserveACLs(false))
		if verbose {
			fmt.Println("ACL preservation disabled")
		}
	}

	// Get sources from arguments
	sources := c.Args().Slice()

	// Handle raw data mode
	if isRaw {
		// Error if both piped data and source arguments are provided
		if len(sources) > 0 {
			return fmt.Errorf("cannot specify source files when using raw mode or piped input")
		}

		if verbose {
			fmt.Println("Reading raw data from stdin...")
		}
		options = append(options, streampack.WithRawDataInput(os.Stdin))
	} else {
		// Error if no sources are provided in non-raw mode
		if len(sources) == 0 {
			return fmt.Errorf("no source files or directories specified")
		}

		if verbose {
			fmt.Println("Adding sources:")
			for _, src := range sources {
				fmt.Printf("  - %s\n", src)
			}
		}

		options = append(options, streampack.WithSource(sources...))
	}

	// Create and run packer
	packer, err := streampack.NewPacker(options...)
	if err != nil {
		return err
	}

	if err := packer.Pack(); err != nil {
		return err
	}

	if verbose {
		fmt.Println("Archive created successfully")
	}

	return nil
}

func unpackAction(c *cli.Context) error {
	verbose := c.Bool("verbose")
	inputPath := c.String("input")
	outputDir := c.String("output")
	decryptionPassword := c.String("decrypt")

	// Check if data is being piped in
	stat, _ := os.Stdin.Stat()
	isPiped := (stat.Mode() & os.ModeCharDevice) == 0

	// Check if output is being piped (stdout isn't a terminal)
	stdoutStat, _ := os.Stdout.Stat()
	isOutputPiped := (stdoutStat.Mode() & os.ModeCharDevice) == 0

	// Use raw mode if output is being piped
	isRaw := isOutputPiped

	// If data is piped in and input file is specified, throw an error
	if isPiped && (inputPath != "" || len(c.Args().Slice()) > 0) {
		return fmt.Errorf("cannot specify input file when reading from stdin")
	}

	// Check if input is from stdin or file
	if isPiped || (inputPath == "" && len(c.Args().Slice()) == 0) {
		// No input file specified, use stdin
		if verbose {
			fmt.Println("Reading from stdin...")
		}
		return unpackFromReader(os.Stdin, outputDir, decryptionPassword, isRaw, verbose)
	}

	// If no input flag but argument provided, use first argument as input file
	if inputPath == "" && len(c.Args().Slice()) > 0 {
		inputPath = c.Args().First()
	}

	if verbose {
		fmt.Printf("Extracting archive: %s\n", inputPath)
		fmt.Printf("Output directory: %s\n", outputDir)
		if decryptionPassword != "" {
			fmt.Println("Decryption enabled")
		}
		if isRaw {
			fmt.Println("Raw data mode enabled")
		}
	}

	// Prepare unpacker options
	var options []streampack.UnpackerOption
	options = append(options, streampack.WithInputFile(inputPath))
	options = append(options, streampack.WithDestination(outputDir))

	// Add decryption if password is provided
	if decryptionPassword != "" {
		options = append(options, streampack.WithDecryption(decryptionPassword))
	}

	// Handle xattr and ACL options
	if c.Bool("no-xattrs") {
		options = append(options, streampack.WithRestoreXattrs(false))
		if verbose {
			fmt.Println("Extended attribute restoration disabled")
		}
	}

	if c.Bool("no-acls") {
		options = append(options, streampack.WithRestoreACLs(false))
		if verbose {
			fmt.Println("ACL restoration disabled")
		}
	}

	// Handle force overwrite option
	if c.Bool("force") {
		options = append(options, streampack.WithForceOverwrite())
		if verbose {
			fmt.Println("Force overwrite enabled")
		}
	}

	// Handle platform compatibility mode
	if c.Bool("no-platform-compat") {
		options = append(options, streampack.WithPlatformCompatMode(false))
		if verbose {
			fmt.Println("Platform compatibility mode disabled")
		}
	}

	// Enable raw data mode if requested or if output is being piped
	if isRaw {
		options = append(options, streampack.WithRawDataOutput())
	}

	// Create and run unpacker
	unpacker := streampack.NewUnpacker(options...)
	if err := unpacker.Unpack(); err != nil {
		return err
	}

	// Handle raw data output
	if isRaw {
		rawData, err := unpacker.GetRawData()
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(rawData)
		return err
	}

	if verbose {
		fmt.Println("Archive extracted successfully")
	}

	return nil
}

func unpackFromReader(reader io.Reader, outputDir string, password string, isRaw bool, verbose bool) error {
	// Prepare unpacker options
	var options []streampack.UnpackerOption
	options = append(options, streampack.WithInput(reader))
	options = append(options, streampack.WithDestination(outputDir))

	// Add decryption if password is provided
	if password != "" {
		options = append(options, streampack.WithDecryption(password))
	}

	// Enable raw data mode if output is being piped
	if isRaw {
		options = append(options, streampack.WithRawDataOutput())
	}

	// Create and run unpacker
	unpacker := streampack.NewUnpacker(options...)
	if err := unpacker.Unpack(); err != nil {
		return err
	}

	// Handle raw data output
	if isRaw {
		rawData, err := unpacker.GetRawData()
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(rawData)
		return err
	}

	if verbose {
		fmt.Println("Archive extracted successfully")
	}

	return nil
}

func infoAction(c *cli.Context) error {
	inputPath := c.String("input")

	file, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	header, _, err := streampack.ReadHeader(file)
	if err != nil {
		return fmt.Errorf("failed to read header: %w", err)
	}

	fmt.Println("Archive Information:")
	fmt.Printf("  Type: %s\n", header.Type)
	fmt.Printf("  Compression: %s\n", header.CompressionType)
	if header.EncryptionType != "" {
		fmt.Printf("  Encryption: %s\n", header.EncryptionType)
	} else {
		fmt.Println("  Encryption: none")
	}

	if header.Metadata != nil && len(header.Metadata) > 0 {
		fmt.Println("  Metadata:")
		for k, v := range header.Metadata {
			fmt.Printf("    %s: %v\n", k, v)
		}
	}

	// Display platform information
	if header.Platform != "" {
		fmt.Printf("  Created on: %s\n", header.Platform)
	}

	// Display feature flags
	fmt.Println("  Features:")
	fmt.Printf("    Extended Attributes: %v\n", header.Features.Xattrs)
	fmt.Printf("    ACLs: %v\n", header.Features.ACLs)

	return nil
}

// Helper functions

func parseCompressionType(name string) compression.CompressionType {
	name = strings.ToLower(name)
	switch name {
	case "none":
		return compression.NoCompression
	case "gzip":
		return compression.GzipCompression
	case "zstd":
		return compression.ZstdCompression
	case "lz4":
		return compression.Lz4Compression
	default:
		// Default to LZ4
		return compression.Lz4Compression
	}
}

func parseCompressionLevel(level string) compression.Level {
	level = strings.ToLower(level)
	switch level {
	case "fast":
		return compression.Fast
	case "best":
		return compression.Best
	default:
		// Default to medium
		return compression.Medium
	}
}

func parseEncryptionType(name string) encryption.EncryptionType {
	name = strings.ToLower(name)
	switch name {
	case "age":
		return encryption.AGEEncryption
	default:
		// Default to AGE
		return encryption.AGEEncryption
	}
}

// formatSize returns a human-readable string for a byte size
func formatSize(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(size)/float64(div), "KMGTPE"[exp])
}

func parseMetadata(jsonStr string) (map[string]interface{}, error) {
	metadata := make(map[string]interface{})

	// Split by commas and parse key=value pairs
	pairs := strings.Split(jsonStr, ",")
	for _, pair := range pairs {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("invalid metadata format, expected key=value: %s", pair)
		}

		key := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])

		// Try to parse as number if possible
		if value == "true" {
			metadata[key] = true
		} else if value == "false" {
			metadata[key] = false
		} else if strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"") {
			// It's a quoted string, remove quotes
			metadata[key] = value[1 : len(value)-1]
		} else {
			// Just use as string
			metadata[key] = value
		}
	}

	return metadata, nil
}
