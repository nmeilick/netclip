package config

import (
	_ "embed" // Import the embed package
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/adrg/xdg"
	"github.com/hashicorp/hcl/v2/hclsimple"
	"github.com/nmeilick/netclip"
	clientconfig "github.com/nmeilick/netclip/client/config"
	serverconfig "github.com/nmeilick/netclip/server/config"
	"github.com/urfave/cli/v2"
)

func init() {
	DefaultConfigFile = FindConfigFile()
}

// Config holds the application configuration
type Config struct {
	Server *serverconfig.Config `hcl:"server,block"`
	Client *clientconfig.Config `hcl:"client,block"`
}

var DefaultConfigFile string

// getConfigLocations returns all standard locations where config files are searched
func getConfigLocations() []string {
	var locations []string

	// Get executable path to check for config in same directory
	execPath, err := os.Executable()
	if err == nil {
		execDir := filepath.Dir(execPath)
		locations = append(locations, filepath.Join(execDir, AppName+".hcl"))
	}

	// User config locations (cross-platform)
	// XDG paths for Linux, appropriate equivalents for Windows and macOS
	userConfigFile, err := xdg.ConfigFile(AppName + ".hcl")
	if err == nil {
		locations = append(locations, userConfigFile)
	}

	// Also check for config in XDG subdirectory
	userConfigDir, err := xdg.ConfigFile(AppName)
	if err == nil {
		locations = append(locations, filepath.Join(userConfigDir, "config.hcl"))
	}

	// Get user's home directory for additional locations
	homeDir, err := os.UserHomeDir()
	if err == nil {
		// Additional user config locations
		locations = append(locations,
			filepath.Join(homeDir, "."+AppName, "config.hcl"),
			filepath.Join(homeDir, "."+AppName+".hcl"),
		)
	}

	// System-wide locations (OS-specific)
	switch runtime.GOOS {
	case "windows":
		// Windows system locations
		programData := os.Getenv("ProgramData")
		if programData != "" {
			locations = append(locations,
				filepath.Join(programData, AppName, "config.hcl"),
			)
		}
	case "darwin":
		// macOS system locations
		locations = append(locations,
			"/Library/Application Support/"+AppName+"/config.hcl",
			"/etc/"+AppName+"/config.hcl",
			"/etc/"+AppName+".hcl",
		)
	default:
		// Linux/Unix system locations
		locations = append(locations,
			"/etc/"+AppName+"/config.hcl",
			"/etc/"+AppName+".hcl",
		)
	}

	return locations
}

// FindConfigFile looks for the configuration file in standard locations
func FindConfigFile() string {
	// Check for existence of each location
	for _, loc := range getConfigLocations() {
		if stat, err := os.Stat(loc); err == nil && stat.Mode().IsRegular() {
			return loc
		}
	}

	return ""
}

// LoadConfig loads the configuration from the specified file, a standard location or an embedded default
func LoadConfig(c *cli.Context) (*Config, string, error) {
	cfg := &Config{}

	path := c.String("config")
	if path == "" {
		locs := getConfigLocations()
		for _, loc := range locs {
			if stat, err := os.Stat(loc); err == nil && stat.Mode().IsRegular() {
				path = loc
				break
			}
		}

		if path == "" {
			if len(netclip.EmbeddedConfig) > 5 {
				if err := hclsimple.Decode("embedded_config.hcl", netclip.EmbeddedConfig, nil, cfg); err != nil {
					return nil, "<embedded>", fmt.Errorf("parsing failed: %w", err)
				}
				return cfg, "<embedded>", nil
			}

			lines := []string{"configuration not found. The following locations where checked"}
			for _, loc := range locs {
				lines = append(lines, "  - "+loc)
			}
			lines = append(lines, "  - <embedded config>")
			return nil, "", errors.New(strings.Join(lines, "\n"))
		}
	}

	if path != "" {
		if err := hclsimple.DecodeFile(path, nil, cfg); err != nil {
			return nil, path, fmt.Errorf("parsing failed: %w", err)
		}
	}

	return cfg, path, nil
}

const (
	// AppName is the main application name
	AppName = "netclip"

	// Binary names
	CopyBinary    = "ncopy"
	PasteBinary   = "npaste"
	ServerBinary  = "nserve"
	ControlBinary = "nctl"
)
