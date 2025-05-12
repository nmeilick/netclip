package netclip

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/nmeilick/netclip"
	"github.com/urfave/cli/v2"
)

// Commands returns the CLI commands for the main program
func Commands() *cli.Command {
	return &cli.Command{
		Name:  "setup",
		Usage: "Perform setup tasks",
		Subcommands: []*cli.Command{
			{
				Name:   "links",
				Usage:  "Setup symbolic links for ncopy, npaste, etc.",
				Action: runSetupLinks,
			},
			{
				Name:   "sample-config",
				Usage:  "Print a sample configuration file to stdout",
				Action: runSampleConfig,
			},
			{
				Name:   "embedded-config",
				Usage:  "Print the embedded configuration to stdout",
				Action: runEmbeddedConfig,
			},
		},
	}
}

func runSetupLinks(c *cli.Context) error {
	// Get the path to the current executable
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	// Get the directory containing the executable
	execDir := filepath.Dir(execPath)

	// Get the base name of the executable
	execName := filepath.Base(execPath)

	// Define the symlinks to create
	symlinks := []string{"ncopy", "npaste", "nserver"}

	// Create each symlink
	for _, link := range symlinks {
		linkPath := filepath.Join(execDir, link)

		// Check if the file already exists
		fileInfo, err := os.Lstat(linkPath)
		if err == nil {
			// File exists, check if it's a symlink
			if fileInfo.Mode()&os.ModeSymlink == 0 {
				// Not a symlink, skip it
				fmt.Printf("Skipping %s: file exists and is not a symlink\n", link)
				continue
			}

			// It's a symlink, remove it
			if err := os.Remove(linkPath); err != nil {
				return fmt.Errorf("failed to remove existing symlink %s: %w", link, err)
			}
		} else if !os.IsNotExist(err) {
			// Error other than "file not exists"
			return fmt.Errorf("failed to check if %s exists: %w", link, err)
		}

		// Create the symlink
		if err := os.Symlink(execName, linkPath); err != nil {
			return fmt.Errorf("failed to create symlink %s: %w", link, err)
		}

		fmt.Printf("Created symlink: %s -> %s\n", link, execName)
	}

	return nil
}

func runSampleConfig(c *cli.Context) error {
	if len(netclip.SampleConfig) == 0 {
		fmt.Fprintln(os.Stderr, "Error: No embedded sample configuration found.")
		return fmt.Errorf("no embedded sample configuration available")
	}
	fmt.Println(string(netclip.SampleConfig))

	return nil
}

func runEmbeddedConfig(c *cli.Context) error {
	if len(netclip.EmbeddedConfig) == 0 {
		fmt.Fprintln(os.Stderr, "Error: No embedded default configuration found.")
		return fmt.Errorf("no embedded configuration available")
	}

	fmt.Println(string(netclip.EmbeddedConfig))
	return nil
}
