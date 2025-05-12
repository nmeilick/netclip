package config

import (
	"fmt"

	clientconfig "github.com/nmeilick/netclip/client/config"
	"github.com/urfave/cli/v2"
)

func LoadClientConfig(c *cli.Context) (*clientconfig.Config, string, error) {
	cfg, path, err := LoadConfig(c)
	if err != nil {
		return nil, path, err
	}

	if cfg.Client == nil {
		return nil, path, fmt.Errorf("config is missing Client section: %s", path)
	}

	if err := cfg.Client.Normalize(); err != nil {
		return nil, path, fmt.Errorf("config has problems: %s: %w", path, err)
	}

	return cfg.Client, path, nil
}
