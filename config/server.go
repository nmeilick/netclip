package config

import (
	"fmt"

	serverconfig "github.com/nmeilick/netclip/server/config"
	"github.com/urfave/cli/v2"
)

func LoadServerConfig(c *cli.Context) (*serverconfig.Config, string, error) {
	cfg, path, err := LoadConfig(c)
	if err != nil {
		return nil, path, err
	}

	if cfg.Server == nil {
		return nil, path, fmt.Errorf("config is missing Server section: %s", path)
	}

	if err := cfg.Server.Normalize(); err != nil {
		return nil, path, fmt.Errorf("config has problems: %s: %w", path, err)
	}

	return cfg.Server, path, nil
}
