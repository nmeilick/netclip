package main

import (
	"os"
	"path/filepath"
	"strings"
	_ "time/tzdata" // Embed timezone data

	"github.com/nmeilick/netclip/common"
	"github.com/nmeilick/netclip/copy"
	"github.com/nmeilick/netclip/netclip"
	"github.com/nmeilick/netclip/paste"
	"github.com/nmeilick/netclip/server"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  common.AppName,
		Usage: "Network clipboard for files",
		Commands: []*cli.Command{
			copy.Commands(),
			paste.Commands(),
			server.Commands(),
			netclip.Commands(),
		},
	}

	// Check if we're being called via a symlink (ncopy, npaste, etc.)
	execName := filepath.Base(os.Args[0])
	if strings.HasSuffix(execName, "copy") {
		app.Name = execName
		app.Commands = nil
		app.Flags = copy.Commands().Flags
		app.Action = copy.Commands().Action
	} else if strings.HasSuffix(execName, "paste") {
		app.Name = execName
		app.Commands = nil
		app.Flags = paste.Commands().Flags
		app.Action = paste.Commands().Action
	} else if strings.HasSuffix(execName, "serve") || strings.HasSuffix(execName, "server") || strings.HasSuffix(execName, "clipd") {
		app.Name = execName
		app.Commands = server.Commands().Subcommands
		app.Flags = server.Commands().Flags
		app.Action = server.Commands().Action
	}

	// Normal execution as netclip
	if err := app.Run(os.Args); err != nil {
		common.ExitWithError(err)
	}
}
