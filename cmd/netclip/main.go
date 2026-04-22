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

type invocationMode int

const (
	normalInvocation invocationMode = iota
	copyInvocation
	pasteInvocation
	serverInvocation
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
	switch invocationModeFromExecutable(execName) {
	case copyInvocation:
		app.Name = execName
		app.Commands = nil
		app.Flags = copy.Commands().Flags
		app.Action = copy.Commands().Action
	case pasteInvocation:
		app.Name = execName
		app.Commands = nil
		app.Flags = paste.Commands().Flags
		app.Action = paste.Commands().Action
	case serverInvocation:
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

func invocationModeFromExecutable(execName string) invocationMode {
	normalizedExecName := common.NormalizeExecutableName(execName)

	switch {
	case strings.HasSuffix(normalizedExecName, "copy"):
		return copyInvocation
	case strings.HasSuffix(normalizedExecName, "paste"):
		return pasteInvocation
	case strings.HasSuffix(normalizedExecName, "serve"),
		strings.HasSuffix(normalizedExecName, "server"),
		strings.HasSuffix(normalizedExecName, "clipd"):
		return serverInvocation
	default:
		return normalInvocation
	}
}
