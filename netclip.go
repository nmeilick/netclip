package netclip

import (
	_ "embed"
)

//go:embed examples/netclip.hcl
var SampleConfig []byte

//go:embed examples/embedded_config.hcl
var EmbeddedConfig []byte
