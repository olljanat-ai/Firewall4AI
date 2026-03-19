// Package web embeds the static admin UI files.
package web

import "embed"

//go:embed all:static
var StaticFiles embed.FS
