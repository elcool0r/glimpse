// Package version contains build version metadata.
package version

import (
	_ "embed"
	"strings"
)

//go:embed VERSION
var versionFile string

// Version is the single source of truth for the app's version: bump the
// VERSION file to release a new one. It stays a plain, non-constant
// expression (not something -ldflags -X could quietly appear to override
// without actually working) so there is exactly one place this value comes
// from.
var Version = strings.TrimSpace(versionFile)
