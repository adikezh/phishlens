// Package buildinfo carries version metadata injected at build time via -ldflags.
package buildinfo

// Version is set by goreleaser / Taskfile: -X .../buildinfo.Version=v1.2.3
var Version = "dev"

// Edition is the product edition detected at start-up (community | business).
var Edition = "community"
