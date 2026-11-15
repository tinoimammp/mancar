// Package version holds build metadata injected with -ldflags.
package version

// Version is overridden at build time:
//
//	go build -ldflags "-X github.com/USERNAME/mancar/internal/version.Version=v0.1.0"
var Version = "dev"
