// Copyright 2026 Lénaïc Huard
//
// Licensed under the MIT License, see LICENSE for details

// Package app provides application metadata for the Freebox API.
// These values are used for app registration via the login/authorize/ endpoint.
package app

import "os"

// Immutable application constants used for Freebox API registration.
const (
	// AppID is the unique application identifier (reverse DNS format).
	// Must remain stable for the Freebox to recognize the application.
	AppID = "fr.lhuard.freebox_ptr_dns"

	// AppName is the human-readable name displayed on the Freebox LCD panel.
	AppName = "Freebox PTR DNS"
)

// version is injected at build time via -ldflags.
// Default: "dev" (for development without git tags).
// Expected format: git tag version (e.g., "v1.0.0") or snapshot (e.g., "1.0.1-next").
var version = "dev"

// Version returns the application version.
// The version is injected at build time via -ldflags by the Makefile and GoReleaser.
func Version() string {
	return version
}

// DeviceName returns the hostname of the device running the binary.
// Uses os.Hostname() which works on Linux, macOS, and Windows.
func DeviceName() (string, error) {
	return os.Hostname()
}
