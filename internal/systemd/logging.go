// Copyright 2026 Lénaïc Huard
//
// Licensed under the MIT License, see LICENSE for details

// Package systemd provides systemd-specific utilities for freebox-ptr-dns.
package systemd

import (
	"os"
	"log/slog"
	"strings"

	slogjournal "github.com/systemd/slog-journal"
)

// NewJournalHandler creates a slog.Handler for journald.
// The handler automatically transforms keys to respect journald format
// (UPPERCASE and underscores only).
func NewJournalHandler(level slog.Level) (slog.Handler, error) {
	return slogjournal.NewHandler(&slogjournal.Options{
		Level: level,
		ReplaceGroup: func(k string) string {
			return strings.ReplaceAll(strings.ToUpper(k), "-", "_")
		},
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			a.Key = strings.ReplaceAll(strings.ToUpper(a.Key), "-", "_")
			return a
		},
	})
}

// IsJournalAvailable checks if journald is available.
func IsJournalAvailable() bool {
	// If we're not running under systemd, no need to try
	if os.Getenv("NOTIFY_SOCKET") == "" {
		return false
	}
	_, err := slogjournal.NewHandler(nil)
	return err == nil
}
