// Copyright 2026 Lénaïc Huard
//
// Licensed under the MIT License, see LICENSE for details

package systemd

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewJournalHandler(t *testing.T) {
	handler, err := NewJournalHandler(slog.LevelInfo)
	require.NoError(t, err)
	require.NotNil(t, handler)
}

func TestIsJournalAvailable(t *testing.T) {
	// This test just verifies the function doesn't panic
	// The actual availability depends on the system configuration
	available := IsJournalAvailable()
	t.Logf("Journald available: %v", available)
	// We don't assert on the value as it depends on the test environment
}

func TestJournalHandlerDoesNotPanic(t *testing.T) {
	// Test that the handler doesn't panic with various key formats
	// journald requires keys in format [A-Z_][A-Z0-9_]*
	handler, err := NewJournalHandler(slog.LevelInfo)
	if err != nil {
		t.Skip("journald not available")
	}

	logger := slog.New(handler)
	// Verify it doesn't panic with keys that need transformation
	logger.Info("test", "err", "test error", "http-status", 200)
}
