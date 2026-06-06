// Copyright 2026 Lénaïc Huard
//
// Licensed under the MIT License, see LICENSE for details

package main

import (
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/L3n41c/freebox_ptr_dns/internal/freebox"
	"github.com/stretchr/testify/assert"
)

func TestParseLevel(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  slog.Level
	}{
		{"debug", "debug", slog.LevelDebug},
		{"info", "info", slog.LevelInfo},
		{"warn", "warn", slog.LevelWarn},
		{"error", "error", slog.LevelError},
		{"uppercase DEBUG", "DEBUG", slog.LevelDebug},
		{"uppercase INFO", "INFO", slog.LevelInfo},
		{"uppercase WARN", "WARN", slog.LevelWarn},
		{"uppercase ERROR", "ERROR", slog.LevelError},
		{"mixed case DeBuG", "DeBuG", slog.LevelDebug},
		{"with spaces defaults to info", " info ", slog.LevelInfo},
		{"empty defaults to info", "", slog.LevelInfo},
		{"unknown defaults to info", "unknown", slog.LevelInfo},
		{"random defaults to info", "random", slog.LevelInfo},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseLevel(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestExitCode(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{
			name: "ErrInvalidAppToken returns 2",
			err:  freebox.ErrInvalidAppToken,
			want: 2,
		},
		{
			name: "ErrAuthorizationDenied returns 3",
			err:  freebox.ErrAuthorizationDenied,
			want: 3,
		},
		{
			name: "ErrAuthorizationTimedOut returns 3",
			err:  freebox.ErrAuthorizationTimedOut,
			want: 3,
		},
		{
			name: "wrapped ErrInvalidAppToken returns 2",
			err:  errors.Join(freebox.ErrInvalidAppToken, errors.New("some error")),
			want: 2,
		},
		{
			name: "other error returns 1",
			err:  errors.New("some other error"),
			want: 1,
		},
		{
			name: "wrapped ErrAuthorizationDenied returns 3",
			err:  errors.Join(errors.New("context"), freebox.ErrAuthorizationDenied),
			want: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := exitCode(tt.err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPromptOnFreebox(t *testing.T) {
	// promptOnFreebox writes to os.Stderr and uses slog.Warn
	// We can only verify it doesn't panic with various inputs
	appNames := []string{
		"TestApp",
		"",
		"app with spaces",
		"app-with-dashes",
		"AppWithCaps",
		strings.Repeat("x", 100),
	}

	for _, appName := range appNames {
		t.Run(appName, func(t *testing.T) {
			// Verify it doesn't panic
			assert.NotPanics(t, func() {
				promptOnFreebox(appName)
			})
		})
	}
}
