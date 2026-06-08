// Copyright 2026 Lénaïc Huard
//
// Licensed under the MIT License, see LICENSE for details

package config

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.toml")
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600), "write config file")
	return p
}

func TestLoad(t *testing.T) {
	cases := []struct {
		name          string
		config        string
		filePath      string
		wantErr       bool
		wantErrSubstr string
		expected      *Config
	}{
		// === SUCCESS CASES ===
		{
			name: "full config",
			config: `[freebox]
token_path   = "/var/lib/test/token"

[dns]
listen           = "127.0.0.1:5353"
ttl              = "10m"
local_domain     = "home"
allowed_networks = ["192.168.0.0/16", "fd00::/8"]

[poller]
interval         = "45s"
http_timeout     = "10s"`,
			wantErr: false,
			expected: &Config{
				Freebox: Freebox{
					TokenPath: "/var/lib/test/token",
				},
				DNS: DNS{
					Listen:      "127.0.0.1:5353",
					TTL:         10 * time.Minute,
					LocalDomain: LocalDomain("home"),
					AllowedNetworks: []netip.Prefix{
						netip.MustParsePrefix("192.168.0.0/16"),
						netip.MustParsePrefix("fd00::/8"),
					},
				},
				Poller: Poller{
					Interval:    45 * time.Second,
					HTTPTimeout: 10 * time.Second,
				},
			},
		},
		{
			name: "applies defaults",
			config: `[freebox]
token_path  = "/tmp/token"`,
			wantErr: false,
			expected: &Config{
				Freebox: Freebox{
					TokenPath: "/tmp/token",
				},
				DNS: DNS{
					Listen:      "0.0.0.0:53",
					TTL:         5 * time.Minute,
					LocalDomain: LocalDomain("lan"),
					AllowedNetworks: []netip.Prefix{
						netip.MustParsePrefix("10.0.0.0/8"),
						netip.MustParsePrefix("172.16.0.0/12"),
						netip.MustParsePrefix("192.168.0.0/16"),
						netip.MustParsePrefix("fc00::/7"),
						netip.MustParsePrefix("fe80::/10"),
					},
				},
				Poller: Poller{
					Interval:    30 * time.Second,
					HTTPTimeout: 5 * time.Second,
				},
			},
		},
		{
			name: "explicit empty local domain honored",
			config: `[freebox]
token_path="/tmp/t"

[dns]
local_domain = ""`,
			wantErr: false,
			expected: &Config{
				Freebox: Freebox{
					TokenPath: "/tmp/t",
				},
				DNS: DNS{
					Listen:      "0.0.0.0:53",
					TTL:         5 * time.Minute,
					LocalDomain: LocalDomain(""),
					AllowedNetworks: []netip.Prefix{
						netip.MustParsePrefix("10.0.0.0/8"),
						netip.MustParsePrefix("172.16.0.0/12"),
						netip.MustParsePrefix("192.168.0.0/16"),
						netip.MustParsePrefix("fc00::/7"),
						netip.MustParsePrefix("fe80::/10"),
					},
				},
				Poller: Poller{
					Interval:    30 * time.Second,
					HTTPTimeout: 5 * time.Second,
				},
			},
		},

		// === ERROR CASES ===
		{
			name: "rejects unknown keys",
			config: `[freebox]
token_path  = "/tmp/t"
unknown_key = "oops"`,
			wantErr:       true,
			wantErrSubstr: "unknown_key",
		},
		{
			name: "rejects invalid CIDR",
			config: `[freebox]
token_path  = "/tmp/t"

[dns]
allowed_networks = ["not-a-cidr"]`,
			wantErr:       true,
			wantErrSubstr: "allowed_networks",
		},

		{
			name: "rejects missing token_path",
			config: `[freebox]`,
			wantErr:       true,
			wantErrSubstr: "token_path",
		},
		{
			name: "rejects zero durations",
			config: `[freebox]
token_path="/tmp/t"

[dns]
ttl = "0s"`,
			wantErr:       true,
			wantErrSubstr: "ttl",
		},
		{
			name: "rejects bad listen",
			config: `[freebox]
token_path="/tmp/t"

[dns]
listen = "no-port-here"`,
			wantErr: true,
		},
		{
			name:     "file not found",
			filePath: "/nonexistent/path/config.toml",
			wantErr:  true,
		},
		{
			name: "rejects empty allowed_networks",
			config: `[freebox]
token_path="/tmp/t"

[dns]
allowed_networks = []`,
			wantErr:       true,
			wantErrSubstr: "allowed_networks",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var path string
			if tc.filePath != "" {
				path = tc.filePath
			} else {
				path = writeConfig(t, tc.config)
			}

			cfg, err := Load(path)

			if tc.wantErr {
				require.Error(t, err, "expected error")
				if tc.wantErrSubstr != "" {
					assert.Contains(t, err.Error(), tc.wantErrSubstr)
				}
			} else {
				require.NoError(t, err, "unexpected error")
				assert.Equal(t, tc.expected, cfg)
			}
		})
	}
}

func TestLoad_LocalDomainValidation(t *testing.T) {
	header := `[freebox]
token_path="/tmp/t"

[dns]
`

	cases := []struct {
		name    string
		domain  string
		wantErr bool
	}{
		{"empty allowed", `""`, false},
		{"simple", `"lan"`, false},
		{"two labels", `"home.lan"`, false},
		{"trailing dot", `"lan."`, true},
		{"space", `"home lan"`, true},
		{"leading dash", `"-lan"`, true},
		{"empty label", `"home..lan"`, true},
		{"unicode", `"café"`, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := writeConfig(t, header+"local_domain = "+tc.domain)
			_, err := Load(p)

			if tc.wantErr {
				require.Error(t, err, "expected error for domain=%s", tc.domain)
				return
			}

			require.NoError(t, err, "unexpected error for domain=%s: %v", tc.domain, err)
		})
	}
}

// --- LocalDomain.String() ----------------------------------------------------

func TestLocalDomain_String(t *testing.T) {
	tests := []struct {
		name     string
		input    LocalDomain
		want     string
	}{
		{"empty", LocalDomain(""), ""},
		{"simple", LocalDomain("lan"), "lan"},
		{"multi-label", LocalDomain("home.lan"), "home.lan"},
		{"with numbers", LocalDomain("mynet123.local"), "mynet123.local"},
		{"with dashes", LocalDomain("my-domain.local"), "my-domain.local"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.input.String()
			assert.Equal(t, tt.want, got)
		})
	}
}

// --- validateLocalDomain ---------------------------------------------------

func TestValidateLocalDomain(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"empty allowed", "", false},
		{"simple", "lan", false},
		{"two labels", "home.lan", false},
		{"with numbers", "mynet123", false},
		{"with dashes in middle", "my-domain", false},
		{"trailing dot", "lan.", true},
		{"embedded space", "home lan", true},
		{"leading dash", "-lan", true},
		{"trailing dash", "lan-", true},
		{"empty label", "home..lan", true},
		{"label too long", strings.Repeat("a", 64), true},
		{"label exactly 63", strings.Repeat("a", 63), false},
		{"unicode", "café", true},
		{"uppercase", "LAN", false},
		{"mixed case", "MyLan", false},
		{"only dash", "-", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateLocalDomain(tt.input)
			if tt.wantErr {
				require.Error(t, err, "expected error for %s", tt.name)
			} else {
				require.NoError(t, err, "unexpected error for %s", tt.name)
			}
		})
	}
}
