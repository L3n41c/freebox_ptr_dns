// Copyright 2026 Lénaïc Huard
//
// Licensed under the MIT License, see LICENSE for details

package freebox

import (
	"testing"

	"github.com/grandcat/zeroconf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseTXTRecord(t *testing.T) {
	tests := []struct {
		name     string
		record   string
		expected DiscoveryResult
	}{
		{
			name:     "api_version",
			record:   "api_version=4.0",
			expected: DiscoveryResult{APIVersion: "4.0"},
		},
		{
			name:     "api_base_url",
			record:   "api_base_url=/api/",
			expected: DiscoveryResult{APIBaseURL: "/api/"},
		},
		{
			name:     "api_domain",
			record:   "api_domain=mafreebox.freebox.fr",
			expected: DiscoveryResult{APIDomain: "mafreebox.freebox.fr"},
		},
		{
			name:     "https_available true",
			record:   "https_available=true",
			expected: DiscoveryResult{HTTPSAvailable: true},
		},
		{
			name:     "https_available false",
			record:   "https_available=false",
			expected: DiscoveryResult{HTTPSAvailable: false},
		},
		{
			name:     "https_available 1",
			record:   "https_available=1",
			expected: DiscoveryResult{HTTPSAvailable: true},
		},
		{
			name:     "https_available 0",
			record:   "https_available=0",
			expected: DiscoveryResult{HTTPSAvailable: false},
		},
		{
			name:     "https_port",
			record:   "https_port=3615",
			expected: DiscoveryResult{HTTPSPort: 3615},
		},
		{
			name:     "unknown key",
			record:   "unknown=value",
			expected: DiscoveryResult{},
		},
		{
			name:     "empty record",
			record:   "",
			expected: DiscoveryResult{},
		},
		{
			name:     "no equals sign",
			record:   "api_version",
			expected: DiscoveryResult{},
		},
		{
			name:     "empty value",
			record:   "api_version=",
			expected: DiscoveryResult{APIVersion: ""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DiscoveryResult{}
			parseTXTRecord(tt.record, &result)
			assert.Equal(t, tt.expected.APIVersion, result.APIVersion, "APIVersion mismatch")
			assert.Equal(t, tt.expected.APIBaseURL, result.APIBaseURL, "APIBaseURL mismatch")
			assert.Equal(t, tt.expected.APIDomain, result.APIDomain, "APIDomain mismatch")
			assert.Equal(t, tt.expected.HTTPSPort, result.HTTPSPort, "HTTPSPort mismatch")
			assert.Equal(t, tt.expected.HTTPSAvailable, result.HTTPSAvailable, "HTTPSAvailable mismatch")
		})
	}
}

func TestParseServiceEntry(t *testing.T) {
	tests := []struct {
		name     string
		entry    zeroconf.ServiceEntry
		expected DiscoveryResult
	}{
		{
			name: "full mDNS entry",
			entry: zeroconf.ServiceEntry{
				Port:     3615,
				HostName: "mafreebox.freebox.fr",
				Text: []string{
					"api_version=4.0",
					"api_base_url=/api/",
					"api_domain=mafreebox.freebox.fr",
					"https_available=true",
				},
			},
			expected: DiscoveryResult{
				APIDomain:      "mafreebox.freebox.fr",
				APIBaseURL:     "/api/",
				APIVersion:     "4.0",
				HTTPSPort:      3615,
				HTTPSAvailable: true,
			},
		},
		{
			name: "entry with trailing dot in hostname",
			entry: zeroconf.ServiceEntry{
				Port:     3615,
				HostName: "mafreebox.freebox.fr.",
				Text:     []string{"api_version=4.0"},
			},
			expected: DiscoveryResult{
				APIDomain:  "mafreebox.freebox.fr",
				APIVersion: "4.0",
				HTTPSPort:  3615,
				APIBaseURL: "/api/",
			},
		},
		{
			name: "minimal entry with defaults",
			entry: zeroconf.ServiceEntry{
				Port:     80,
				HostName: "fallback.local",
				Text:     []string{"api_version=4.0"},
			},
			expected: DiscoveryResult{
				APIDomain:  "fallback.local",
				APIBaseURL: "/api/",
				APIVersion: "4.0",
				HTTPSPort:  80,
			},
		},
		{
			name: "entry with api_base_url without leading slash",
			entry: zeroconf.ServiceEntry{
				HostName: "host.local",
				Text:     []string{"api_version=4.0", "api_base_url=api"},
			},
			expected: DiscoveryResult{
				APIDomain:  "host.local",
				APIBaseURL: "api",
				APIVersion: "4.0",
				HTTPSPort:  0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseServiceEntry(&tt.entry)
			require.NoError(t, err, "parseServiceEntry should not return error")
			assert.Equal(t, tt.expected.APIDomain, result.APIDomain, "APIDomain mismatch")
			assert.Equal(t, tt.expected.APIBaseURL, result.APIBaseURL, "APIBaseURL mismatch")
			assert.Equal(t, tt.expected.APIVersion, result.APIVersion, "APIVersion mismatch")
			assert.Equal(t, tt.expected.HTTPSPort, result.HTTPSPort, "HTTPSPort mismatch")
			assert.Equal(t, tt.expected.HTTPSAvailable, result.HTTPSAvailable, "HTTPSAvailable mismatch")
		})
	}
}

func TestParseServiceEntryMissingAPIDomain(t *testing.T) {
	// Test that parseServiceEntry returns error when api_domain is missing and no hostname
	entry := zeroconf.ServiceEntry{
		Text: []string{"api_version=4.0"},
	}
	_, err := parseServiceEntry(&entry)
	require.Error(t, err, "should return error when api_domain is empty and no hostname")
	assert.Contains(t, err.Error(), "empty api_domain", "error should mention empty api_domain")
}

func TestParseServiceEntryMissingAPIVersion(t *testing.T) {
	// Test that parseServiceEntry returns error when api_version is missing
	entry := zeroconf.ServiceEntry{
		HostName: "host.local",
		Text:     []string{"api_domain=host.local"},
	}
	_, err := parseServiceEntry(&entry)
	require.Error(t, err, "should return error when api_version is empty")
	assert.Contains(t, err.Error(), "empty api_version", "error should mention empty api_version")
}


