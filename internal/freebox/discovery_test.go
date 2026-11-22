// Copyright 2026 Lénaïc Huard
//
// Licensed under the MIT License, see LICENSE for details

package freebox

import (
	"testing"

	mdns "github.com/hashicorp/mdns"
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
		entry    mdns.ServiceEntry
		expected DiscoveryResult
	}{
		{
			name: "full mDNS entry",
			entry: mdns.ServiceEntry{
				Port: 80, // SRV port is the plain HTTP port and must be ignored
				Host: "Freebox-Server.local.",
				InfoFields: []string{
					"api_version=4.0",
					"api_base_url=/api/",
					"api_domain=mafreebox.freebox.fr",
					"https_available=true",
					"https_port=3615",
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
			name: "minimal entry with defaults",
			entry: mdns.ServiceEntry{
				Port:       80,
				Host:       "freebox-server.local",
				InfoFields: []string{"api_version=4.0", "api_domain=example.fbxos.fr", "https_port=443"},
			},
			expected: DiscoveryResult{
				APIDomain:  "example.fbxos.fr",
				APIBaseURL: "/api/",
				APIVersion: "4.0",
				HTTPSPort:  443,
			},
		},
		{
			name: "entry with api_base_url without leading slash",
			entry: mdns.ServiceEntry{
				Host:       "host.local",
				InfoFields: []string{"api_version=4.0", "api_base_url=api", "api_domain=host.example", "https_port=8443"},
			},
			expected: DiscoveryResult{
				APIDomain:  "host.example",
				APIBaseURL: "api",
				APIVersion: "4.0",
				HTTPSPort:  8443,
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
	// api_domain is part of the TXT record advertised by the Freebox; the SRV
	// target (Host) must not be used as a fallback, even when present.
	entry := mdns.ServiceEntry{
		Host:       "Freebox-Server.local.",
		InfoFields: []string{"api_version=4.0"},
	}
	_, err := parseServiceEntry(&entry)
	require.Error(t, err, "should return error when api_domain is missing from the TXT record")
	assert.Contains(t, err.Error(), "empty api_domain", "error should mention empty api_domain")
}

func TestParseServiceEntryMissingHTTPSPort(t *testing.T) {
	// https_port is part of the TXT record advertised by the Freebox; the SRV
	// port must not be used as a fallback, even when present.
	entry := mdns.ServiceEntry{
		Port:       80,
		InfoFields: []string{"api_version=4.0", "api_domain=mafreebox.freebox.fr"},
	}
	_, err := parseServiceEntry(&entry)
	require.Error(t, err, "should return error when https_port is missing from the TXT record")
	assert.Contains(t, err.Error(), "empty https_port", "error should mention empty https_port")
}

func TestParseServiceEntryMissingAPIVersion(t *testing.T) {
	// Test that parseServiceEntry returns error when api_version is missing
	entry := mdns.ServiceEntry{
		Host:       "host.local",
		InfoFields: []string{"api_domain=host.local"},
	}
	_, err := parseServiceEntry(&entry)
	require.Error(t, err, "should return error when api_version is empty")
	assert.Contains(t, err.Error(), "empty api_version", "error should mention empty api_version")
}
