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
				Port:     80,
				Host:     "Freebox-Server.local",
				InfoFields: []string{
					"api_version=4.0",
					"api_base_url=/api/",
					"api_domain=mafreebox.freebox.fr",
					"https_available=true",
					"https_port=443",
				},
			},
			expected: DiscoveryResult{
				APIDomain:      "mafreebox.freebox.fr",
				APIBaseURL:     "/api/",
				APIVersion:     "4.0",
				HTTPSPort:      443,
				HTTPSAvailable: true,
			},
		},
		{
			name: "entry with custom api_base_url",
			entry: mdns.ServiceEntry{
				Host: "host.local",
				InfoFields: []string{
					"api_version=4.0",
					"api_domain=mafreebox.freebox.fr",
					"https_port=8443",
					"api_base_url=/custom/",
				},
			},
			expected: DiscoveryResult{
				APIDomain:  "mafreebox.freebox.fr",
				APIBaseURL: "/custom/",
				APIVersion: "4.0",
				HTTPSPort:  8443,
			},
		},
		{
			name: "entry with default api_base_url",
			entry: mdns.ServiceEntry{
				InfoFields: []string{
					"api_version=4.0",
					"api_domain=mafreebox.freebox.fr",
					"https_port=443",
				},
			},
			expected: DiscoveryResult{
				APIDomain:  "mafreebox.freebox.fr",
				APIBaseURL: "/api/", // Default applied
				APIVersion: "4.0",
				HTTPSPort:  443,
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

func TestParseServiceEntryMissingRequiredFields(t *testing.T) {
	tests := []struct {
		name           string
		entry          mdns.ServiceEntry
		expectedErrSub string
	}{
		{
			name:           "missing api_version",
			entry:          mdns.ServiceEntry{InfoFields: []string{"api_domain=mafreebox.freebox.fr", "https_port=443"}},
			expectedErrSub: "empty api_version",
		},
		{
			name:           "missing api_domain",
			entry:          mdns.ServiceEntry{InfoFields: []string{"api_version=4.0", "https_port=443"}},
			expectedErrSub: "empty api_domain",
		},
		{
			name:           "missing https_port",
			entry:          mdns.ServiceEntry{InfoFields: []string{"api_version=4.0", "api_domain=mafreebox.freebox.fr"}},
			expectedErrSub: "empty https_port",
		},
		{
			name:           "missing api_domain and https_port",
			entry:          mdns.ServiceEntry{InfoFields: []string{"api_version=4.0"}},
			expectedErrSub: "empty api_domain", // First error encountered
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseServiceEntry(&tt.entry)
			require.Error(t, err, "parseServiceEntry should return error for missing required field")
			assert.Contains(t, err.Error(), tt.expectedErrSub, "error should mention the missing field")
		})
	}
}


