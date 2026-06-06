// Copyright 2026 Lénaïc Huard
//
// Licensed under the MIT License, see LICENSE for details

package freebox

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/grandcat/zeroconf"
)

// DiscoveryResult contains the Freebox API information obtained via mDNS discovery.
type DiscoveryResult struct {
	// APIDomain is the domain name to use for API requests (e.g., "example.fbxos.fr").
	APIDomain string
	// APIBaseURL is the base path for API endpoints (e.g., "/api/").
	APIBaseURL string
	// APIVersion is the API version (e.g., "4.0").
	APIVersion string
	// HTTPSPort is the port for HTTPS access (e.g., 3615).
	HTTPSPort int
	// HTTPSAvailable indicates if HTTPS is configured on the Freebox.
	HTTPSAvailable bool
}

// discoverTimeout is the maximum time to wait for mDNS discovery.
const discoverTimeout = 5 * time.Second

// serviceName is the mDNS service name for Freebox API discovery.
const serviceName = "_fbx-api._tcp"

// ErrDiscoveryFailed is returned when no Freebox can be discovered on the network.
var ErrDiscoveryFailed = errors.New("freebox: mDNS discovery failed: no Freebox found on the network")

// Discover finds a Freebox on the local network using mDNS and returns its API information.
// It searches for the "_fbx-api._tcp" service and parses the TXT record to extract
// API configuration details.
func Discover(ctx context.Context) (DiscoveryResult, error) {
	// Create a zeroconf resolver
	resolver, err := zeroconf.NewResolver()
	if err != nil {
		return DiscoveryResult{}, fmt.Errorf("create mDNS resolver: %w", err)
	}

	// Create a context with timeout
	discCtx, cancel := context.WithTimeout(ctx, discoverTimeout)
	defer cancel()

	// Start searching for the Freebox API service
	entries := make(chan *zeroconf.ServiceEntry, 1)
	browseErr := make(chan error, 1)
	go func() {
		if err := resolver.Browse(discCtx, serviceName, "local.", entries); err != nil {
			browseErr <- err
		}
	}()

	// Wait for the first service entry
	select {
	case err := <-browseErr:
		// Browse returned an error, propagate it
		return DiscoveryResult{}, fmt.Errorf("mDNS browse: %w", err)
	case <-discCtx.Done():
		// Map context.DeadlineExceeded to ErrDiscoveryFailed for consistency
		if discCtx.Err() == context.DeadlineExceeded {
			return DiscoveryResult{}, ErrDiscoveryFailed
		}
		return DiscoveryResult{}, fmt.Errorf("mDNS discovery: %w", discCtx.Err())
	case entry, ok := <-entries:
		if !ok {
			return DiscoveryResult{}, ErrDiscoveryFailed
		}
		// Cancel immediately to avoid goroutine leak
		cancel()
		// Drain remaining entries to prevent sender block
		go func() {
			for {
				select {
				case <-entries:
					// Drain
				case <-discCtx.Done():
					return
				}
			}
		}()
		return parseServiceEntry(entry)
	}
}

// parseServiceEntry extracts Freebox API information from a mDNS service entry.
func parseServiceEntry(entry *zeroconf.ServiceEntry) (DiscoveryResult, error) {
	result := DiscoveryResult{}

	// Parse TXT records first to get all fields including https_port
	// Freebox mDNS TXT records contain key=value pairs like "api_version=4.0"
	for _, record := range entry.Text {
		if record != "" {
			parseTXTRecord(record, &result)
		}
	}

	// If https_port was not in TXT records, fall back to SRV port
	if result.HTTPSPort == 0 {
		result.HTTPSPort = entry.Port
	}

	// Validate and set defaults
	if result.APIDomain == "" {
		// Try to use the host name from the service entry as fallback
		// Trim trailing dot from mDNS hostname (e.g., "freebox.local." -> "freebox.local")
		if entry.HostName != "" {
			result.APIDomain = strings.TrimSuffix(entry.HostName, ".")
		} else {
			return DiscoveryResult{}, errors.New("freebox: mDNS discovery returned empty api_domain")
		}
	}
	if result.APIVersion == "" {
		return DiscoveryResult{}, errors.New("freebox: mDNS discovery returned empty api_version")
	}
	if result.APIBaseURL == "" {
		// Default to /api/ as per Freebox SDK
		result.APIBaseURL = "/api/"
	}

	return result, nil
}

// parseTXTRecord parses a single TXT record string in the format "key=value"
// and updates the result with the extracted information.
func parseTXTRecord(record string, result *DiscoveryResult) {
	key, value, ok := strings.Cut(record, "=")
	if !ok {
		// No '=' found, skip this record
		return
	}

	switch key {
	case "api_version":
		result.APIVersion = value
	case "api_base_url":
		result.APIBaseURL = value
	case "api_domain":
		result.APIDomain = value
	case "https_available":
		// Freebox mDNS encodes this as "1"/"0" or "true"/"false"
		result.HTTPSAvailable = value == "true" || value == "1"
	case "https_port":
		if port, err := strconv.Atoi(value); err == nil {
			result.HTTPSPort = port
		}
	}
}
