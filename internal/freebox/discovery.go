// Copyright 2026 Lénaïc Huard
//
// Licensed under the MIT License, see LICENSE for details

package freebox

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	mdns "github.com/hashicorp/mdns"
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
// It queries on all available network interfaces to ensure discovery works across
// all network configurations including IPv6.
func Discover(ctx context.Context) (DiscoveryResult, error) {
	// Create a context with timeout for the mDNS query
	discCtx, cancel := context.WithTimeout(ctx, discoverTimeout)
	defer cancel()

	// Get all network interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		return DiscoveryResult{}, fmt.Errorf("get network interfaces: %w", err)
	}

	// Create a channel to collect results from all interfaces
	entries := make(chan *mdns.ServiceEntry, len(ifaces))

	// Launch a query on each active, non-loopback interface
	for i := range ifaces {
		iface := ifaces[i]
		// Skip down and loopback interfaces
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		go func(iface net.Interface) {
			// Create a channel for this interface's query results
			ifaceEntries := make(chan *mdns.ServiceEntry, 1)
			
			params := &mdns.QueryParam{
				Service:   serviceName,
				Domain:    "local",
				Entries:   ifaceEntries,
				Interface: &iface,
			}
			
			if err := mdns.QueryContext(discCtx, params); err != nil {
				// Log at debug level: failure on one interface is not fatal,
				// other interfaces may still succeed
				slog.Debug("mDNS query failed on interface",
					"interface", iface.Name,
					"error", err)
			}
			
			// Forward the first result (if any) to main channel
			if entry, ok := <-ifaceEntries; ok {
				entries <- entry
			}
		}(iface)
	}

	// Wait for the first service entry from any interface
	select {
	case entry, ok := <-entries:
		if !ok {
			return DiscoveryResult{}, ErrDiscoveryFailed
		}
		return parseServiceEntry(entry)
	case <-discCtx.Done():
		// Map context.DeadlineExceeded to ErrDiscoveryFailed for consistency
		if discCtx.Err() == context.DeadlineExceeded {
			return DiscoveryResult{}, ErrDiscoveryFailed
		}
		return DiscoveryResult{}, fmt.Errorf("mDNS discovery: %w", discCtx.Err())
	}
}

// parseServiceEntry extracts Freebox API information from a mDNS service entry.
func parseServiceEntry(entry *mdns.ServiceEntry) (DiscoveryResult, error) {
	result := DiscoveryResult{}

	// Parse TXT records first to get all fields including https_port
	// Freebox mDNS TXT records contain key=value pairs like "api_version=4.0"
	for _, record := range entry.InfoFields {
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
		if entry.Host != "" {
			result.APIDomain = strings.TrimSuffix(entry.Host, ".")
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
