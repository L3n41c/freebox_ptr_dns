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

// queryTimeout is the duration of a single mDNS query attempt.
const queryTimeout = time.Second

// queryRetryDelay is the pause between two query attempts.
const queryRetryDelay = 500 * time.Millisecond

// serviceName is the mDNS service name for Freebox API discovery.
const serviceName = "_fbx-api._tcp"

// serviceSuffix is the FQDN suffix of the service instances (e.g., "Freebox._fbx-api._tcp.local.").
const serviceSuffix = serviceName + ".local."

// ErrDiscoveryFailed is returned when no Freebox can be discovered on the network.
var ErrDiscoveryFailed = errors.New("freebox: mDNS discovery failed: no Freebox found on the network")

// Discover finds a Freebox on the local network via mDNS ("_fbx-api._tcp") and
// parses its TXT record for the API configuration.
//
// Only the default multicast interface is queried (single-interface deployment).
// Attempts are retried until discoverTimeout: the mdns library can drop an entry
// (non-blocking send), but the Freebox answers every PTR query, so a dropped
// entry is received again on the next attempt.
func Discover(ctx context.Context) (DiscoveryResult, error) {
	ctx, cancel := context.WithTimeout(ctx, discoverTimeout)
	defer cancel()

	for ctx.Err() == nil {
		result, found, err := query(ctx)
		if found {
			return result, nil
		}
		if err != nil && ctx.Err() == nil {
			return DiscoveryResult{}, err
		}
		select {
		case <-ctx.Done():
		case <-time.After(queryRetryDelay):
		}
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return DiscoveryResult{}, ErrDiscoveryFailed
	}
	return DiscoveryResult{}, fmt.Errorf("mDNS discovery: %w", ctx.Err())
}

// query runs a single bounded mDNS query for the Freebox service.
// found is false when the query completes without a matching entry.
func query(ctx context.Context) (DiscoveryResult, bool, error) {
	entries := make(chan *mdns.ServiceEntry, 8)
	params := &mdns.QueryParam{
		Service: serviceName,
		Domain:  "local.",
		Timeout: queryTimeout,
		Entries: entries,
	}
	done := make(chan error, 1)
	go func() {
		done <- mdns.QueryContext(ctx, params)
	}()

	// parseIfService parses entry if it belongs to the browsed service: the mdns
	// library does not filter answers by service type.
	parseIfService := func(entry *mdns.ServiceEntry) (DiscoveryResult, bool, error) {
		if !strings.HasSuffix(strings.ToLower(entry.Name), "."+serviceSuffix) {
			return DiscoveryResult{}, false, nil
		}
		result, err := parseServiceEntry(entry)
		return result, err == nil, err
	}

	for {
		select {
		case entry := <-entries:
			if result, found, err := parseIfService(entry); found || err != nil {
				return result, found, err
			}
		case err := <-done:
			if err != nil {
				return DiscoveryResult{}, false, fmt.Errorf("mDNS query: %w", err)
			}
			// The query is over and no more entries will be sent: drain the
			// ones received just before completion.
			for {
				select {
				case entry := <-entries:
					if result, found, err := parseIfService(entry); found || err != nil {
						return result, found, err
					}
				default:
					return DiscoveryResult{}, false, nil
				}
			}
		case <-ctx.Done():
			return DiscoveryResult{}, false, ctx.Err()
		}
	}
}

// parseServiceEntry extracts Freebox API information from a mDNS service entry.
// The TXT record of the "_fbx-api._tcp" service advertised by the Freebox carries
// the api_domain, api_version and https_port keys (see https://dev.freebox.fr/sdk/os/);
// all of them are required. The SRV target and port are local mDNS data and are
// not used: the SRV port is the plain HTTP port, not the HTTPS one.
func parseServiceEntry(entry *mdns.ServiceEntry) (DiscoveryResult, error) {
	result := DiscoveryResult{}

	// Freebox mDNS TXT records contain key=value pairs like "api_version=4.0"
	for _, record := range entry.InfoFields {
		if record != "" {
			parseTXTRecord(record, &result)
		}
	}

	if result.APIDomain == "" {
		return DiscoveryResult{}, errors.New("freebox: mDNS discovery returned empty api_domain")
	}
	if result.APIVersion == "" {
		return DiscoveryResult{}, errors.New("freebox: mDNS discovery returned empty api_version")
	}
	if result.HTTPSPort == 0 {
		return DiscoveryResult{}, errors.New("freebox: mDNS discovery returned empty https_port")
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
