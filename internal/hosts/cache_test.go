// Copyright 2026 Lénaïc Huard
//
// Licensed under the MIT License, see LICENSE for details

package hosts

import (
	"net/netip"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCache_LookupOnEmpty(t *testing.T) {
	c := NewCache()
	_, ok := c.Lookup(netip.MustParseAddr("192.168.1.1"))
	assert.False(t, ok, "expected miss on empty cache")
}

func TestCache_ReplaceAndLookup(t *testing.T) {
	tests := []struct {
		name     string
		entries  map[netip.Addr]string
		addr     netip.Addr
		expected string
		wantOk   bool
	}{
		{
			name: "hit v4",
			entries: map[netip.Addr]string{
				netip.MustParseAddr("192.168.1.42"): "laptop.lan",
				netip.MustParseAddr("fd00::1"):      "router.lan",
			},
			addr:     netip.MustParseAddr("192.168.1.42"),
			expected: "laptop.lan",
			wantOk:   true,
		},
		{
			name: "hit v6",
			entries: map[netip.Addr]string{
				netip.MustParseAddr("192.168.1.42"): "laptop.lan",
				netip.MustParseAddr("fd00::1"):      "router.lan",
			},
			addr:     netip.MustParseAddr("fd00::1"),
			expected: "router.lan",
			wantOk:   true,
		},
		{
			name:    "miss",
			entries: map[netip.Addr]string{netip.MustParseAddr("192.168.1.42"): "laptop.lan"},
			addr:     netip.MustParseAddr("10.0.0.1"),
			expected: "",
			wantOk:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCache()
			c.Replace(tt.entries)
			name, ok := c.Lookup(tt.addr)
			assert.Equal(t, tt.wantOk, ok)
			assert.Equal(t, tt.expected, name)
		})
	}
}

func TestCache_ReplaceIsAtomic(t *testing.T) {
	// Two successive Replace must be visible atomically: every read sees
	// either the old or the new map fully, never a torn state.
	c := NewCache()
	old := map[netip.Addr]string{netip.MustParseAddr("10.0.0.1"): "old"}
	c.Replace(old)

	new := map[netip.Addr]string{netip.MustParseAddr("10.0.0.1"): "new"}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range 4 {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				name, ok := c.Lookup(netip.MustParseAddr("10.0.0.1"))
				if !assert.True(t, ok, "unexpected miss during concurrent replace") {
					return
				}
				if !assert.Contains(t, []string{"old", "new"}, name) {
					return
				}
			}
		})
	}
	for range 1000 {
		c.Replace(new)
		c.Replace(old)
	}
	close(stop)
	wg.Wait()
}

func TestCache_ReplaceDoesNotMutateInput(t *testing.T) {
	// After Replace, mutating the caller's map must not affect the cache.
	c := NewCache()
	m := map[netip.Addr]string{netip.MustParseAddr("10.0.0.1"): "host"}
	c.Replace(m)
	m[netip.MustParseAddr("10.0.0.1")] = "tampered"

	name, ok := c.Lookup(netip.MustParseAddr("10.0.0.1"))
	assert.True(t, ok)
	assert.Equal(t, "host", name, "cache mutated externally")
}

func TestCache_Len(t *testing.T) {
	tests := []struct {
		name     string
		entries  map[netip.Addr]string
		expected int
	}{
		{name: "empty", entries: nil, expected: 0},
		{name: "single", entries: map[netip.Addr]string{netip.MustParseAddr("1.1.1.1"): "a"}, expected: 1},
		{name: "multiple", entries: map[netip.Addr]string{
			netip.MustParseAddr("1.1.1.1"): "a",
			netip.MustParseAddr("2.2.2.2"): "b",
		}, expected: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCache()
			if tt.entries != nil {
				c.Replace(tt.entries)
			}
			assert.Equal(t, tt.expected, c.Len())
		})
	}
}
