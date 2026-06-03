// Copyright 2026 Lénaïc Huard
//
// Licensed under the MIT License, see LICENSE for details

package hosts

import (
	"maps"
	"net/netip"
	"sync/atomic"
)

// Cache is a lock-free, atomically-swappable map of IP → host name.
// Readers never block; Replace publishes a brand-new immutable map.
type Cache struct {
	p atomic.Pointer[map[netip.Addr]string]
}

func NewCache() *Cache {
	c := &Cache{}
	empty := map[netip.Addr]string{}
	c.p.Store(&empty)
	return c
}

func (c *Cache) Lookup(addr netip.Addr) (string, bool) {
	m := *c.p.Load()
	name, ok := m[addr]
	return name, ok
}

func (c *Cache) Replace(m map[netip.Addr]string) {
	// Copy so the caller can't mutate the map we just published.
	copied := maps.Clone(m)
	c.p.Store(&copied)
}

func (c *Cache) Len() int {
	return len(*c.p.Load())
}
