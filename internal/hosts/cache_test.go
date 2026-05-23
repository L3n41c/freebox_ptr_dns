package hosts

import (
	"net/netip"
	"sync"
	"testing"
)

func TestCache_LookupOnEmpty(t *testing.T) {
	c := NewCache()
	_, ok := c.Lookup(netip.MustParseAddr("192.168.1.1"))
	if ok {
		t.Fatal("expected miss on empty cache")
	}
}

func TestCache_ReplaceAndLookup(t *testing.T) {
	c := NewCache()
	m := map[netip.Addr]string{
		netip.MustParseAddr("192.168.1.42"): "laptop.lan",
		netip.MustParseAddr("fd00::1"):      "router.lan",
	}
	c.Replace(m)

	name, ok := c.Lookup(netip.MustParseAddr("192.168.1.42"))
	if !ok || name != "laptop.lan" {
		t.Errorf("lookup v4: got (%q, %v)", name, ok)
	}
	name, ok = c.Lookup(netip.MustParseAddr("fd00::1"))
	if !ok || name != "router.lan" {
		t.Errorf("lookup v6: got (%q, %v)", name, ok)
	}
	_, ok = c.Lookup(netip.MustParseAddr("10.0.0.1"))
	if ok {
		t.Error("expected miss for unknown addr")
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
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				name, ok := c.Lookup(netip.MustParseAddr("10.0.0.1"))
				if !ok {
					t.Errorf("unexpected miss during concurrent replace")
					return
				}
				if name != "old" && name != "new" {
					t.Errorf("torn read: %q", name)
					return
				}
			}
		}()
	}
	for i := 0; i < 1000; i++ {
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
	if !ok || name != "host" {
		t.Errorf("cache mutated externally: got (%q, %v)", name, ok)
	}
}

func TestCache_Len(t *testing.T) {
	c := NewCache()
	if c.Len() != 0 {
		t.Errorf("empty cache Len = %d", c.Len())
	}
	c.Replace(map[netip.Addr]string{
		netip.MustParseAddr("1.1.1.1"): "a",
		netip.MustParseAddr("2.2.2.2"): "b",
	})
	if c.Len() != 2 {
		t.Errorf("Len = %d", c.Len())
	}
}
