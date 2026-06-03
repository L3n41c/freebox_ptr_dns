// Copyright 2026 Lénaïc Huard
//
// Licensed under the MIT License, see LICENSE for details

package hosts

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/L3n41c/freebox_ptr_dns/internal/freebox"
)

// fakeAPI is a controllable stub of the Freebox API used by the poller.
type fakeAPI struct {
	calls      atomic.Int32
	failNext   atomic.Int32 // non-zero ⇒ next N calls fail
	interfaces []freebox.LanInterface
	hostsByIf  map[string][]freebox.LanHost
}

func (f *fakeAPI) ListInterfaces(ctx context.Context) ([]freebox.LanInterface, error) {
	f.calls.Add(1)
	if f.failNext.Load() > 0 {
		f.failNext.Add(-1)
		return nil, errors.New("boom")
	}
	return f.interfaces, nil
}

func (f *fakeAPI) ListHosts(ctx context.Context, iface string) ([]freebox.LanHost, error) {
	return f.hostsByIf[iface], nil
}

func TestPoller_Refresh_PopulatesCache(t *testing.T) {
	api := &fakeAPI{
		interfaces: []freebox.LanInterface{{Name: "pub"}},
		hostsByIf: map[string][]freebox.LanHost{
			"pub": {
				{
					PrimaryName: "laptop",
					L3Connectivities: []freebox.L3Conn{
						{Addr: "192.168.1.42", Af: "ipv4"},
						{Addr: "fd00::1", Af: "ipv6"},
					},
				},
			},
		},
	}
	cache := NewCache()
	p := NewPoller(api, cache, "lan", 0)

	require.NoError(t, p.Refresh(t.Context()))
	name, ok := cache.Lookup(netip.MustParseAddr("192.168.1.42"))
	assert.True(t, ok)
	assert.Equal(t, "laptop.lan.", name)
	name, ok = cache.Lookup(netip.MustParseAddr("fd00::1"))
	assert.True(t, ok)
	assert.Equal(t, "laptop.lan.", name)
}

func TestPoller_Refresh_SkipsHostsWithoutName(t *testing.T) {
	api := &fakeAPI{
		interfaces: []freebox.LanInterface{{Name: "pub"}},
		hostsByIf: map[string][]freebox.LanHost{
			"pub": {
				{PrimaryName: "", L3Connectivities: []freebox.L3Conn{{Addr: "10.0.0.1"}}},
				{PrimaryName: "named", L3Connectivities: []freebox.L3Conn{{Addr: "10.0.0.2"}}},
			},
		},
	}
	cache := NewCache()
	p := NewPoller(api, cache, "lan", 0)

	require.NoError(t, p.Refresh(t.Context()))
	_, ok := cache.Lookup(netip.MustParseAddr("10.0.0.1"))
	assert.False(t, ok, "nameless host should be skipped")
	name, ok := cache.Lookup(netip.MustParseAddr("10.0.0.2"))
	assert.True(t, ok)
	assert.Equal(t, "named.lan.", name)
}

func TestPoller_Refresh_SkipsInvalidAddrs(t *testing.T) {
	api := &fakeAPI{
		interfaces: []freebox.LanInterface{{Name: "pub"}},
		hostsByIf: map[string][]freebox.LanHost{
			"pub": {
				{PrimaryName: "x", L3Connectivities: []freebox.L3Conn{
					{Addr: "not-an-ip", Af: "ipv4"},
					{Addr: "", Af: "ipv4"},
					{Addr: "10.0.0.7", Af: "ipv4"},
				}},
			},
		},
	}
	cache := NewCache()
	p := NewPoller(api, cache, "lan", 0)

	require.NoError(t, p.Refresh(t.Context()))
	assert.Equal(t, 1, cache.Len())
	_, ok := cache.Lookup(netip.MustParseAddr("10.0.0.7"))
	assert.True(t, ok, "valid addr missing")
}

func TestPoller_Refresh_SanitizesName(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"My Laptop", "my-laptop.lan."},
		{"café", "caf.lan."},    // accents removed, trailing '-' trimmed (RFC 1035)
		{"Léa", "l-a.lan."},     // accents in the middle keep the placeholder
		{"a/b\\c", "a-b-c.lan."},
		{"UPPER", "upper.lan."},
		{"  trim  ", "trim.lan."},
		{"-bad-", "bad.lan."}, // labels cannot start/end with '-'
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			api := &fakeAPI{
				interfaces: []freebox.LanInterface{{Name: "pub"}},
				hostsByIf: map[string][]freebox.LanHost{
					"pub": {
						{PrimaryName: tc.raw, L3Connectivities: []freebox.L3Conn{{Addr: "10.0.0.1"}}},
					},
				},
			}
			cache := NewCache()
			p := NewPoller(api, cache, "lan", 0)
			require.NoError(t, p.Refresh(t.Context()))
			name, _ := cache.Lookup(netip.MustParseAddr("10.0.0.1"))
			assert.Equal(t, tc.want, name)
		})
	}
}

func TestPoller_Refresh_LocalDomainOptional(t *testing.T) {
	// Empty local domain ⇒ bare name, still a FQDN (trailing dot).
	api := &fakeAPI{
		interfaces: []freebox.LanInterface{{Name: "pub"}},
		hostsByIf: map[string][]freebox.LanHost{
			"pub": {{PrimaryName: "host", L3Connectivities: []freebox.L3Conn{{Addr: "10.0.0.1"}}}},
		},
	}
	cache := NewCache()
	p := NewPoller(api, cache, "", 0)
	require.NoError(t, p.Refresh(t.Context()))
	name, _ := cache.Lookup(netip.MustParseAddr("10.0.0.1"))
	assert.Equal(t, "host.", name)
}

func TestPoller_Refresh_ErrorKeepsPreviousCache(t *testing.T) {
	api := &fakeAPI{
		interfaces: []freebox.LanInterface{{Name: "pub"}},
		hostsByIf: map[string][]freebox.LanHost{
			"pub": {{PrimaryName: "host", L3Connectivities: []freebox.L3Conn{{Addr: "10.0.0.1"}}}},
		},
	}
	cache := NewCache()
	p := NewPoller(api, cache, "lan", 0)

	require.NoError(t, p.Refresh(t.Context()))
	api.failNext.Store(1)
	assert.Error(t, p.Refresh(t.Context()), "expected error")
	name, ok := cache.Lookup(netip.MustParseAddr("10.0.0.1"))
	assert.True(t, ok)
	assert.Equal(t, "host.lan.", name, "cache should be unchanged")
}

func TestPoller_Run_TicksAndStops(t *testing.T) {
	api := &fakeAPI{
		interfaces: []freebox.LanInterface{{Name: "pub"}},
	}
	cache := NewCache()
	p := NewPoller(api, cache, "lan", 5*time.Millisecond)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- p.Run(ctx)
	}()

	time.Sleep(30 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		assert.NoError(t, err, "Run after cancel returned err")
	case <-time.After(time.Second):
		t.Fatal("Run did not return after cancel")
	}
	assert.GreaterOrEqual(t, api.calls.Load(), int32(2), "api called at least 2 times")
}

func TestPoller_Run_BubblesUpInvalidAppToken(t *testing.T) {
	api := &fakeAPIWithErr{err: freebox.ErrInvalidAppToken}
	p := NewPoller(api, NewCache(), "lan", 5*time.Millisecond)

	done := make(chan error, 1)
	go func() {
		done <- p.Run(t.Context())
	}()

	select {
	case err := <-done:
		assert.ErrorIs(t, err, freebox.ErrInvalidAppToken)
	case <-time.After(time.Second):
		t.Fatal("Run did not return on ErrInvalidAppToken")
	}
}

// fakeAPIWithErr always returns the configured error from ListInterfaces.
type fakeAPIWithErr struct{ err error }

func (f *fakeAPIWithErr) ListInterfaces(context.Context) ([]freebox.LanInterface, error) {
	return nil, f.err
}
func (f *fakeAPIWithErr) ListHosts(context.Context, string) ([]freebox.LanHost, error) {
	return nil, f.err
}
