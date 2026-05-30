// Copyright 2026 Lénaïc Huard
//
// Licensed under the MIT License, see LICENSE for details

package dns

import (
	"net"
	"net/netip"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/L3n41c/freebox_ptr_dns/internal/hosts"
)

// recWriter is a dns.ResponseWriter that records the last message written.
type recWriter struct {
	msg *mdns.Msg
}

func (r *recWriter) LocalAddr() net.Addr         { return &net.UDPAddr{} }
func (r *recWriter) RemoteAddr() net.Addr        { return &net.UDPAddr{} }
func (r *recWriter) WriteMsg(m *mdns.Msg) error  { r.msg = m; return nil }
func (r *recWriter) Write(b []byte) (int, error) { return len(b), nil }
func (r *recWriter) Close() error                { return nil }
func (r *recWriter) TsigStatus() error           { return nil }
func (r *recWriter) TsigTimersOnly(bool)         {}
func (r *recWriter) Hijack()                     {}

func newQuestion(name string, qtype uint16) *mdns.Msg {
	m := new(mdns.Msg)
	m.SetQuestion(mdns.Fqdn(name), qtype)
	return m
}

func newHandler(t *testing.T, populate map[string]string, networks []string) *Handler {
	t.Helper()
	cache := hosts.NewCache()
	m := make(map[netip.Addr]string, len(populate))
	for k, v := range populate {
		m[netip.MustParseAddr(k)] = v
	}
	cache.Replace(m)
	nets := make([]netip.Prefix, 0, len(networks))
	for _, n := range networks {
		nets = append(nets, netip.MustParsePrefix(n))
	}
	h := NewHandler(cache, 300*time.Second, nets)
	h.MarkReady()
	return h
}

func TestHandler_ServeDNS(t *testing.T) {
	tests := []struct {
		name      string
		populate  map[string]string
		networks   []string
		question   func() *mdns.Msg
		wantRcode  int
		wantPTR    string
		wantTTL    uint32
	}{
		{
			name:      "PTR hit IPv4",
			populate:  map[string]string{"192.168.1.42": "laptop.lan."},
			networks:   []string{"192.168.0.0/16"},
			question:   func() *mdns.Msg { return newQuestion("42.1.168.192.in-addr.arpa.", mdns.TypePTR) },
			wantRcode:  mdns.RcodeSuccess,
			wantPTR:    "laptop.lan.",
			wantTTL:    300,
		},
		{
			name:      "PTR hit IPv6",
			populate:  map[string]string{"fd00::1": "router.lan."},
			networks:   []string{"fd00::/8"},
			question:   func() *mdns.Msg { qname, _ := mdns.ReverseAddr("fd00::1"); return newQuestion(qname, mdns.TypePTR) },
			wantRcode:  mdns.RcodeSuccess,
			wantPTR:    "router.lan.",
		},
		{
			name:      "PTR miss",
			populate:  map[string]string{},
			networks:   []string{"192.168.0.0/16"},
			question:   func() *mdns.Msg { return newQuestion("99.1.168.192.in-addr.arpa.", mdns.TypePTR) },
			wantRcode:  mdns.RcodeNameError,
		},
		{
			name:      "outside allowed networks",
			populate:  map[string]string{},
			networks:   []string{"192.168.0.0/16"},
			question:   func() *mdns.Msg { return newQuestion("8.8.8.8.in-addr.arpa.", mdns.TypePTR) },
			wantRcode:  mdns.RcodeRefused,
		},
		{
			name:      "non PTR type",
			populate:  map[string]string{},
			networks:   []string{"192.168.0.0/16"},
			question:   func() *mdns.Msg { return newQuestion("example.com.", mdns.TypeA) },
			wantRcode:  mdns.RcodeRefused,
		},
		{
			name:      "non IN class",
			populate:  map[string]string{},
			networks:   []string{"192.168.0.0/16"},
			question:   func() *mdns.Msg {
				q := newQuestion("42.1.168.192.in-addr.arpa.", mdns.TypePTR)
				q.Question[0].Qclass = mdns.ClassCHAOS
				return q
			},
			wantRcode: mdns.RcodeRefused,
		},
		{
			name:      "malformed PTR name",
			populate:  map[string]string{},
			networks:   []string{"192.168.0.0/16"},
			question:   func() *mdns.Msg { return newQuestion("not.a.valid.in-addr.arpa.", mdns.TypePTR) },
			wantRcode:  mdns.RcodeFormatError,
		},
		{
			name:      "empty question",
			populate:  map[string]string{},
			networks:   []string{"192.168.0.0/16"},
			question:   func() *mdns.Msg { m := new(mdns.Msg); m.Id = 1; return m },
			wantRcode:  mdns.RcodeFormatError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHandler(t, tt.populate, tt.networks)
			w := &recWriter{}
			h.ServeDNS(w, tt.question())

			assert.Equal(t, tt.wantRcode, w.msg.Rcode)

			// Verify PTR-specific assertions for successful PTR lookups
			if tt.wantPTR != "" {
				require.Len(t, w.msg.Answer, 1, "expected exactly one answer for PTR hit")
				ptr, ok := w.msg.Answer[0].(*mdns.PTR)
				require.True(t, ok, "answer should be PTR type")
				assert.Equal(t, tt.wantPTR, ptr.Ptr)
				if tt.wantTTL > 0 {
					assert.Equal(t, tt.wantTTL, ptr.Hdr.Ttl)
				}
			} else {
				assert.Empty(t, w.msg.Answer)
			}
		})
	}
}

func TestHandler_ReturnsServfailUntilReady(t *testing.T) {
	// Before MarkReady() is called we must NOT answer authoritative
	// NXDOMAIN — we have no data, so SERVFAIL is the honest answer.
	cache := hosts.NewCache()
	nets := []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}
	h := NewHandler(cache, 300*time.Second, nets)

	w := &recWriter{}
	h.ServeDNS(w, newQuestion("42.1.168.192.in-addr.arpa.", mdns.TypePTR))
	assert.Equal(t, mdns.RcodeServerFailure, w.msg.Rcode, "before ready")

	h.MarkReady()
	w = &recWriter{}
	h.ServeDNS(w, newQuestion("42.1.168.192.in-addr.arpa.", mdns.TypePTR))
	assert.Equal(t, mdns.RcodeNameError, w.msg.Rcode, "after ready")
}

func TestHandler_NxDomainHasSOA(t *testing.T) {
	// RFC 2308: a negative response should carry an SOA in the authority
	// section so downstream caches can negatively cache for a short time.
	h := newHandler(t, map[string]string{}, []string{"192.168.0.0/16"})

	w := &recWriter{}
	h.ServeDNS(w, newQuestion("99.1.168.192.in-addr.arpa.", mdns.TypePTR))

	assert.Equal(t, mdns.RcodeNameError, w.msg.Rcode)
	require.NotEmpty(t, w.msg.Ns, "NXDOMAIN response should have SOA in authority")
	soa, ok := w.msg.Ns[0].(*mdns.SOA)
	require.True(t, ok, "authority[0] should be *SOA")
	assert.Greater(t, soa.Minttl, uint32(0), "SOA MinTTL should be > 0 for negative caching")
}
