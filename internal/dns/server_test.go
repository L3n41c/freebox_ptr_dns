package dns

import (
	"net"
	"net/netip"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

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

func TestHandler_PTRHit(t *testing.T) {
	h := newHandler(t, map[string]string{"192.168.1.42": "laptop.lan."}, []string{"192.168.0.0/16"})

	w := &recWriter{}
	h.ServeDNS(w, newQuestion("42.1.168.192.in-addr.arpa.", mdns.TypePTR))

	if w.msg == nil {
		t.Fatal("no response")
	}
	if w.msg.Rcode != mdns.RcodeSuccess {
		t.Errorf("Rcode = %d, want NOERROR", w.msg.Rcode)
	}
	if len(w.msg.Answer) != 1 {
		t.Fatalf("answers = %d", len(w.msg.Answer))
	}
	ptr, ok := w.msg.Answer[0].(*mdns.PTR)
	if !ok {
		t.Fatalf("answer not PTR: %T", w.msg.Answer[0])
	}
	if ptr.Ptr != "laptop.lan." {
		t.Errorf("Ptr = %q", ptr.Ptr)
	}
	if ptr.Hdr.Ttl != 300 {
		t.Errorf("Ttl = %d", ptr.Hdr.Ttl)
	}
}

func TestHandler_PTRHit_IPv6(t *testing.T) {
	h := newHandler(t,
		map[string]string{"fd00::1": "router.lan."},
		[]string{"fd00::/8"},
	)

	qname, _ := mdns.ReverseAddr("fd00::1")
	w := &recWriter{}
	h.ServeDNS(w, newQuestion(qname, mdns.TypePTR))

	if w.msg.Rcode != mdns.RcodeSuccess {
		t.Errorf("Rcode = %d", w.msg.Rcode)
	}
	if len(w.msg.Answer) != 1 {
		t.Fatalf("answers = %d", len(w.msg.Answer))
	}
	ptr := w.msg.Answer[0].(*mdns.PTR)
	if ptr.Ptr != "router.lan." {
		t.Errorf("Ptr = %q", ptr.Ptr)
	}
}

func TestHandler_PTRMiss(t *testing.T) {
	h := newHandler(t, map[string]string{}, []string{"192.168.0.0/16"})

	w := &recWriter{}
	h.ServeDNS(w, newQuestion("99.1.168.192.in-addr.arpa.", mdns.TypePTR))

	if w.msg.Rcode != mdns.RcodeNameError {
		t.Errorf("Rcode = %d, want NXDOMAIN", w.msg.Rcode)
	}
	if len(w.msg.Answer) != 0 {
		t.Errorf("expected no answers, got %d", len(w.msg.Answer))
	}
}

func TestHandler_OutsideAllowedNetworks(t *testing.T) {
	h := newHandler(t, map[string]string{}, []string{"192.168.0.0/16"})

	w := &recWriter{}
	h.ServeDNS(w, newQuestion("8.8.8.8.in-addr.arpa.", mdns.TypePTR))

	if w.msg.Rcode != mdns.RcodeRefused {
		t.Errorf("Rcode = %d, want REFUSED", w.msg.Rcode)
	}
}

func TestHandler_NonPTRType(t *testing.T) {
	h := newHandler(t, map[string]string{}, []string{"192.168.0.0/16"})

	w := &recWriter{}
	h.ServeDNS(w, newQuestion("example.com.", mdns.TypeA))

	if w.msg.Rcode != mdns.RcodeRefused {
		t.Errorf("Rcode = %d, want REFUSED", w.msg.Rcode)
	}
}

func TestHandler_NonINClass(t *testing.T) {
	h := newHandler(t, map[string]string{}, []string{"192.168.0.0/16"})

	q := newQuestion("42.1.168.192.in-addr.arpa.", mdns.TypePTR)
	q.Question[0].Qclass = mdns.ClassCHAOS

	w := &recWriter{}
	h.ServeDNS(w, q)

	if w.msg.Rcode != mdns.RcodeRefused {
		t.Errorf("Rcode = %d, want REFUSED", w.msg.Rcode)
	}
}

func TestHandler_MalformedPTRName(t *testing.T) {
	h := newHandler(t, map[string]string{}, []string{"192.168.0.0/16"})

	w := &recWriter{}
	h.ServeDNS(w, newQuestion("not.a.valid.in-addr.arpa.", mdns.TypePTR))

	if w.msg.Rcode != mdns.RcodeFormatError {
		t.Errorf("Rcode = %d, want FORMERR", w.msg.Rcode)
	}
}

func TestHandler_EmptyQuestion(t *testing.T) {
	h := newHandler(t, map[string]string{}, []string{"192.168.0.0/16"})

	w := &recWriter{}
	m := new(mdns.Msg)
	m.Id = 1
	h.ServeDNS(w, m)

	if w.msg.Rcode != mdns.RcodeFormatError {
		t.Errorf("Rcode = %d, want FORMERR", w.msg.Rcode)
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
	if w.msg.Rcode != mdns.RcodeServerFailure {
		t.Errorf("before ready: Rcode = %d, want SERVFAIL", w.msg.Rcode)
	}

	h.MarkReady()
	w = &recWriter{}
	h.ServeDNS(w, newQuestion("42.1.168.192.in-addr.arpa.", mdns.TypePTR))
	if w.msg.Rcode != mdns.RcodeNameError {
		t.Errorf("after ready: Rcode = %d, want NXDOMAIN", w.msg.Rcode)
	}
}

func TestHandler_NxDomainHasSOA(t *testing.T) {
	// RFC 2308: a negative response should carry an SOA in the authority
	// section so downstream caches can negatively cache for a short time.
	h := newHandler(t, map[string]string{}, []string{"192.168.0.0/16"})

	w := &recWriter{}
	h.ServeDNS(w, newQuestion("99.1.168.192.in-addr.arpa.", mdns.TypePTR))

	if w.msg.Rcode != mdns.RcodeNameError {
		t.Fatalf("Rcode = %d", w.msg.Rcode)
	}
	if len(w.msg.Ns) == 0 {
		t.Fatal("NXDOMAIN response missing SOA in authority")
	}
	soa, ok := w.msg.Ns[0].(*mdns.SOA)
	if !ok {
		t.Fatalf("authority[0] = %T, want *SOA", w.msg.Ns[0])
	}
	if soa.Minttl == 0 {
		t.Error("SOA MinTTL should be > 0 for negative caching")
	}
}
