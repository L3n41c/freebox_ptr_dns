package dns

import (
	"context"
	"log/slog"
	"net/netip"
	"slices"
	"sync/atomic"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/L3n41c/freebox_ptr_dns/internal/hosts"
)

type Handler struct {
	cache   *hosts.Cache
	ttl     uint32
	allowed []netip.Prefix
	ready   atomic.Bool
}

func NewHandler(cache *hosts.Cache, ttl time.Duration, allowed []netip.Prefix) *Handler {
	return &Handler{cache: cache, ttl: uint32(ttl.Seconds()), allowed: allowed}
}

// MarkReady declares that the cache has been populated at least once. Before
// MarkReady is called, every query returns SERVFAIL so downstream resolvers
// do not negatively cache an authoritative NXDOMAIN built on empty data.
func (h *Handler) MarkReady() { h.ready.Store(true) }

func (h *Handler) ServeDNS(w mdns.ResponseWriter, r *mdns.Msg) {
	m := new(mdns.Msg)
	m.SetReply(r)
	m.Compress = true
	m.Authoritative = true

	defer func() {
		if err := w.WriteMsg(m); err != nil {
			slog.Debug("WriteMsg failed", "err", err)
		}
	}()

	if len(r.Question) == 0 {
		m.Rcode = mdns.RcodeFormatError
		return
	}
	q := r.Question[0]
	if q.Qclass != mdns.ClassINET || q.Qtype != mdns.TypePTR {
		m.Rcode = mdns.RcodeRefused
		return
	}

	addr, err := AddrFromPTR(q.Name)
	if err != nil {
		m.Rcode = mdns.RcodeFormatError
		return
	}

	if !h.allows(addr) {
		m.Rcode = mdns.RcodeRefused
		return
	}

	if !h.ready.Load() {
		m.Rcode = mdns.RcodeServerFailure
		m.Authoritative = false
		return
	}

	if name, ok := h.cache.Lookup(addr); ok {
		m.Answer = []mdns.RR{
			&mdns.PTR{
				Hdr: mdns.RR_Header{
					Name:   q.Name,
					Rrtype: mdns.TypePTR,
					Class:  mdns.ClassINET,
					Ttl:    h.ttl,
				},
				Ptr: name,
			},
		}
		return
	}

	m.Rcode = mdns.RcodeNameError
	m.Ns = []mdns.RR{negativeSOA(q.Name, h.ttl)}
}

// negativeSOA builds a SOA suitable for RFC 2308 negative caching. The owner
// is the queried zone (we lazily reuse the qname so downstream resolvers do
// not have to walk back to a real apex; this is the same trick dnsmasq uses).
func negativeSOA(qname string, ttl uint32) *mdns.SOA {
	return &mdns.SOA{
		Hdr: mdns.RR_Header{
			Name:   qname,
			Rrtype: mdns.TypeSOA,
			Class:  mdns.ClassINET,
			Ttl:    ttl,
		},
		Ns:      "freebox-ptr-dns.",
		Mbox:    "nobody.invalid.",
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  ttl,
	}
}

func (h *Handler) allows(addr netip.Addr) bool {
	if len(h.allowed) == 0 {
		return true
	}
	return slices.ContainsFunc(h.allowed, func(p netip.Prefix) bool {
		return p.Contains(addr)
	})
}

// Server bundles a UDP and TCP listener serving the same Handler.
type Server struct {
	udp *mdns.Server
	tcp *mdns.Server
}

func NewServer(addr string, h *Handler) *Server {
	mux := mdns.NewServeMux()
	mux.Handle(".", h)
	return &Server{
		udp: &mdns.Server{Addr: addr, Net: "udp", Handler: mux},
		tcp: &mdns.Server{Addr: addr, Net: "tcp", Handler: mux},
	}
}

// ListenAndServe runs both listeners and returns the first error encountered.
// Returns nil after a clean Shutdown.
func (s *Server) ListenAndServe(ctx context.Context) error {
	errs := make(chan error, 2)
	go func() { errs <- s.udp.ListenAndServe() }()
	go func() { errs <- s.tcp.ListenAndServe() }()

	select {
	case <-ctx.Done():
		s.Shutdown()
		<-errs
		<-errs
		return nil
	case err := <-errs:
		s.Shutdown()
		<-errs
		return err
	}
}

func (s *Server) Shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.udp.ShutdownContext(ctx)
	_ = s.tcp.ShutdownContext(ctx)
}
