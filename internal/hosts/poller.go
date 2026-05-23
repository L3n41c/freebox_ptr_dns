package hosts

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"github.com/L3n41c/freebox_ptr_dns/internal/freebox"
)

// API is the slice of the Freebox client used by the poller. Defined here so
// the poller can be tested with a stub.
type API interface {
	ListInterfaces(ctx context.Context) ([]freebox.LanInterface, error)
	ListHosts(ctx context.Context, iface string) ([]freebox.LanHost, error)
}

type Poller struct {
	api         API
	cache       *Cache
	localDomain string
	interval    time.Duration

	// OnRefreshSuccess is invoked after every successful refresh (idempotent).
	// Set by the caller to e.g. mark the DNS handler ready.
	OnRefreshSuccess func()
}

func NewPoller(api API, cache *Cache, localDomain string, interval time.Duration) *Poller {
	return &Poller{
		api:         api,
		cache:       cache,
		localDomain: localDomain,
		interval:    interval,
	}
}

// Refresh fetches the host list once and atomically swaps the cache.
// Returns the underlying error without touching the cache on failure.
func (p *Poller) Refresh(ctx context.Context) error {
	ifaces, err := p.api.ListInterfaces(ctx)
	if err != nil {
		return fmt.Errorf("list interfaces: %w", err)
	}
	out := make(map[netip.Addr]string)
	for _, iface := range ifaces {
		hosts, err := p.api.ListHosts(ctx, iface.Name)
		if err != nil {
			return fmt.Errorf("list hosts on %s: %w", iface.Name, err)
		}
		for _, h := range hosts {
			label := sanitizeLabel(h.PrimaryName)
			if label == "" {
				continue
			}
			fqdn := buildFQDN(label, p.localDomain)
			for _, l3 := range h.L3Connectivities {
				addr, err := netip.ParseAddr(l3.Addr)
				if err != nil {
					continue
				}
				out[addr] = fqdn
			}
		}
	}
	p.cache.Replace(out)
	return nil
}

// Run loops over Refresh at the configured interval. Returns nil when ctx is
// done, or a non-nil error for fatal conditions (e.g. revoked app_token) that
// require the daemon to exit. Transient API errors are logged with backoff;
// the previous cache is preserved.
func (p *Poller) Run(ctx context.Context) error {
	const maxBackoff = 5 * time.Minute
	backoff := p.interval

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		err := p.Refresh(ctx)
		if err == nil {
			slog.Info("hosts refreshed", "n", p.cache.Len())
			if p.OnRefreshSuccess != nil {
				p.OnRefreshSuccess()
			}
			backoff = p.interval
			continue
		}
		if errors.Is(err, freebox.ErrInvalidAppToken) {
			return err
		}
		slog.Warn("refresh failed", "err", err, "backoff", backoff)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// sanitizeLabel turns a free-form device name into something safe for a single
// DNS label: lowercased, ASCII-only, non-alphanumerics → '-', trimmed,
// and capped at 63 octets per RFC 1035.
func sanitizeLabel(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	for _, r := range strings.TrimSpace(name) {
		switch {
		case r >= 'A' && r <= 'Z':
			b.WriteByte(byte(r) + ('a' - 'A'))
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteByte(byte(r))
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 63 {
		out = out[:63]
	}
	return out
}

func buildFQDN(label, domain string) string {
	if domain == "" {
		return label + "."
	}
	return label + "." + domain + "."
}
