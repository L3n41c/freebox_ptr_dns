package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Freebox Freebox `toml:"freebox"`
	DNS     DNS     `toml:"dns"`
	Poller  Poller  `toml:"poller"`
}

type Freebox struct {
	APIDomain    string `toml:"api_domain"`
	AppID        string `toml:"app_id"`
	AppName      string `toml:"app_name"`
	AppVersion   string `toml:"app_version"`
	DeviceName   string `toml:"device_name"`
	TokenPath    string `toml:"token_path"`
	InsecureHTTP bool   `toml:"insecure_http"` // opt-in: send tokens over plain HTTP
}

type DNS struct {
	Listen          string         `toml:"listen"`
	TTLSeconds      int            `toml:"ttl_seconds"`
	LocalDomain     string         `toml:"local_domain"`
	AllowedNetworks []netip.Prefix `toml:"-"`
	AllowedNetRaw   []string       `toml:"allowed_networks"`
	TTL             time.Duration  `toml:"-"`
}

type Poller struct {
	IntervalSeconds    int           `toml:"interval_seconds"`
	HTTPTimeoutSeconds int           `toml:"http_timeout_seconds"`
	Interval           time.Duration `toml:"-"`
	HTTPTimeout        time.Duration `toml:"-"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	md, err := toml.Decode(string(data), &cfg)
	if err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}

	if md.IsDefined("dns", "allowed_networks") && len(cfg.DNS.AllowedNetRaw) == 0 {
		return nil, errors.New("dns.allowed_networks must be non-empty " +
			"(omit the key to use the defaults; an empty list would disable the safety net)")
	}

	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, len(undecoded))
		for i, k := range undecoded {
			keys[i] = k.String()
		}
		return nil, fmt.Errorf("config has unknown keys: %v", keys)
	}

	applyDefaults(&cfg, md)

	if err := validate(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func applyDefaults(cfg *Config, md toml.MetaData) {
	if !md.IsDefined("freebox", "api_domain") {
		cfg.Freebox.APIDomain = "mafreebox.freebox.fr"
	}
	if !md.IsDefined("dns", "listen") {
		cfg.DNS.Listen = "0.0.0.0:53"
	}
	if !md.IsDefined("dns", "ttl_seconds") {
		cfg.DNS.TTLSeconds = 300
	}
	if !md.IsDefined("dns", "local_domain") {
		cfg.DNS.LocalDomain = "lan"
	}
	if !md.IsDefined("dns", "allowed_networks") {
		cfg.DNS.AllowedNetRaw = []string{
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
			"fc00::/7",
			"fe80::/10",
		}
	}
	if !md.IsDefined("poller", "interval_seconds") {
		cfg.Poller.IntervalSeconds = 30
	}
	if !md.IsDefined("poller", "http_timeout_seconds") {
		cfg.Poller.HTTPTimeoutSeconds = 5
	}
}

func validate(cfg *Config) error {
	if cfg.Freebox.APIDomain == "" {
		return errors.New("freebox.api_domain must be non-empty")
	}
	if cfg.Freebox.AppID == "" {
		return errors.New("freebox.app_id is required")
	}
	if cfg.Freebox.AppName == "" {
		return errors.New("freebox.app_name is required")
	}
	if cfg.Freebox.AppVersion == "" {
		return errors.New("freebox.app_version is required")
	}
	if cfg.Freebox.DeviceName == "" {
		return errors.New("freebox.device_name is required")
	}
	if cfg.Freebox.TokenPath == "" {
		return errors.New("freebox.token_path is required")
	}

	if cfg.DNS.TTLSeconds <= 0 {
		return fmt.Errorf("dns.ttl_seconds must be > 0 (got %d)", cfg.DNS.TTLSeconds)
	}
	cfg.DNS.TTL = time.Duration(cfg.DNS.TTLSeconds) * time.Second

	if _, _, err := net.SplitHostPort(cfg.DNS.Listen); err != nil {
		return fmt.Errorf("dns.listen invalid: %w", err)
	}

	if err := validateLocalDomain(cfg.DNS.LocalDomain); err != nil {
		return fmt.Errorf("dns.local_domain: %w", err)
	}

	cfg.DNS.AllowedNetworks = make([]netip.Prefix, 0, len(cfg.DNS.AllowedNetRaw))
	for _, s := range cfg.DNS.AllowedNetRaw {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return fmt.Errorf("dns.allowed_networks: invalid CIDR %q: %w", s, err)
		}
		cfg.DNS.AllowedNetworks = append(cfg.DNS.AllowedNetworks, p)
	}

	if cfg.Poller.IntervalSeconds <= 0 {
		return errors.New("poller.interval_seconds must be > 0")
	}
	if cfg.Poller.HTTPTimeoutSeconds <= 0 {
		return errors.New("poller.http_timeout_seconds must be > 0")
	}
	cfg.Poller.Interval = time.Duration(cfg.Poller.IntervalSeconds) * time.Second
	cfg.Poller.HTTPTimeout = time.Duration(cfg.Poller.HTTPTimeoutSeconds) * time.Second

	return nil
}

// validateLocalDomain checks that the suffix is a syntactically reasonable
// DNS name. Empty is allowed (no suffix). Trailing dots, embedded spaces and
// labels > 63 bytes are rejected — those produce malformed PTR RDATA.
func validateLocalDomain(d string) error {
	if d == "" {
		return nil
	}
	if strings.HasSuffix(d, ".") {
		return fmt.Errorf("must not end with a dot: %q", d)
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" {
			return fmt.Errorf("empty label in %q", d)
		}
		if len(label) > 63 {
			return fmt.Errorf("label %q exceeds 63 bytes", label)
		}
		for _, r := range label {
			ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
				(r >= '0' && r <= '9') || r == '-'
			if !ok {
				return fmt.Errorf("invalid character %q in label %q", r, label)
			}
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("label %q must not start or end with '-'", label)
		}
	}
	return nil
}
