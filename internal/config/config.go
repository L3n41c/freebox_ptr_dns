// Copyright 2026 Lénaïc Huard
//
// Licensed under the MIT License, see LICENSE for details

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

// LocalDomain is a local DNS domain for PTR record suffixes.
type LocalDomain string

// String implements fmt.Stringer to provide a string representation.
func (d LocalDomain) String() string {
	return string(d)
}

// UnmarshalText implements encoding.TextUnmarshaler to validate the domain.
func (d *LocalDomain) UnmarshalText(text []byte) error {
	*d = LocalDomain(text)
	return validateLocalDomain(string(*d))
}

type DNS struct {
	Listen          string         `toml:"listen"`
	TTL             time.Duration  `toml:"ttl"`
	LocalDomain     LocalDomain    `toml:"local_domain"`
	AllowedNetworks []netip.Prefix `toml:"allowed_networks"`
}

type Poller struct {
	Interval    time.Duration `toml:"interval"`
	HTTPTimeout time.Duration `toml:"http_timeout"`
}

func Load(path string) (*Config, error) {
	// 1. Create a config with all default values
	cfg := &Config{
		Freebox: Freebox{
			APIDomain: "mafreebox.freebox.fr",
		},
		DNS: DNS{
			Listen:      "0.0.0.0:53",
			TTL:         5 * time.Minute,
			LocalDomain: LocalDomain("lan"),
			AllowedNetworks: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/8"),
				netip.MustParsePrefix("172.16.0.0/12"),
				netip.MustParsePrefix("192.168.0.0/16"),
				netip.MustParsePrefix("fc00::/7"),
				netip.MustParsePrefix("fe80::/10"),
			},
		},
		Poller: Poller{
			Interval:    30 * time.Second,
			HTTPTimeout: 5 * time.Second,
		},
	}

	// 2. Read the config file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	// 3. Decode the file.
	// BurntSushi/toml will:
	// - Overwrite fields present in the file
	// - Keep default values for missing fields
	// - Automatically handle time.Duration and []netip.Prefix via UnmarshalText
	md, err := toml.Decode(string(data), cfg)
	if err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}

	// 4. Check for unknown keys
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, len(undecoded))
		for i, k := range undecoded {
			keys[i] = k.String()
		}
		return nil, fmt.Errorf("config has unknown keys: %v", keys)
	}

	// 5. Validate required fields and constraints
	if err := validate(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

func validate(cfg *Config) error {
	// Validate Freebox (all fields required)
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

	// Validate DNS
	if cfg.DNS.TTL < time.Second {
		return errors.New("dns.ttl must be >= 1s")
	}
	if cfg.DNS.TTL%time.Second != 0 {
		return errors.New("dns.ttl must be a whole number of seconds")
	}
	if cfg.DNS.TTL > time.Duration(^uint32(0))*time.Second {
		return errors.New("dns.ttl must fit in a uint32 number of seconds")
	}

	if _, _, err := net.SplitHostPort(cfg.DNS.Listen); err != nil {
		return fmt.Errorf("dns.listen invalid: %w", err)
	}
	if err := validateLocalDomain(string(cfg.DNS.LocalDomain)); err != nil {
		return fmt.Errorf("dns.local_domain invalid: %w", err)
	}

	// Ensure AllowedNetworks is not empty (omit the key to use defaults;
	// an empty list would disable the safety net)
	if len(cfg.DNS.AllowedNetworks) == 0 {
		return errors.New("dns.allowed_networks must be non-empty " +
			"(omit the key to use the defaults; an empty list would disable the safety net)")
	}

	// Validate Poller
	if cfg.Poller.Interval <= 0 {
		return errors.New("poller.interval must be > 0")
	}
	if cfg.Poller.HTTPTimeout <= 0 {
		return errors.New("poller.http_timeout must be > 0")
	}

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
