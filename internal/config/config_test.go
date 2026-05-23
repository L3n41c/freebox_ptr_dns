package config

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

func TestLoad_FullConfig(t *testing.T) {
	p := writeConfig(t, `
[freebox]
api_domain   = "mafreebox.freebox.fr"
app_id       = "fr.test.app"
app_name     = "Test App"
app_version  = "1.2"
device_name  = "test-host"
token_path   = "/var/lib/test/token"

[dns]
listen           = "127.0.0.1:5353"
ttl_seconds      = 600
local_domain     = "home"
allowed_networks = ["192.168.0.0/16", "fd00::/8"]

[poller]
interval_seconds     = 45
http_timeout_seconds = 10
`)

	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Freebox.APIDomain != "mafreebox.freebox.fr" {
		t.Errorf("APIDomain = %q", cfg.Freebox.APIDomain)
	}
	if cfg.Freebox.AppID != "fr.test.app" {
		t.Errorf("AppID = %q", cfg.Freebox.AppID)
	}
	if cfg.Freebox.AppName != "Test App" {
		t.Errorf("AppName = %q", cfg.Freebox.AppName)
	}
	if cfg.Freebox.AppVersion != "1.2" {
		t.Errorf("AppVersion = %q", cfg.Freebox.AppVersion)
	}
	if cfg.Freebox.DeviceName != "test-host" {
		t.Errorf("DeviceName = %q", cfg.Freebox.DeviceName)
	}
	if cfg.Freebox.TokenPath != "/var/lib/test/token" {
		t.Errorf("TokenPath = %q", cfg.Freebox.TokenPath)
	}
	if cfg.DNS.Listen != "127.0.0.1:5353" {
		t.Errorf("Listen = %q", cfg.DNS.Listen)
	}
	if cfg.DNS.TTL != 600*time.Second {
		t.Errorf("TTL = %v", cfg.DNS.TTL)
	}
	if cfg.DNS.LocalDomain != "home" {
		t.Errorf("LocalDomain = %q", cfg.DNS.LocalDomain)
	}
	if len(cfg.DNS.AllowedNetworks) != 2 {
		t.Fatalf("AllowedNetworks len = %d", len(cfg.DNS.AllowedNetworks))
	}
	if cfg.DNS.AllowedNetworks[0] != netip.MustParsePrefix("192.168.0.0/16") {
		t.Errorf("AllowedNetworks[0] = %v", cfg.DNS.AllowedNetworks[0])
	}
	if cfg.DNS.AllowedNetworks[1] != netip.MustParsePrefix("fd00::/8") {
		t.Errorf("AllowedNetworks[1] = %v", cfg.DNS.AllowedNetworks[1])
	}
	if cfg.Poller.Interval != 45*time.Second {
		t.Errorf("Interval = %v", cfg.Poller.Interval)
	}
	if cfg.Poller.HTTPTimeout != 10*time.Second {
		t.Errorf("HTTPTimeout = %v", cfg.Poller.HTTPTimeout)
	}
}

func TestLoad_AppliesDefaults(t *testing.T) {
	p := writeConfig(t, `
[freebox]
app_id      = "fr.test.app"
app_name    = "Test App"
app_version = "1.0"
device_name = "host"
token_path  = "/tmp/token"
`)

	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Freebox.APIDomain != "mafreebox.freebox.fr" {
		t.Errorf("default APIDomain = %q", cfg.Freebox.APIDomain)
	}
	if cfg.DNS.Listen != "0.0.0.0:53" {
		t.Errorf("default Listen = %q", cfg.DNS.Listen)
	}
	if cfg.DNS.TTL != 300*time.Second {
		t.Errorf("default TTL = %v", cfg.DNS.TTL)
	}
	if cfg.DNS.LocalDomain != "lan" {
		t.Errorf("default LocalDomain = %q", cfg.DNS.LocalDomain)
	}
	if cfg.Poller.Interval != 30*time.Second {
		t.Errorf("default Interval = %v", cfg.Poller.Interval)
	}
	if cfg.Poller.HTTPTimeout != 5*time.Second {
		t.Errorf("default HTTPTimeout = %v", cfg.Poller.HTTPTimeout)
	}
}

func TestLoad_RejectsUnknownKeys(t *testing.T) {
	p := writeConfig(t, `
[freebox]
app_id      = "x"
app_name    = "x"
app_version = "1"
device_name = "x"
token_path  = "/tmp/t"
unknown_key = "oops"
`)
	_, err := Load(p)
	if err == nil {
		t.Fatal("expected error for unknown key")
	}
	if !strings.Contains(err.Error(), "unknown_key") {
		t.Errorf("error should mention unknown_key: %v", err)
	}
}

func TestLoad_RejectsInvalidCIDR(t *testing.T) {
	p := writeConfig(t, `
[freebox]
app_id      = "x"
app_name    = "x"
app_version = "1"
device_name = "x"
token_path  = "/tmp/t"

[dns]
allowed_networks = ["not-a-cidr"]
`)
	_, err := Load(p)
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
	if !strings.Contains(err.Error(), "allowed_networks") {
		t.Errorf("error should mention allowed_networks: %v", err)
	}
}

func TestLoad_RejectsMissingRequired(t *testing.T) {
	cases := []struct {
		name    string
		content string
		missing string
	}{
		{"app_id", `[freebox]
app_name="x"
app_version="1"
device_name="x"
token_path="/tmp/t"`, "app_id"},
		{"app_name", `[freebox]
app_id="x"
app_version="1"
device_name="x"
token_path="/tmp/t"`, "app_name"},
		{"token_path", `[freebox]
app_id="x"
app_name="x"
app_version="1"
device_name="x"`, "token_path"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := writeConfig(t, tc.content)
			_, err := Load(p)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.missing) {
				t.Errorf("error should mention %s: %v", tc.missing, err)
			}
		})
	}
}

func TestLoad_RejectsZeroDurations(t *testing.T) {
	p := writeConfig(t, `
[freebox]
app_id="x"
app_name="x"
app_version="1"
device_name="x"
token_path="/tmp/t"

[dns]
ttl_seconds = 0
`)
	_, err := Load(p)
	if err == nil {
		t.Fatal("expected error for ttl_seconds = 0")
	}
	if !strings.Contains(err.Error(), "ttl_seconds") {
		t.Errorf("error should mention ttl_seconds: %v", err)
	}
}

func TestLoad_RejectsBadListen(t *testing.T) {
	p := writeConfig(t, `
[freebox]
app_id="x"
app_name="x"
app_version="1"
device_name="x"
token_path="/tmp/t"

[dns]
listen = "no-port-here"
`)
	_, err := Load(p)
	if err == nil {
		t.Fatal("expected error for bad listen")
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/path/config.toml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoad_ExplicitEmptyLocalDomainHonored(t *testing.T) {
	p := writeConfig(t, `
[freebox]
app_id="x"
app_name="x"
app_version="1"
device_name="x"
token_path="/tmp/t"

[dns]
local_domain = ""
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DNS.LocalDomain != "" {
		t.Errorf("LocalDomain = %q, want empty (user opted out)", cfg.DNS.LocalDomain)
	}
}

func TestLoad_RejectsEmptyAPIDomain(t *testing.T) {
	p := writeConfig(t, `
[freebox]
api_domain = ""
app_id="x"
app_name="x"
app_version="1"
device_name="x"
token_path="/tmp/t"
`)
	_, err := Load(p)
	if err == nil {
		t.Fatal("expected error for empty api_domain")
	}
	if !strings.Contains(err.Error(), "api_domain") {
		t.Errorf("error should mention api_domain: %v", err)
	}
}

func TestLoad_RejectsEmptyAllowedNetworks(t *testing.T) {
	p := writeConfig(t, `
[freebox]
app_id="x"
app_name="x"
app_version="1"
device_name="x"
token_path="/tmp/t"

[dns]
allowed_networks = []
`)
	_, err := Load(p)
	if err == nil {
		t.Fatal("expected error for explicit empty allowed_networks")
	}
	if !strings.Contains(err.Error(), "allowed_networks") {
		t.Errorf("error should mention allowed_networks: %v", err)
	}
}

func TestLoad_LocalDomainValidation(t *testing.T) {
	header := `[freebox]
app_id="x"
app_name="x"
app_version="1"
device_name="x"
token_path="/tmp/t"

[dns]
`
	cases := []struct {
		name    string
		domain  string
		wantErr bool
	}{
		{"empty allowed", `""`, false},
		{"simple", `"lan"`, false},
		{"two labels", `"home.lan"`, false},
		{"trailing dot", `"lan."`, true},
		{"space", `"home lan"`, true},
		{"leading dash", `"-lan"`, true},
		{"empty label", `"home..lan"`, true},
		{"unicode", `"café"`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := writeConfig(t, header+`local_domain = `+tc.domain)
			_, err := Load(p)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error for domain=%s", tc.domain)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error for domain=%s: %v", tc.domain, err)
			}
		})
	}
}
