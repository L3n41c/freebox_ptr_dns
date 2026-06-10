# freebox-ptr-dns

Copyright (c) 2026 Lénaïc Huard

Licensed under the [MIT License](LICENSE).

![CI](https://github.com/L3n41c/freebox_ptr_dns/actions/workflows/ci.yml/badge.svg)
![Lint](https://github.com/L3n41c/freebox_ptr_dns/actions/workflows/lint.yml/badge.svg)
![CodeQL](https://github.com/L3n41c/freebox_ptr_dns/actions/workflows/codeql.yml/badge.svg)
![Release](https://github.com/L3n41c/freebox_ptr_dns/actions/workflows/release.yml/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/L3n41c/freebox_ptr_dns)](https://goreportcard.com/report/github.com/L3n41c/freebox_ptr_dns)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A tiny DNS server that answers PTR queries for the local network by asking
the Freebox API. Designed to plug into Pi-hole's `rev-server` so the Pi-hole
dashboard shows device names instead of IPs and MAC addresses.

## The problem

On a home network where:

- the **Freebox** acts as the DHCP server,
- **Pi-hole** acts as the DNS server,

the Pi-hole dashboard ("Top clients", client list) shows raw IPs and MACs
because Pi-hole can only learn names through reverse DNS (PTR) — and the
Freebox does not answer PTR queries for the IPs it hands out.

Pi-hole's "Local DNS Records" only affect forward lookups (A/AAAA) and do
**not** populate the dashboard. The only fix is a PTR-capable resolver for
the LAN, which this project provides.

## How it works

```
   Pi-hole FTL ── PTR query ──▶ freebox-ptr-dns ── HTTPS ──▶ Freebox API
                                       │  (/api/v4/lan/browser/…)
                                       ▼
                          in-memory cache (IP → name),
                          refreshed every 30 s
```

- One Go binary, statically linked, ~12-15 MB, ~10-20 MB RSS at runtime.
- Single binary handles the initial enrollment too — no separate registration
  tool. On first launch it walks the Freebox authorization flow, prompts you
  to approve on the front panel, then persists the long-lived `app_token`
  in `0600` mode.
- Session tokens are renewed automatically (20 min cadence + reactive on
  `auth_required`).
- PTR answers are returned with a short TTL (default 300 s). The DHCP lease
  duration is intentionally ignored — see the rationale below.

## Build

```bash
make             # native build
make build-arm64 # Raspberry Pi 4/5 (64-bit)
make build-armv7 # Raspberry Pi 2/3 (32-bit)
make dist        # all three above into ./dist/
```

The output is a static binary built with `CGO_ENABLED=0`, stripped via
`-ldflags="-s -w"`.

## Installation

Packages are available for Debian/Ubuntu (.deb), RHEL/Fedora (.rpm), and Arch Linux from the [releases page](https://github.com/L3n41c/freebox_ptr_dns/releases).
All packages include the binary, default configuration, and systemd service file.
The DNS server listens on `[::1]:1053` by default to avoid conflicts with existing DNS servers (e.g., Pi-hole which binds port 53 on all interfaces).

### Download the Public GPG Key

First, download and import the signing key:

```bash
curl -sSfL https://github.com/L3n41c/freebox_ptr_dns/releases/latest/download/freebox-ptr-dns.asc | gpg --import -
```

### Debian / Ubuntu (.deb)

```bash
# Download the package (replace VERSION and ARCH with actual values)
wget https://github.com/L3n41c/freebox_ptr_dns/releases/latest/download/freebox-ptr-dns-VERSION-linux-ARCH.deb

# Verify GPG signature
gpg --verify freebox-ptr-dns-VERSION-linux-ARCH.deb.asc freebox-ptr-dns-VERSION-linux-ARCH.deb

# Verify GitHub attestation
gh attestation verify --owner L3n41c freebox-ptr-dns-VERSION-linux-ARCH.deb

# Install the package
sudo dpkg -i freebox-ptr-dns-VERSION-linux-ARCH.deb
```

### RHEL / Fedora / CentOS (.rpm)

```bash
# Download the package (replace VERSION and ARCH with actual values)
wget https://github.com/L3n41c/freebox_ptr_dns/releases/latest/download/freebox-ptr-dns-VERSION-linux-ARCH.rpm

# Verify GPG signature
gpg --verify freebox-ptr-dns-VERSION-linux-ARCH.rpm.asc freebox-ptr-dns-VERSION-linux-ARCH.rpm

# Verify GitHub attestation
gh attestation verify --owner L3n41c freebox-ptr-dns-VERSION-linux-ARCH.rpm

# Install the package
sudo rpm -ivh freebox-ptr-dns-VERSION-linux-ARCH.rpm
```

### Arch Linux (archlinux)

```bash
# Download the package (replace VERSION and ARCH with actual values)
wget https://github.com/L3n41c/freebox_ptr_dns/releases/latest/download/freebox-ptr-dns-VERSION-linux-ARCH.pkg.tar.zst

# Verify GPG signature
gpg --verify freebox-ptr-dns-VERSION-linux-ARCH.pkg.tar.zst.asc freebox-ptr-dns-VERSION-linux-ARCH.pkg.tar.zst

# Verify GitHub attestation
gh attestation verify --owner L3n41c freebox-ptr-dns-VERSION-linux-ARCH.pkg.tar.zst

# Install the package
sudo pacman -U freebox-ptr-dns-VERSION-linux-ARCH.pkg.tar.zst
```

### After Installation (All Distributions)

The package installs:
- Binary: `/usr/bin/freebox-ptr-dns`
- Configuration: `/etc/freebox-ptr-dns.toml`
- Systemd service: `/usr/lib/systemd/system/freebox-ptr-dns.service`

Start and enable the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now freebox-ptr-dns
```

Check the service status:

```bash
sudo systemctl status freebox-ptr-dns
sudo journalctl -u freebox-ptr-dns -f
```

**First launch requires Freebox approval:** On first start, the service will prompt you to approve the application on your Freebox front panel (use the arrow keys + checkmark). Once approved, the service will start automatically.

To verify security settings:

```bash
systemd-analyze security freebox-ptr-dns
```

**Note:** The service requires systemd >= 245 for `StateDirectory` and `ProtectProc=invisible` support.

## Wire it into Pi-hole

By default, the service listens on `[::1]:1053`. Configure Pi-hole to use this address and port.

### Pi-hole v6

```toml
# /etc/pihole/pihole.toml
[dns]
revServers = [
  "true,192.168.1.0/24,::1#1053,lan",
  "true,fd00::/8,::1#1053,lan",
]
```

Restart FTL:

```bash
sudo systemctl restart pihole-FTL
```

### Pi-hole v5

```
REV_SERVER=true
REV_SERVER_CIDR=192.168.1.0/24
REV_SERVER_TARGET=::1
REV_SERVER_DOMAIN=lan
REV_SERVER_PORT=1053
```

The `local_domain` setting in `/etc/freebox-ptr-dns.toml` must match the
`REV_SERVER_DOMAIN` on Pi-hole side (default: `lan`). The names appearing on
the dashboard will then look like `laptop-alice.lan`.

## Test

```bash
# IPv4
dig @::1 -p 1053 -x 192.168.1.42
# expected: PTR record pointing to <name>.lan., TTL 300

# IPv6
dig @::1 -p 1053 -x fd00::1

# Off-LAN: REFUSED
dig @::1 -p 1053 -x 8.8.8.8

# Unknown LAN IP: NXDOMAIN
dig @::1 -p 1053 -x 192.168.1.250
```

## TTL rationale

The Freebox's DHCP lease is fixed at 12 h and not configurable through the
API. One might be tempted to align PTR TTLs with the lease duration, but:

- Pi-hole FTL only resolves a client's name on **first contact**, then caches
  it forever in its own database. Long PTR TTLs do not save round-trips that
  weren't going to happen anyway.
- A 12 h TTL means a downstream resolver could serve the wrong name for 12
  hours if a device reuses an IP. With 300 s TTL we converge quickly while
  still amortizing the work.

## License

Licensed under the [MIT License](LICENSE).
