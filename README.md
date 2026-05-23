# freebox-ptr-dns

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

## Configure

Copy `config.example.toml` to `/etc/freebox-ptr-dns/config.toml` and edit
the `[freebox]` block (especially `app_id`, which should be reverse-DNS).

```bash
sudo install -d -m 0755 /etc/freebox-ptr-dns
sudo install -m 0644 config.example.toml /etc/freebox-ptr-dns/config.toml
sudo install -d -m 0700 /var/lib/freebox-ptr-dns
```

## First launch (enrollment)

Run the binary by hand once, with the Freebox in reach:

```bash
sudo ./freebox-ptr-dns -config /etc/freebox-ptr-dns/config.toml
```

You will see:

```
WARN ACTION REQUIRED
==================================================================
Approve "Freebox PTR DNS" on your Freebox front panel
(use the arrow keys + checkmark).
==================================================================
```

Approve on the front panel. The binary then writes the `app_token` to
`/var/lib/freebox-ptr-dns/app_token` (mode `0600`) and proceeds to start
the DNS server.

If the user denies the request (exit code 3) or times out, just rerun the
binary.

## Run as a service

A minimal systemd unit:

```ini
# /etc/systemd/system/freebox-ptr-dns.service
[Unit]
Description=Freebox PTR DNS
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/freebox-ptr-dns -config /etc/freebox-ptr-dns/config.toml
Restart=on-failure
RestartSec=5s

# Hardening
DynamicUser=no
User=freebox-ptr-dns
Group=freebox-ptr-dns
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/freebox-ptr-dns
PrivateTmp=true
PrivateDevices=true

[Install]
WantedBy=multi-user.target
```

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin freebox-ptr-dns
sudo chown -R freebox-ptr-dns:freebox-ptr-dns /var/lib/freebox-ptr-dns
sudo systemctl daemon-reload
sudo systemctl enable --now freebox-ptr-dns
```

## Wire it into Pi-hole

### Pi-hole v6

```toml
# /etc/pihole/pihole.toml
[dns]
revServers = [
  "true,192.168.1.0/24,<PTR_SERVER_IP>#53,lan",
  "true,fd00::/8,<PTR_SERVER_IP>#53,lan",
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
REV_SERVER_TARGET=<PTR_SERVER_IP>
REV_SERVER_DOMAIN=lan
```

The `local_domain` setting in `config.toml` must match the `REV_SERVER_DOMAIN`
on Pi-hole side (default: `lan`). The names appearing on the dashboard will
then look like `laptop-alice.lan`.

## Test

```bash
# IPv4
dig @<PTR_SERVER_IP> -x 192.168.1.42
# expected: PTR record pointing to <name>.lan., TTL 300

# IPv6
dig @<PTR_SERVER_IP> -x fd00::1

# Off-LAN: REFUSED
dig @<PTR_SERVER_IP> -x 8.8.8.8

# Unknown LAN IP: NXDOMAIN
dig @<PTR_SERVER_IP> -x 192.168.1.250
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

## Re-enrollment

To re-enroll (e.g. after rotating the app or revoking it on the Freebox):

```bash
sudo systemctl stop freebox-ptr-dns
sudo rm /var/lib/freebox-ptr-dns/app_token
sudo systemctl start freebox-ptr-dns
sudo journalctl -u freebox-ptr-dns -f
# approve on the front panel when prompted
```

## License

Personal project, no license declared yet.
