# TipOff

**Self-hosted security monitoring for small businesses.**

TipOff runs as a Docker container on your network and continuously monitors your:

- **External domains** — SSL certificates, SPF, DMARC, DKIM, security headers, HTTPS redirect, domain expiry. Auto-detects whether a domain runs a website, so a mail-only or admin-only domain doesn't get checked for one it doesn't have; subdomains skip the registrar-expiry check that only applies to the registrable domain. Score each domain 0–60 and acknowledge known issues with notes.
- **LAN hosts** — auto-discovery via nmap/ARP, open port risk analysis, vendor/OS detection, automatic VM detection, IPv6 neighbour discovery, host tagging, near-realtime connectivity checks (TCP every 5 minutes), Wake-on-LAN, freeform notes, acknowledge/mitigate workflow
- **Network map** — interactive topology view of your whole network: gateway, infrastructure tier, and local devices grouped by subnet, plus automatic detection of routed/VPN-connected remote subnets (with peer inference and a "likely VPN/WAN" latency hint) and IPv6 segments
- **Upcoming events** — a single view of every domain's registration and SSL certificate expiry, soonest first, so renewals get handled before they turn into a critical alert
- **Uptime monitors** — TCP, HTTP/HTTPS, and ICMP ping service monitors with response time history and up/down tracking
- **WordPress scanning** — detect WordPress installations on domains and LAN hosts, check plugins and themes against the WPScan vulnerability database (API key required)
- **Email breaches** — staff email addresses checked against Have I Been Pwned, password breach checker included
- **Cyber Essentials readiness** — guided questionnaire across all 5 CE control areas, auto-populated from scan evidence
- **Webhook notifications** — instant alerts to Discord, Slack, ntfy, or Matrix when monitors go down, hosts go offline, or new issues are found

All checks, data, and reports stay on your own infrastructure — nothing is sent to external services except the checks themselves.

---

## Requirements

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (Windows/Mac) or Docker Engine (Linux)
- [Docker Compose](https://docs.docker.com/compose/install/) (included with Docker Desktop)
- Linux host required for LAN discovery — see [Windows / Mac](#windows--mac) below

---

## Quick Start

### Linux

**Option A — Docker Hub (recommended):**
```bash
# Pull the image
docker pull meatlotion/tipoff:latest

# Grab docker-compose.yml from this repo, edit credentials, then:
docker compose up -d
```

**Option B — Build from source:**
```bash
git clone https://github.com/christiansacks/tipoff.git
cd tipoff

# Edit docker-compose.yml and change TIPOFF_USERNAME / TIPOFF_PASSWORD
# then:
docker compose up -d
```

Open [http://localhost:8080](http://localhost:8080) and log in.

### Windows / Mac

All features work except **LAN host discovery**, which requires Linux kernel networking (`network_mode: host`). Domain checks, breach monitoring, Cyber Essentials, and reports all work normally.

Install [Docker Desktop](https://www.docker.com/products/docker-desktop/), then:

```bash
git clone https://github.com/christiansacks/tipoff.git
cd tipoff

# Edit docker-compose.yml and change TIPOFF_USERNAME / TIPOFF_PASSWORD
# then use the Windows override:
docker compose -f docker-compose.yml -f docker-compose.windows.yml up -d
```

Open [http://localhost:8080](http://localhost:8080) and log in.

> **LAN discovery on Windows:** If you need LAN scanning on a Windows network, the recommended approach is to run TipOff on a small always-on Linux machine (a Raspberry Pi works well) on the same network.

The first-run wizard will walk you through adding your first domain and discovering LAN hosts.

---

## Configuration

All settings can be changed at runtime via the **Settings** page. The following environment variables are available in `docker-compose.yml`:

| Variable | Default | Description |
|---|---|---|
| `TIPOFF_USERNAME` | `admin` | Dashboard login username |
| `TIPOFF_PASSWORD` | `admin` | Dashboard login password — **change this** |
| `HTTPS` | *(unset)* | Set to `true` to enable HTTPS on port 8443 |

### Changing the port

By default TipOff runs on port 8080. To use a different port, create a `docker-compose.override.yml` alongside your `docker-compose.yml`:

```yaml
services:
  tipoff:
    entrypoint: []
    command: uvicorn main:app --host 0.0.0.0 --port 9090
```

Replace `9090` with any port you like. Docker Compose picks up the override file automatically — no flags needed. This file is gitignored so it stays local to your machine.

### HTTPS

Uncomment `HTTPS=true` in `docker-compose.yml`. TipOff will generate a self-signed certificate on first start and serve on port 8443.

For a proper certificate, mount your cert/key into `/data/cert.pem` and `/data/key.pem`.

### DNS servers

By default, domain checks (SPF, DMARC, DKIM, etc.) use Cloudflare (1.1.1.1) and Google (8.8.8.8) rather than the container's system resolver. This avoids false results on networks with VPN or split-DNS configurations.

You can customise the DNS servers used under **Settings → DNS Servers**.

---

## Domain Monitoring

TipOff auto-detects what a domain actually needs checking for, rather than assuming every domain runs a website and sends mail:

- **Website capability** is detected by probing ports 443/80 when the domain is added. If it's off, uptime becomes a DNS-resolves check instead of a false "down" for a mail-only or admin-only domain, and SSL/security-header checks are skipped.
- **Mail security** (SPF/DMARC/DKIM) checks for MX records first. A domain with no MX gets a low-priority housekeeping note instead of a critical alert — the fix is still to publish a null SPF/DMARC record so spammers can't spoof it, just not urgent.
- **Subdomains** are detected automatically when you're also monitoring their parent domain, and skip WHOIS expiry entirely — only the registrable domain has a real registration date. Mail-security checks still run on subdomains, though: a name having no MX record only means it doesn't *receive* mail here, not that it can't *send* mail (a send-only transactional subdomain is a common setup with SPF but no MX), so SPF/DMARC stay checked either way rather than risk a false sense of coverage.
- Both capability flags can be overridden per domain if auto-detection gets it wrong.

**Manual expiry override:** some registries (Australian `.au` domains, for one) don't publish an expiry date via WHOIS at all. When that happens, the domain page lets you enter the date yourself — the same day-count warnings apply afterwards, clearly labelled as manually entered.

---

## LAN Discovery & Host Monitoring

TipOff uses `nmap` + ARP to discover hosts on your network.

Enter one or more CIDR ranges (comma-separated) in the dashboard, e.g. `192.168.1.0/24, 10.0.0.0/24`. Scheduled auto-scans can be configured under **Settings → LAN Scan Schedule**. Ranges are validated before scanning — IPv4 only, capped at `/16` — so a mistyped range fails fast with a clear message instead of exhausting memory on a sweep that was never going to finish.

Once hosts are discovered, TipOff TCP-checks every open port every 5 minutes, giving you a near-realtime view of which hosts and ports are online. If a host or port goes unreachable, you can receive an instant webhook alert (see below).

**Host detail page:** every discovered host has its own page with open ports (clickable if a web service is detected), a network-distance readout (hop count and TTL, so you can tell a local device from one reached over a VPN or router hop), a **Wake-on-LAN** button for hosts with a MAC address on your local segment, quick "add monitor" shortcuts pre-filled from the host's IP and open ports, and a freeform notes field.

Hosts with risky open ports (Telnet, SMB, RDP etc.) are flagged with a risk level and remediation advice. You can acknowledge flagged hosts with a note to remove them from the active alert count.

**VM detection:** TipOff identifies virtual machines from known hypervisor MAC OUI prefixes (VMware, VirtualBox, Hyper-V, Parallels, QEMU, Xen) — tagged with a `VM` badge. Hosts whose MAC has the locally-administered bit set but no matching hypervisor OUI get a separate `Randomized MAC` badge instead of being assumed to be a VM: that bit only means "not a manufacturer-assigned address", which is equally true of a real phone or laptop using MAC privacy randomization (the default on modern iOS, macOS, and Android) as it is of a Proxmox/QEMU VM. Calling every locally-administered address a VM would misidentify perfectly ordinary devices.

**IPv6 discovery:** After each LAN scan, TipOff probes each interface's IPv6 all-nodes multicast address across several rounds a few seconds apart (a single probe misses anything that doesn't answer instantly) and records what responds. The IPv6 default router is also picked up directly from the kernel's Router Advertisement–learned route, no separate probing needed since it's almost always the same device as the IPv4 gateway.

A plain multicast probe only reliably elicits a neighbour's *link-local* address — its global SLAAC address only shows up if some other, unrelated traffic happened to touch it first, which is inconsistent. So TipOff also reads the on-link global/ULA prefix advertised via Router Advertisement and, for any local host with a known MAC, computes the SLAAC address standard EUI-64 addressing would assign it — then confirms it with a real ping before trusting it (a device using IPv6 privacy addressing simply won't answer at that address, which is exactly the point of checking rather than assuming).

Hosts with IPv6 show their address directly on the Network Map — compressed to just the host portion once the /64 prefix is already shown by the segment header — and, when a host has more than one address, the classic MAC-derived EUI-64/SLAAC form is tagged as such and shown as secondary, since it's usually the address a human didn't choose.

Each part of the map defaults to showing its own natural address family as the bold line: the regular device tiers show IPv4 first, the IPv6 segments section shows IPv6 first. A "Show other address" toggle answers the cross-reference question in both places at once — what's this IPv4 host's IPv6 address, and what's this IPv6 host's IPv4 address — rather than forcing one family everywhere. A separate "IPv6 segment on top" toggle (persisted, like everything else on the map) moves the IPv6 segments section to the top of the page, for anyone working IPv6-first day to day.

**Host tagging:** Add your own freeform tags to any host — `production`, `dmz`, `printer`, whatever makes sense for your network. The dashboard includes a tag filter bar so you can quickly isolate a group of hosts.

**Finding a host:** Both the dashboard and the Network Map have a search box — find a host instantly by name, IP, or MAC address, without needing to scroll or remember which subnet it's in. On the dashboard it combines with the tag filter (a host has to match both to show).

> **Linux only:** LAN discovery requires `network_mode: host`, `NET_RAW`, and `NET_ADMIN` capabilities, which are pre-configured in `docker-compose.yml`. These are needed for raw socket ARP scanning.

---

## Network Map

The **Network Map** (`/topology`) gives you an at-a-glance visual of your network topology, drawn as a family tree with your gateway at the head:

- **Default gateway** at the top, with your **local network** dropping straight down from it
- **Infrastructure tier** — routers, switches, APs and similar devices auto-classified by vendor and hostname
- **Devices** — everything else, with VM, v6, and user tags shown inline

Three toggle modes for the local devices tier, remembered in your browser:
- **By /24** — devices split into columns by /24 subnet (useful for seeing your `.0.x`, `.1.x`, `.10.x` ranges at a glance)
- **By network** — devices grouped by the CIDR block you entered in discovery settings. If a host falls outside every configured range but shares a /24 with one, TipOff works out the actual complementary block (e.g. a configured `10.1.3.0/25` puts uncovered addresses under `10.1.3.128/25`, not a misleading full `/24`)
- **Flat** — all devices in one pool

**Routed and VPN-connected subnets** hang off the gateway's side as a dashed branch, separate from the local tree. TipOff infers this from traceroute hop counts and TTL — a host reached through your gateway with more hops than your local devices is a routed subnet, not a local one. Where one host in that subnet sits exactly one hop closer than the rest, it's promoted as the subnet's gateway/peer with the others shown underneath. A **"likely VPN/WAN"** chip appears when that subnet answers noticeably slower than your local LAN (a tunnel or WAN link, rather than a second local segment or VLAN).

**Dual-reachable flag:** if the same subnet shows up both as directly-attached local devices *and* as a routed subnet, the map flags it — that usually means a host is bridging two segments (a second NIC, or acting as a router). Harmless on a homelab, worth a look on a network that expects proper segmentation.

**IPv6 segments** discovered via NDP are drawn as their own section, grouped by /64 prefix (link-local addresses excluded, since every host has one and it isn't a real segment), sorted by the actual IPv6 address rather than inheriting IPv4 order. It gets its own Internet → Gateway → Local network tree, same skeleton as the IPv4 side, when a router's IPv6 address is known — not just a flat list of pills. Cards in this section are wider than the standard IPv4 ones, with room for a full compressed address instead of relying on a hover tooltip to see the last couple of truncated characters.

The network map is also included in PDF reports (Pro).

---

## Upcoming Events

The **Events** page (`/events`) lists every domain's registration and SSL certificate expiry across your whole install, soonest first — including any manually entered expiry dates. It's the answer to "I found out my domain expired when a customer emailed me": renewals show up here weeks in advance instead of as a surprise critical alert.

---

## Subnet Calculator

The **Subnet Calculator** (`/tools/subnet-calculator`) is a standalone IPv4/IPv6 calculator — paste in a CIDR (or just an address, defaulting to /24 or /64) and get the network address, host range, address count, and for IPv6, how many /64 subnets a larger block breaks down into. Runs entirely client-side, no scan data involved.

---

## Uptime Monitors

Add TCP, HTTP/HTTPS, or ICMP ping monitors under the **Monitors** page — ICMP is useful for portless devices like switches or printers that don't run any TCP service to check. TipOff checks them every 5 minutes, records response times, and tracks up/down history. Webhook alerts fire when a monitor transitions from up to down or back.

---

## WordPress Scanning

TipOff detects WordPress installations on both domains and LAN hosts. With a [WPScan API key](https://wpscan.com/api) configured under **Settings → WPScan**, it checks every detected plugin, theme, and WordPress core version against the WPScan vulnerability database and reports CVEs with CVSS scores and fix versions.

---

## Webhook Notifications

Configure webhooks under the **Webhooks** page to receive instant alerts for:

- Monitor goes down / comes back up
- LAN host goes offline / comes back online
- Domain expiry warning
- New port opened or closed on a LAN host

Supports **Discord**, **Slack**, **Mattermost** (generic JSON), **ntfy**, and **Matrix**.

---

## Email Alerts

Configure SMTP under **Settings → Email**. TipOff will send:

- **Instant alerts** when a new critical issue is found
- **Weekly digests** with a summary of all domain and host status

Both plain text and HTML versions are sent.

---

## Breach Monitoring

The **password breach checker** is free and works out of the box — it uses the [Have I Been Pwned Pwned Passwords](https://haveibeenpwned.com/Passwords) k-anonymity API (only a partial SHA-1 hash is sent; the actual password never leaves your server).

**Email breach monitoring** (checking staff email addresses against HIBP) requires a [HIBP API key](https://haveibeenpwned.com/API/Key). Enter it under **Settings → Breach Monitoring**.

---

## Cyber Essentials Readiness

The **CE questionnaire** covers all five Cyber Essentials control areas:

1. Firewalls
2. Secure Configuration
3. User Access Control
4. Malware Protection
5. Patch Management

Where scan evidence exists (e.g. dangerous open ports found, SSL failures, missing security headers), TipOff automatically surfaces it on the relevant question with an "⚡ scan evidence" badge. Overall CE readiness is tracked as a percentage and shown on the dashboard at a glance.

---

## Public Status Page & Read-Only Link

TipOff has two ways to share visibility without giving out credentials:

- **Public status page** (`/status`) — a clean, unauthenticated page showing uptime and domain health for any monitors or domains you mark as public. Suitable for sharing with customers or colleagues.
- **Read-only dashboard link** — generate a token under **Settings → Shareable Link** to give someone a live view of the full dashboard (read-only). Configure a custom domain under the same setting for a friendlier URL.

---

## Updating

To update to the latest version:

```bash
docker compose pull
docker compose up -d
```

This pulls the latest image from Docker Hub and recreates the container. Your data volume is unaffected — database migrations run automatically on startup.

---

## Pro Licence

TipOff Free includes all scanning and monitoring features.

**TipOff Pro** unlocks:

- PDF report generation (domain checks, host inventory, network map, breach status, CE readiness — all in one report with clickable table of contents)
- Email alerts and weekly digests
- Email breach monitoring (HIBP)
- MSP features (coming soon)

Pro licences — activate a key under **Settings → Licence**.

---

## Development

A `docker-compose.dev.yml` override is included for live-reload development:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up
```

This mounts the source directory into the container and starts Uvicorn with `--reload` — code changes apply instantly without a rebuild.

**Stack:** Python 3.12 · FastAPI · Jinja2/HTMX · SQLite (SQLAlchemy async) · APScheduler · WeasyPrint · dnspython

---

## Licence

TipOff is licensed under the [GNU Affero General Public License v3.0](LICENSE).

In short: you can use, modify, and self-host TipOff freely. If you distribute a modified version or run it as a service for others, you must make your source changes available under the same licence.

Commercial Pro licence keys are sold separately and are not covered by the AGPL.
