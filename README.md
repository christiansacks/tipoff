# CyberReady

**Self-hosted security health checks for small businesses.**

CyberReady runs as a Docker container on your network and continuously monitors your:

- **External domains** — SSL certificates, SPF, DMARC, DKIM, security headers, HTTPS redirect, domain expiry
- **LAN hosts** — auto-discovery, open port risk analysis, vendor/OS detection, acknowledge/mitigate workflow
- **Email breaches** — staff email addresses checked against Have I Been Pwned, password breach checker built in
- **Cyber Essentials readiness** — guided questionnaire across all 5 CE control areas, auto-populated from scan evidence

All checks, data, and reports stay on your own infrastructure — nothing is sent to external services except the DNS checks themselves.

---

## Requirements

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (Windows/Mac) or Docker Engine (Linux)
- [Docker Compose](https://docs.docker.com/compose/install/) (included with Docker Desktop)
- Linux host required for LAN discovery — see [Windows / Mac](#windows--mac) below

---

## Quick Start

### Linux

```bash
git clone https://github.com/christiansacks/cyberready.git
cd cyberready

# Edit docker-compose.yml and change CYBERREADY_USERNAME / CYBERREADY_PASSWORD
# then:
docker compose up -d
```

Open [http://localhost:8080](http://localhost:8080) and log in.

### Windows / Mac

All features work except **LAN host discovery**, which requires Linux kernel networking (`network_mode: host`). Domain checks, breach monitoring, Cyber Essentials, and reports all work normally.

Install [Docker Desktop](https://www.docker.com/products/docker-desktop/), then:

```bash
git clone https://github.com/christiansacks/cyberready.git
cd cyberready

# Edit docker-compose.yml and change CYBERREADY_USERNAME / CYBERREADY_PASSWORD
# then use the Windows override:
docker compose -f docker-compose.yml -f docker-compose.windows.yml up -d
```

Open [http://localhost:8080](http://localhost:8080) and log in.

> **LAN discovery on Windows:** If you need LAN scanning on a Windows network, the recommended approach is to run CyberReady on a small always-on Linux machine (a Raspberry Pi works well) on the same network.

The first-run wizard will walk you through adding your first domain and discovering LAN hosts.

---

## Configuration

All settings can be changed at runtime via the **Settings** page. The following environment variables are available in `docker-compose.yml`:

| Variable | Default | Description |
|---|---|---|
| `CYBERREADY_USERNAME` | `admin` | Dashboard login username |
| `CYBERREADY_PASSWORD` | `admin` | Dashboard login password — **change this** |
| `HTTPS` | *(unset)* | Set to `true` to enable HTTPS on port 8443 |

### HTTPS

Uncomment `HTTPS=true` in `docker-compose.yml`. CyberReady will generate a self-signed certificate on first start and serve on port 8443.

For a proper certificate, mount your cert/key into `/data/cert.pem` and `/data/key.pem`.

### DNS servers

By default, domain checks (SPF, DMARC, DKIM, etc.) use Cloudflare (1.1.1.1) and Google (8.8.8.8) rather than the container's system resolver. This avoids false results on networks with VPN or split-DNS configurations.

You can customise the DNS servers used under **Settings → DNS Servers**.

---

## LAN Discovery

CyberReady uses `nmap` + ARP to discover hosts on your network.

Enter one or more CIDR ranges (comma-separated) in the dashboard, e.g. `192.168.1.0/24, 10.0.0.0/24`. Scheduled auto-scans can be configured under **Settings → LAN Scan Schedule**.

> **Linux only:** LAN discovery requires `network_mode: host`, `NET_RAW`, and `NET_ADMIN` capabilities, which are pre-configured in `docker-compose.yml`. These are needed for raw socket ARP scanning.

---

## Email Alerts

Configure SMTP under **Settings → Email**. CyberReady will send:

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

Where scan evidence exists (e.g. dangerous open ports found, SSL failures), CyberReady automatically surfaces it on the relevant question with an "⚡ scan evidence" badge.

---

## Shareable Read-Only Link

Generate a read-only link under **Settings → Shareable Link**. Share it with a manager, auditor, or client to give them a live view of the dashboard without login credentials. The link works on your local network; configure a custom domain under the same setting if you want a friendlier URL.

---

## Pro Licence

CyberReady Free includes all scanning and monitoring features.

**CyberReady Pro** unlocks:

- PDF report generation
- Email alerts and weekly digests
- Email breach monitoring (HIBP)
- MSP features (coming soon)

Pro licences are available at **[cyberready.io](https://cyberready.io)** *(coming soon)*. Activate a key under **Settings → Licence**.

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

CyberReady is licensed under the [GNU Affero General Public License v3.0](LICENSE).

In short: you can use, modify, and self-host CyberReady freely. If you distribute a modified version or run it as a service for others, you must make your source changes available under the same licence.

Commercial Pro licence keys are sold separately and are not covered by the AGPL.
