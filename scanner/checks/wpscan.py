"""
WordPress detection and vulnerability scanning.

Free:  HTTP-based detection — confirms WordPress, extracts version,
       lists plugins/themes found in page source.
Pro:   WPScan API lookup — CVEs for detected WP version, plugins, themes.
       Requires a WPScan API key (wpscan.com, free tier = 25 req/day).
"""
import re
import httpx
from datetime import datetime, timezone

WPSCAN_API = "https://wpscan.com/api/v3"
_TIMEOUT   = httpx.Timeout(10.0)
_SSL_CTX   = False   # skip SSL verification for self-signed certs on LAN


async def run_for_domain(hostname: str, api_key: str | None = None) -> dict:
    """Entry point for domain-based scanning — tries HTTPS then HTTP."""
    detection = await _check_url(f"https://{hostname}")
    if not detection["detected"]:
        detection = await _check_url(f"http://{hostname}")

    result = {
        "scanned_at":    datetime.now(timezone.utc).isoformat(),
        **detection,
        "vulnerabilities": [],
        "api_used":        False,
        "vuln_error":      None,
    }
    if detection["detected"] and api_key:
        try:
            result["vulnerabilities"] = await _vuln_lookup(detection, api_key)
            result["api_used"] = True
        except Exception as exc:
            result["vuln_error"] = str(exc)
    return result


async def run(ip: str, open_ports: list, api_key: str | None = None) -> dict:
    """Main entry point — returns a result dict stored as wp_scan_results on Host."""
    detection = await _detect(ip, open_ports)
    result = {
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        **detection,
        "vulnerabilities": [],
        "api_used":        False,
        "vuln_error":      None,
    }

    if detection["detected"] and api_key:
        try:
            result["vulnerabilities"] = await _vuln_lookup(detection, api_key)
            result["api_used"] = True
        except Exception as exc:
            result["vuln_error"] = str(exc)

    return result


# ── Detection ─────────────────────────────────────────────────────────────────

async def _detect(ip: str, open_ports: list) -> dict:
    port_nums = {p["port"] for p in open_ports}
    urls = []
    if 443 in port_nums:
        urls.append(f"https://{ip}")
    if 80 in port_nums:
        urls.append(f"http://{ip}")

    for url in urls:
        result = await _check_url(url)
        if result["detected"]:
            return result

    return {"detected": False, "url": None, "version": None, "plugins": [], "themes": []}


async def _check_url(base: str) -> dict:
    result = {"detected": False, "url": base, "version": None, "plugins": [], "themes": []}

    try:
        async with httpx.AsyncClient(verify=_SSL_CTX, timeout=_TIMEOUT,
                                     follow_redirects=True) as client:
            # 1. wp-login.php
            try:
                r = await client.get(f"{base}/wp-login.php")
                if r.status_code == 200 and ("wp-login" in r.text or "WordPress" in r.text):
                    result["detected"] = True
            except Exception:
                pass

            # 2. wp-json (also gives version)
            if not result["detected"]:
                try:
                    r = await client.get(f"{base}/wp-json/")
                    if r.status_code == 200:
                        data = r.json()
                        if "namespaces" in data or "generator" in data:
                            result["detected"] = True
                            gen = data.get("generator", "")
                            m = re.search(r"wordpress/([\d.]+)", gen, re.I)
                            if m:
                                result["version"] = m.group(1)
                except Exception:
                    pass

            if not result["detected"]:
                return result

            # 3. Homepage — version + plugin/theme slugs
            try:
                r = await client.get(base)
                if r.status_code == 200:
                    html = r.text
                    if not result["version"]:
                        m = re.search(
                            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s+([\d.]+)',
                            html, re.I)
                        if m:
                            result["version"] = m.group(1)

                    result["plugins"] = sorted(set(
                        re.findall(r'wp-content/plugins/([a-z0-9_-]+)/', html)))
                    result["themes"]  = sorted(set(
                        re.findall(r'wp-content/themes/([a-z0-9_-]+)/', html)))
            except Exception:
                pass

    except Exception:
        pass

    return result


# ── WPScan API vulnerability lookup (Pro) ─────────────────────────────────────

async def _vuln_lookup(detection: dict, api_key: str) -> list:
    vulns   = []
    headers = {"Authorization": f"Token token={api_key}"}

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:

        # WP core
        if detection.get("version"):
            ver_key = detection["version"].replace(".", "")
            try:
                r = await client.get(f"{WPSCAN_API}/wordpresses/{ver_key}", headers=headers)
                if r.status_code == 200:
                    data = r.json()
                    core = next(iter(data.values()), {})
                    for v in core.get("vulnerabilities", []):
                        vulns.append(_fmt_vuln("WordPress Core", detection["version"], v))
            except Exception:
                pass

        # Plugins
        for slug in detection.get("plugins", []):
            try:
                r = await client.get(f"{WPSCAN_API}/plugins/{slug}", headers=headers)
                if r.status_code == 200:
                    data = r.json()
                    for v in data.get(slug, {}).get("vulnerabilities", []):
                        vulns.append(_fmt_vuln(f"Plugin: {slug}", None, v))
            except Exception:
                pass

        # Themes
        for slug in detection.get("themes", []):
            try:
                r = await client.get(f"{WPSCAN_API}/themes/{slug}", headers=headers)
                if r.status_code == 200:
                    data = r.json()
                    for v in data.get(slug, {}).get("vulnerabilities", []):
                        vulns.append(_fmt_vuln(f"Theme: {slug}", None, v))
            except Exception:
                pass

    return vulns


def _fmt_vuln(component: str, version: str | None, v: dict) -> dict:
    refs  = v.get("references", {})
    cves  = refs.get("cve", [])
    cvss  = v.get("cvss", {}) or {}
    return {
        "component":         component,
        "component_version": version,
        "title":             v.get("title", "Unknown vulnerability"),
        "cvss":              cvss.get("score"),
        "cve":               cves[0] if cves else None,
        "fixed_in":          v.get("fixed_in"),
        "url":               refs.get("url", [None])[0] if refs.get("url") else None,
    }
