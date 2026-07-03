import asyncio, ipaddress, json, os, secrets, socket, uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta

from fastapi import FastAPI, Request, Depends, Form, BackgroundTasks
from fastapi.responses import HTMLResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from db.database import (
    init_db, seed_defaults, get_db, get_setting,
    Domain, Host, ScanResult, Setting, MonitoredEmail, UptimeCheck, Monitor, Webhook,
    hash_password, verify_password,
)
from scanner.runner import scan_domain
from scanner.models import Status

# ── Auth ───────────────────────────────────────────────────────────────────────
# Env vars lock credentials (UI change disabled). Falls back to DB, then admin/admin.
_ENV_USERNAME = os.environ.get("TIPOFF_USERNAME", os.environ.get("CYBERREADY_USERNAME", ""))
_ENV_PASSWORD = os.environ.get("TIPOFF_PASSWORD", os.environ.get("CYBERREADY_PASSWORD", ""))

# In-memory cache — loaded from DB at startup, updated on UI change.
_auth: dict = {"username": "admin", "password_hash": ""}


async def _load_auth_cache():
    from db.database import SessionLocal
    async with SessionLocal() as db:
        _auth["username"]      = await get_setting(db, "auth_username") or "admin"
        _auth["password_hash"] = await get_setting(db, "auth_password_hash") or ""


def _check_auth(request: Request) -> bool:
    import base64
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Basic "):
        return False
    try:
        _, encoded = auth.split(" ", 1)
        username, password = base64.b64decode(encoded).decode().split(":", 1)
    except Exception:
        return False

    if _ENV_USERNAME and _ENV_PASSWORD:
        return (
            secrets.compare_digest(username, _ENV_USERNAME)
            and secrets.compare_digest(password, _ENV_PASSWORD)
        )

    return (
        secrets.compare_digest(username, _auth["username"])
        and verify_password(password, _auth["password_hash"])
    )

from discovery.lan import discover_network, rescan_host as _rescan_host, discover_ipv6_neighbors
from discovery.port_info import PORT_INFO
from discovery.port_info import enrich_ports
from license import verify_license_key, LicenseInfo, LicenseStatus

# ── License ────────────────────────────────────────────────────────────────────
_license: LicenseInfo = LicenseInfo()

async def _load_license_cache():
    from db.database import SessionLocal
    global _license
    async with SessionLocal() as db:
        raw = await get_setting(db, "license_key")
        _license = verify_license_key(raw or "")

async def _save_license(db, raw_key: str):
    global _license
    result = await db.execute(select(Setting).where(Setting.key == "license_key"))
    row = result.scalar_one_or_none()
    if row:
        row.value = raw_key
    else:
        db.add(Setting(key="license_key", value=raw_key))
    await db.commit()
    _license = verify_license_key(raw_key)


# ── LAN Auto-Discovery Schedule ───────────────────────────────────────────────
_discovery_cidr: str = ""
_lan_scan_time:  str = "03:00"
_lan_scan_days:  str = "mon,tue,wed,thu,fri,sat,sun"


async def _save_setting(key: str, value: str):
    from db.database import SessionLocal
    async with SessionLocal() as db:
        r = await db.execute(select(Setting).where(Setting.key == key))
        row = r.scalar_one_or_none()
        if row:
            row.value = value
        else:
            db.add(Setting(key=key, value=value))
        await db.commit()


async def _load_lan_schedule():
    global _discovery_cidr, _lan_scan_time, _lan_scan_days
    from db.database import SessionLocal
    async with SessionLocal() as db:
        for key, attr in [
            ("discovery_cidr", "_discovery_cidr"),
            ("lan_scan_time",  "_lan_scan_time"),
            ("lan_scan_days",  "_lan_scan_days"),
        ]:
            r = await db.execute(select(Setting).where(Setting.key == key))
            row = r.scalar_one_or_none()
            if row and row.value:
                globals()[attr] = row.value


def _apply_lan_schedule():
    try:
        scheduler.remove_job("lan_autodiscovery")
    except Exception:
        pass
    if not _discovery_cidr or not _lan_scan_days:
        return
    try:
        hour, minute = map(int, _lan_scan_time.split(":"))
    except Exception:
        hour, minute = 3, 0
    scheduler.add_job(
        _run_scheduled_lan_discovery,
        "cron",
        hour=hour,
        minute=minute,
        day_of_week=_lan_scan_days,
        id="lan_autodiscovery",
        misfire_grace_time=3600,
    )


async def _run_scheduled_lan_discovery():
    if not _discovery_cidr:
        return
    job_id = f"sched-{uuid.uuid4()}"
    _discovery_jobs[job_id] = {
        "status": "running",
        "stage": "Scheduled scan starting…",
        "hosts_found": 0,
        "scanned": 0,
        "total": 0,
        "cidr": _discovery_cidr,
    }
    await _run_discovery_job(job_id, _discovery_cidr)


# ── Email ──────────────────────────────────────────────────────────────────────
_email_cfg: dict = {"host": "", "port": "587", "user": "", "password": "", "from_addr": "", "tls": "starttls"}
_email_recipient:       str  = ""
_email_alerts_enabled:  bool = False
_email_digest_enabled:  bool = False
_digest_day:            str  = "mon"
_digest_time:           str  = "08:00"

# ── DNS resolver ─────────────────────────────────────────────────────────────
_dns_servers: str = "1.1.1.1, 8.8.8.8"


async def _load_dns_settings():
    global _dns_servers
    from db.database import SessionLocal
    from scanner import resolver as _res
    async with SessionLocal() as db:
        r = await db.execute(select(Setting).where(Setting.key == "dns_servers"))
        row = r.scalar_one_or_none()
        if row and row.value:
            _dns_servers = row.value
    _res.configure([s.strip() for s in _dns_servers.split(",")])


# ── HIBP / Breach monitoring ──────────────────────────────────────────────────
_hibp_api_key:   str = ""
_wpscan_api_key: str = ""


async def _load_wpscan_settings():
    global _wpscan_api_key
    from db.database import SessionLocal
    async with SessionLocal() as db:
        r = await db.execute(select(Setting).where(Setting.key == "wpscan_api_key"))
        row = r.scalar_one_or_none()
        if row and row.value:
            _wpscan_api_key = row.value


async def _load_hibp_settings():
    global _hibp_api_key
    from db.database import SessionLocal
    async with SessionLocal() as db:
        r = await db.execute(select(Setting).where(Setting.key == "hibp_api_key"))
        row = r.scalar_one_or_none()
        if row and row.value:
            _hibp_api_key = row.value


async def _run_breach_checks():
    """Check all monitored emails against HIBP and LeakCheck."""
    import asyncio as _asyncio
    from db.database import SessionLocal
    from scanner.checks.hibp_email import check_email_breaches
    from scanner.checks.leakcheck import check_email_leakcheck
    async with SessionLocal() as db:
        result = await db.execute(select(MonitoredEmail))
        emails = result.scalars().all()
        for me in emails:
            hibp = await check_email_breaches(me.email, _hibp_api_key)
            prev_hibp_count = me.breach_count or 0
            me.status        = hibp["status"]
            me.breach_count  = hibp["count"]
            me.breaches      = json.dumps(hibp["breaches"])
            if hibp["count"] > prev_hibp_count:
                me.hibp_acked = False
            lc = await check_email_leakcheck(me.email)
            prev_lc_count = me.lc_count or 0
            me.lc_status     = lc["status"]
            me.lc_count      = lc["count"]
            me.lc_breaches   = json.dumps(lc["breaches"])
            if lc["count"] > prev_lc_count:
                me.lc_acked = False
            me.last_check_at = datetime.now(timezone.utc)
            await _asyncio.sleep(1.6)  # stay under HIBP's rate limit
        await db.commit()


# ── Shareable read-only link ──────────────────────────────────────────────────
_readonly_token: str = ""
_base_url:       str = ""


def _detect_server_url() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        return f"http://{ip}:8080"
    except Exception:
        return "http://localhost:8080"


def _build_share_url() -> str:
    if not _readonly_token:
        return ""
    base = _base_url or _detect_server_url()
    return f"{base}/?token={_readonly_token}"


async def _load_readonly_settings():
    global _readonly_token, _base_url
    from db.database import SessionLocal
    async with SessionLocal() as db:
        for key, attr in [("readonly_token", "_readonly_token"), ("base_url", "_base_url")]:
            r = await db.execute(select(Setting).where(Setting.key == key))
            row = r.scalar_one_or_none()
            if row and row.value:
                globals()[attr] = row.value

_EMAIL_SETTING_KEYS = [
    "smtp_host", "smtp_port", "smtp_user", "smtp_password",
    "smtp_from", "smtp_tls", "email_recipient",
    "email_alerts_enabled", "email_digest_enabled",
    "digest_day", "digest_time",
]


async def _load_email_settings():
    global _email_cfg, _email_recipient, _email_alerts_enabled
    global _email_digest_enabled, _digest_day, _digest_time
    from db.database import SessionLocal
    async with SessionLocal() as db:
        vals = {}
        for key in _EMAIL_SETTING_KEYS:
            r = await db.execute(select(Setting).where(Setting.key == key))
            row = r.scalar_one_or_none()
            vals[key] = row.value if row else ""
    _email_cfg = {
        "host":      vals.get("smtp_host", ""),
        "port":      vals.get("smtp_port", "587") or "587",
        "user":      vals.get("smtp_user", ""),
        "password":  vals.get("smtp_password", ""),
        "from_addr": vals.get("smtp_from", ""),
        "tls":       vals.get("smtp_tls", "starttls") or "starttls",
    }
    _email_recipient      = vals.get("email_recipient", "")
    _email_alerts_enabled = vals.get("email_alerts_enabled") == "true"
    _email_digest_enabled = vals.get("email_digest_enabled") == "true"
    _digest_day           = vals.get("digest_day", "mon") or "mon"
    _digest_time          = vals.get("digest_time", "08:00") or "08:00"


def _apply_digest_schedule():
    try:
        scheduler.remove_job("weekly_digest")
    except Exception:
        pass
    if not _email_digest_enabled or not _email_recipient or not _email_cfg.get("host"):
        return
    try:
        hour, minute = map(int, _digest_time.split(":"))
    except Exception:
        hour, minute = 8, 0
    scheduler.add_job(
        _send_weekly_digest,
        "cron",
        hour=hour,
        minute=minute,
        day_of_week=_digest_day,
        id="weekly_digest",
        misfire_grace_time=3600,
    )


async def _send_port_change_alert(changes: list[dict]):
    if not _email_alerts_enabled or not _email_recipient or not _email_cfg.get("host"):
        return
    from mailer.sender import send_email
    lines = []
    for c in changes:
        if c["appeared"]:
            lines.append(f"{c['host']} ({c['ip']}) — new port(s) open: {', '.join(str(p) for p in c['appeared'])}")
        if c["disappeared"]:
            lines.append(f"{c['host']} ({c['ip']}) — port(s) closed: {', '.join(str(p) for p in c['disappeared'])}")
    body = "\n".join(lines)
    html = "<br>".join(lines)
    try:
        await send_email(
            _email_cfg, _email_recipient,
            f"TipOff — port changes detected on {len(changes)} host(s)",
            f"<p>{html}</p>",
            body,
        )
    except Exception as e:
        print(f"Port change alert email failed: {e}")


async def _check_and_send_alerts():
    if not _email_alerts_enabled or not _email_recipient or not _email_cfg.get("host"):
        return
    from db.database import SessionLocal
    from mailer.sender import send_email
    async with SessionLocal() as db:
        domains_result = await db.execute(select(Domain))
        new_domain_issues = []
        for domain in domains_result.scalars().all():
            scans = await db.execute(select(ScanResult).where(ScanResult.domain_id == domain.id))
            results = scans.scalars().all()
            current_fail_ids = {r.check_id for r in results if r.status == "fail"}
            try:
                alerted_ids = set(json.loads(domain.alerted_fail_ids or "[]"))
            except Exception:
                alerted_ids = set()
            new_fails = current_fail_ids - alerted_ids
            if new_fails:
                fail_results = [r for r in results if r.check_id in new_fails]
                new_domain_issues.append({"domain": domain, "results": fail_results})
                domain.alerted_fail_ids = json.dumps(sorted(current_fail_ids))
            elif not current_fail_ids and alerted_ids:
                domain.alerted_fail_ids = "[]"

        hosts_result = await db.execute(
            select(Host).where(Host.flagged == True, Host.acknowledged == False, Host.last_alert_at == None)
        )
        new_flagged_hosts = hosts_result.scalars().all()

        if new_domain_issues or new_flagged_hosts:
            try:
                ctx = {
                    "domain_issues":  new_domain_issues,
                    "flagged_hosts":  new_flagged_hosts,
                    "generated_at":   datetime.now(timezone.utc).strftime("%d %b %Y at %H:%M UTC"),
                }
                html = templates.env.get_template("email/alert.html").render(ctx)
                text = templates.env.get_template("email/alert.txt").render(ctx)
                n = len(new_domain_issues) + len(new_flagged_hosts)
                subject = f"TipOff Alert — {n} new issue{'s' if n != 1 else ''} found"
                await send_email(_email_cfg, _email_recipient, subject, html, text)
                now = datetime.now(timezone.utc)
                for host in new_flagged_hosts:
                    host.last_alert_at = now
            except Exception as e:
                print(f"Alert email failed: {e}")
        await db.commit()


async def _fire_webhooks(event: str, context: dict):
    """POST to all enabled webhooks subscribed to `event`."""
    import httpx
    from db.database import SessionLocal
    async with SessionLocal() as db:
        result = await db.execute(select(Webhook).where(Webhook.enabled == True))
        webhooks = result.scalars().all()

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for wh in webhooks:
        subscribed = json.loads(wh.events or "[]")
        if event not in subscribed:
            continue
        name = context.get("name", "")
        status = context.get("status", event.replace("_", " "))
        body     = f"{name} — {status}"
        msg      = f"TipOff • {body}"
        priority = 4 if "down" in event else 3

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                if wh.webhook_type == "ntfy":
                    await client.post(
                        wh.url,
                        content=body.encode(),
                        headers={
                            "Title":    "TipOff",
                            "Priority": str(priority),
                            "Tags":     "bell" if "down" not in event else "rotating_light",
                        },
                    )
                elif wh.webhook_type == "matrix":
                    txn_url = wh.url.replace("{txn_id}", str(uuid.uuid4()))
                    await client.put(txn_url, json={
                        "msgtype": "m.text",
                        "body":    msg,
                    })
                else:
                    await client.post(wh.url, json={
                        "content":   msg,
                        "text":      msg,
                        "event":     event,
                        "name":      name,
                        "status":    status,
                        "timestamp": now,
                    })
        except Exception as e:
            print(f"Webhook '{wh.name}' failed: {e}")


def _check_expected_status(actual: int, expected: str | None) -> bool:
    """Return True if actual HTTP status matches the expected pattern."""
    if not expected or not expected.strip():
        return actual < 500
    for part in expected.split(","):
        part = part.strip().lower()
        if part == "2xx" and 200 <= actual < 300:
            return True
        if part == "3xx" and 300 <= actual < 400:
            return True
        if part == "4xx" and 400 <= actual < 500:
            return True
        if part == "5xx" and 500 <= actual < 600:
            return True
        try:
            if int(part) == actual:
                return True
        except ValueError:
            pass
    return False


async def _http_check(url: str, timeout: int = 10) -> tuple[bool, int | None, int | None]:
    """Perform HTTP GET, return (is_reachable, status_code, response_ms)."""
    import httpx
    try:
        t0 = datetime.now(timezone.utc)
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            r = await client.get(url)
        ms = int((datetime.now(timezone.utc) - t0).total_seconds() * 1000)
        return True, r.status_code, ms
    except Exception:
        return False, None, None


async def _tcp_check(host: str, port: int, timeout: int = 5) -> tuple[bool, int | None]:
    """TCP connect check, return (is_up, response_ms)."""
    import asyncio as _asyncio
    try:
        t0 = datetime.now(timezone.utc)
        _, writer = await _asyncio.wait_for(
            _asyncio.open_connection(host, port), timeout=timeout
        )
        ms = int((datetime.now(timezone.utc) - t0).total_seconds() * 1000)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True, ms
    except Exception:
        return False, None


async def _run_uptime_checks():
    """Check every domain + custom monitor. Runs every 5 minutes."""
    from datetime import timedelta
    from db.database import SessionLocal
    async with SessionLocal() as db:
        now = datetime.now(timezone.utc)
        newly_down, newly_up = [], []

        # ── Domain checks (HTTP/HTTPS) ──────────────────────────────────────
        domains_result = await db.execute(select(Domain))
        for domain in domains_result.scalars().all():
            reachable, status_code, response_ms = await _http_check(f"https://{domain.hostname}")
            if not reachable:
                reachable, status_code, response_ms = await _http_check(f"http://{domain.hostname}")
            is_up = reachable and (status_code is not None) and status_code < 500

            db.add(UptimeCheck(domain_id=domain.id, checked_at=now,
                               is_up=is_up, response_ms=response_ms, status_code=status_code))
            if not is_up and not domain.uptime_alerted:
                domain.uptime_alerted = True
                newly_down.append(("domain", domain.hostname))
            elif is_up and domain.uptime_alerted:
                domain.uptime_alerted = False
                newly_up.append(("domain", domain.hostname))

        # ── Custom monitor checks ───────────────────────────────────────────
        monitors_result = await db.execute(select(Monitor).where(Monitor.enabled == True))
        for mon in monitors_result.scalars().all():
            is_up, response_ms, status_code = False, None, None

            if mon.protocol == "tcp":
                is_up, response_ms = await _tcp_check(mon.host, mon.port)
            else:
                scheme = "https" if mon.protocol == "https" else "http"
                reachable, status_code, response_ms = await _http_check(
                    f"{scheme}://{mon.host}:{mon.port}"
                )
                is_up = reachable and status_code is not None and _check_expected_status(status_code, mon.expected_status)

            db.add(UptimeCheck(monitor_id=mon.id, checked_at=now,
                               is_up=is_up, response_ms=response_ms, status_code=status_code))
            label = f"{mon.name} ({mon.host}:{mon.port})"
            if not is_up and not mon.uptime_alerted:
                mon.uptime_alerted = True
                newly_down.append(("monitor", label))
            elif is_up and mon.uptime_alerted:
                mon.uptime_alerted = False
                newly_up.append(("monitor", label))

        # ── Host connectivity checks (TCP ping all known ports) ────────────
        hosts_result = await db.execute(select(Host))
        for host in hosts_result.scalars().all():
            if not host.open_ports:
                continue
            port_nums = [p["port"] for p in host.open_ports]
            check_results = await asyncio.gather(
                *[_tcp_check(host.ip, port, timeout=3) for port in port_nums]
            )
            new_port_status = {
                str(port): is_up for port, (is_up, _) in zip(port_nums, check_results)
            }
            new_host_online = any(new_port_status.values())
            label = host.hostname or host.ip
            if host.host_online is True and not new_host_online:
                newly_down.append(("host", label))
            elif host.host_online is False and new_host_online:
                newly_up.append(("host", label))
            host.port_status   = new_port_status
            host.host_online   = new_host_online
            host.last_ping_at  = now

        # Prune checks older than 90 days
        cutoff = now - timedelta(days=90)
        await db.execute(delete(UptimeCheck).where(UptimeCheck.checked_at < cutoff))
        await db.commit()

    # Send alert if anything went down (Pro + email configured)
    if newly_down and _email_alerts_enabled and _email_recipient and _email_cfg.get("host") and _license.has_feature("email_alerts"):
        from mailer.sender import send_email
        try:
            ctx = {
                "newly_down":   [label for _, label in newly_down],
                "newly_up":     [label for _, label in newly_up],
                "generated_at": datetime.now(timezone.utc).strftime("%d %b %Y at %H:%M UTC"),
            }
            html = templates.env.get_template("email/uptime_alert.html").render(ctx)
            text = templates.env.get_template("email/uptime_alert.txt").render(ctx)
            n = len(newly_down)
            await send_email(_email_cfg, _email_recipient,
                             f"TipOff — {n} service{'s' if n != 1 else ''} went down",
                             html, text)
        except Exception as e:
            print(f"Uptime alert email failed: {e}")

    # Fire webhooks — split host events from monitor/domain events
    for kind, label in newly_down:
        if kind == "host":
            await _fire_webhooks("host_offline", {"name": label, "status": "went offline"})
        else:
            await _fire_webhooks("monitor_down", {"name": label, "status": "went DOWN"})
    for kind, label in newly_up:
        if kind == "host":
            await _fire_webhooks("host_online", {"name": label, "status": "came back online"})
        else:
            await _fire_webhooks("monitor_up", {"name": label, "status": "came back UP"})


async def _send_domain_expiry_alerts():
    """Daily check — email when domains hit 60/30/14/7 day expiry thresholds. Pro only."""
    if not _license.has_feature("email_alerts"):
        return
    if not _email_alerts_enabled or not _email_recipient or not _email_cfg.get("host"):
        return
    from db.database import SessionLocal
    from mailer.sender import send_email

    thresholds = [60, 30, 14, 7]

    async with SessionLocal() as db:
        domains_result = await db.execute(select(Domain))
        to_alert = []

        for domain in domains_result.scalars().all():
            # Get days_left from most recent WHOIS scan result
            scan_result = await db.execute(
                select(ScanResult).where(
                    ScanResult.domain_id == domain.id,
                    ScanResult.check_id.in_(["domain_expiring_soon", "domain_renewal_due", "domain_expired", "domain_expiry_ok"]),
                ).order_by(ScanResult.scanned_at.desc())
            )
            row = scan_result.scalars().first()
            if not row or not row.raw or "days_left" not in row.raw:
                continue

            days_left = row.raw["days_left"]
            expiry    = row.raw.get("expiry", "unknown")

            # Which thresholds have already been notified?
            try:
                already_sent = set(json.loads(domain.whois_alert_sent or "[]"))
            except Exception:
                already_sent = set()

            # If domain was renewed (days_left climbed back above 60), reset
            if days_left > 60 and already_sent:
                domain.whois_alert_sent = "[]"
                continue

            # Find the lowest threshold we've crossed that hasn't been sent yet
            for t in thresholds:
                if days_left <= t and t not in already_sent:
                    to_alert.append({"hostname": domain.hostname, "days_left": days_left, "expiry": expiry})
                    already_sent.add(t)
                    domain.whois_alert_sent = json.dumps(sorted(already_sent))
                    break  # one email per domain per run

        if to_alert:
            try:
                ctx = {
                    "expiring":     to_alert,
                    "generated_at": datetime.now(timezone.utc).strftime("%d %b %Y at %H:%M UTC"),
                }
                html = templates.env.get_template("email/expiry_alert.html").render(ctx)
                text = templates.env.get_template("email/expiry_alert.txt").render(ctx)
                n       = len(to_alert)
                subject = f"TipOff — {n} domain{'s' if n != 1 else ''} expiring soon"
                await send_email(_email_cfg, _email_recipient, subject, html, text)
            except Exception as e:
                print(f"Expiry alert email failed: {e}")

            for d in to_alert:
                await _fire_webhooks("domain_expiry", {
                    "name":     d["hostname"],
                    "status":   f"expires in {d['days_left']} days",
                    "days_left": d["days_left"],
                })

        await db.commit()


async def _send_weekly_digest():
    if not _email_recipient or not _email_cfg.get("host"):
        return
    from db.database import SessionLocal
    from mailer.sender import send_email
    async with SessionLocal() as db:
        domains_result = await db.execute(select(Domain))
        domain_data, domain_passes = [], 0
        for d in domains_result.scalars().all():
            scans = await db.execute(select(ScanResult).where(ScanResult.domain_id == d.id))
            results = scans.scalars().all()
            score = _score_from_rows(results)
            if score is not None and score >= 50:
                domain_passes += 1
            domain_data.append({
                "domain": d, "score": score,
                "fails":  sum(1 for r in results if r.status == "fail"),
                "warns":  sum(1 for r in results if r.status == "warn"),
                "results": results,
            })
        hosts_result = await db.execute(select(Host))
        hosts = hosts_result.scalars().all()
    try:
        ctx = {
            "domain_data":       domain_data,
            "domain_passes":     domain_passes,
            "flagged_hosts":     [h for h in hosts if h.flagged and not h.acknowledged],
            "acknowledged_hosts":[h for h in hosts if h.flagged and h.acknowledged],
            "total_hosts":       len(hosts),
            "generated_at":      datetime.now(timezone.utc).strftime("%d %B %Y"),
        }
        html = templates.env.get_template("email/digest.html").render(ctx)
        text = templates.env.get_template("email/digest.txt").render(ctx)
        subject = f"TipOff Weekly Digest — {datetime.now(timezone.utc).strftime('%d %b %Y')}"
        await send_email(_email_cfg, _email_recipient, subject, html, text)
    except Exception as e:
        print(f"Digest email failed: {e}")


scheduler = AsyncIOScheduler()

# In-memory discovery job state — keyed by job_id
_discovery_jobs: dict[str, dict] = {}


async def run_due_scans():
    from db.database import SessionLocal
    async with SessionLocal() as db:
        now = datetime.utcnow()  # naive UTC — matches SQLite storage
        result = await db.execute(
            select(Domain).where(Domain.next_scan_at <= now)
        )
        domains = result.scalars().all()
        for domain in domains:
            try:
                print(f"Scanning {domain.hostname}…")
                results = await scan_domain(domain.hostname)
                await db.execute(
                    delete(ScanResult).where(
                        ScanResult.domain_id == domain.id,
                        ScanResult.check_id != "wordpress_vulns",
                    )
                )
                for r in results:
                    db.add(ScanResult(
                        domain_id=domain.id,
                        check_id=r.check_id,
                        status=r.status.value,
                        title=r.title,
                        detail=r.detail,
                        remediation=r.remediation,
                        score_impact=r.score_impact,
                        raw=r.raw,
                    ))
                domain.last_scan_at = now
                domain.next_scan_at = now + timedelta(hours=24)
                await db.commit()

                # Auto-rescan WordPress vulnerabilities if detected and API key is set
                if domain.is_wordpress and _wpscan_api_key and _license.has_feature("pdf"):
                    try:
                        from scanner.checks import wpscan as _wpscan
                        wp_result = await _wpscan.run_for_domain(domain.hostname, _wpscan_api_key)
                        async with SessionLocal() as wp_db:
                            wp_domain = await wp_db.get(Domain, domain.id)
                            if wp_domain:
                                wp_domain.wp_scan_at      = now
                                wp_domain.wp_scan_results = wp_result
                                await wp_db.execute(delete(ScanResult).where(
                                    ScanResult.domain_id == domain.id,
                                    ScanResult.check_id  == "wordpress_vulns",
                                ))
                                vulns = wp_result.get("vulnerabilities", []) if wp_result.get("api_used") else []
                                if vulns:
                                    has_crit = any(v.get("cvss") and v["cvss"] >= 9 for v in vulns)
                                    has_high = any(v.get("cvss") and v["cvss"] >= 7 for v in vulns)
                                    impact   = 12 if has_crit else (8 if has_high else 4)
                                    n_vulns  = len(vulns)
                                    wp_db.add(ScanResult(
                                        domain_id    = domain.id,
                                        check_id     = "wordpress_vulns",
                                        status       = "fail",
                                        title        = f"WordPress: {n_vulns} known vulnerabilit{'y' if n_vulns == 1 else 'ies'}",
                                        detail       = f"WPScan found {n_vulns} unpatched vulnerabilit{'y' if n_vulns == 1 else 'ies'} in WordPress core, plugins or themes.",
                                        remediation  = "Update all plugins, themes, and WordPress core to their latest versions.",
                                        score_impact = impact,
                                        raw          = {"vulnerabilities": vulns},
                                    ))
                                await wp_db.commit()
                    except Exception as e:
                        print(f"WPScan auto-rescan failed for {domain.hostname}: {e}")
            except Exception as e:
                print(f"Scan failed for {domain.hostname}: {e}")
    await _check_and_send_alerts()
    try:
        await _run_breach_checks()
    except Exception as e:
        print(f"Breach check run failed: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    await seed_defaults()
    await _load_auth_cache()
    await _load_license_cache()
    await _load_dns_settings()
    await _load_lan_schedule()
    await _load_email_settings()
    await _load_readonly_settings()
    await _load_hibp_settings()
    await _load_wpscan_settings()
    scheduler.add_job(run_due_scans, "interval", hours=1, id="domain_scanner")
    scheduler.add_job(_run_uptime_checks, "interval", minutes=5, id="uptime_checks")
    scheduler.add_job(_send_domain_expiry_alerts, "cron", hour=9, minute=0, id="expiry_alerts", misfire_grace_time=3600)
    scheduler.start()
    _apply_lan_schedule()
    _apply_digest_schedule()
    asyncio.create_task(run_due_scans())
    yield
    scheduler.shutdown()


app = FastAPI(lifespan=lifespan)

@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    if request.url.path.startswith("/static") or request.url.path == "/status":
        return await call_next(request)

    if _check_auth(request):
        return await call_next(request)

    # Read-only token — query param on first visit, cookie thereafter
    provided = request.query_params.get("token") or request.cookies.get("readonly_access", "")
    if provided and _readonly_token and secrets.compare_digest(provided, _readonly_token):
        if request.method != "GET":
            return Response("Read-only access — this action is not permitted.", status_code=403)
        if request.url.path.startswith("/settings"):
            return Response(status_code=302, headers={"Location": "/"})
        request.state.readonly = True
        response = await call_next(request)
        if request.query_params.get("token"):
            response.set_cookie("readonly_access", provided,
                                max_age=86400 * 30, httponly=True, samesite="strict")
        return response

    return Response(
        content="Unauthorized",
        status_code=401,
        headers={"WWW-Authenticate": 'Basic realm="TipOff"'},
    )

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")
templates.env.globals["LicenseStatus"] = LicenseStatus

@app.middleware("http")
async def inject_license(request: Request, call_next):
    request.state.license = _license
    request.state.readonly = False  # auth_middleware may override for token users
    return await call_next(request)

def _tpl(name: str, ctx: dict):
    ctx.setdefault("license", _license)
    req = ctx.get("request")
    ctx.setdefault("readonly", getattr(req.state, "readonly", False) if req else False)
    return templates.TemplateResponse(name, ctx)


def _score_from_rows(rows) -> int | None:
    if not rows:
        return None
    deducted = sum(r.score_impact for r in rows if r.status in ("fail", "warn"))
    return max(0, 60 - deducted)


def _detect_cidr() -> str:
    """Prefer physical Ethernet/WiFi interfaces over VPN/tunnel interfaces."""
    import subprocess
    try:
        # parse `ip -o -4 addr` to find interfaces with their CIDRs
        out = subprocess.check_output(["ip", "-o", "-4", "addr"], text=True)
        candidates = []
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            iface, cidr = parts[1], parts[3]
            ip = cidr.split("/")[0]
            if ip.startswith("127.") or ip.startswith("172."):
                continue  # skip loopback and Docker bridges
            # rank physical interfaces above tunnels/VPNs
            rank = 0 if any(iface.startswith(p) for p in ("eth", "enp", "ens", "wlan", "wlp")) else 1
            candidates.append((rank, cidr))
        if candidates:
            candidates.sort()
            cidr = candidates[0][1]
            network = ipaddress.ip_network(cidr, strict=False)
            # cap at /24 — scanning a /22 (1024 hosts) takes too long
            if network.prefixlen < 24:
                ip = cidr.split("/")[0]
                return str(ipaddress.ip_network(f"{ip}/24", strict=False))
            return str(network)
    except Exception:
        pass
    return "192.168.1.0/24"


# ── Pages ──────────────────────────────────────────────────────────────────────

@app.get("/logout")
async def logout():
    return Response(
        status_code=401,
        headers={"WWW-Authenticate": 'Basic realm="TipOff"'},
        content="Logged out",
    )


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, db: AsyncSession = Depends(get_db)):
    domains_result = await db.execute(select(Domain))
    domains = domains_result.scalars().all()

    domain_data = []
    for d in domains:
        scans = await db.execute(select(ScanResult).where(ScanResult.domain_id == d.id))
        results = scans.scalars().all()
        score = _score_from_rows(results)
        acked_ids = set((d.acked_checks or {}).keys())
        fails  = sum(1 for r in results if r.status == "fail" and r.check_id not in acked_ids)
        warns  = sum(1 for r in results if r.status == "warn" and r.check_id not in acked_ids)
        domain_data.append({"domain": d, "score": score, "fails": fails, "warns": warns, "results": results})

    hosts_result = await db.execute(select(Host))
    hosts = hosts_result.scalars().all()

    emails_result = await db.execute(select(MonitoredEmail))
    emails = emails_result.scalars().all()

    ce_answers = await _load_ce_answers()
    from ce.questions import score_answers as _ce_score_fn
    ce_scores  = _ce_score_fn(ce_answers)

    new_cutoff = datetime.now() - timedelta(hours=24)
    return _tpl("index.html", {
        "request":      request,
        "domain_data":  domain_data,
        "hosts":        hosts,
        "new_cutoff":   new_cutoff,
        "default_cidr": _detect_cidr(),
        # section summaries
        "domain_total":    len(domain_data),
        "domain_passing":  sum(1 for d in domain_data if d["fails"] == 0 and d["warns"] == 0 and d["score"] is not None),
        "domain_warn":     sum(1 for d in domain_data if d["fails"] == 0 and d["warns"] > 0),
        "domain_critical": sum(1 for d in domain_data if d["fails"] > 0),
        "host_total":       len(hosts),
        "host_flagged":     sum(1 for h in hosts if h.flagged and not h.acknowledged),
        "host_acked":       sum(1 for h in hosts if h.flagged and h.acknowledged),
        "host_offline":     sum(1 for h in hosts if h.host_online is False),
        "host_ports_down":  sum(1 for h in hosts if h.host_online is True and h.port_status and any(not v for v in h.port_status.values())),
        "hosts_checked":    any(h.host_online is not None for h in hosts),
        "breach_monitored": len(emails),
        "breach_count":     sum(1 for e in emails if (e.status == "breached" and not e.hibp_acked) or (e.lc_status == "breached" and not e.lc_acked)),
        "ce_pct":           ce_scores["pct"],
        "ce_remaining":     ce_scores["total"] - ce_scores["passed"],
    })


@app.get("/partials/wizard", response_class=HTMLResponse)
async def partials_wizard(request: Request, db: AsyncSession = Depends(get_db)):
    # Never show wizard to read-only users
    if getattr(request.state, "readonly", False):
        return HTMLResponse("")
    dismissed = await get_setting(db, "wizard_dismissed")
    if dismissed == "true":
        return HTMLResponse("")
    domain_count = (await db.execute(select(Domain))).scalars().all()
    host_count   = (await db.execute(select(Host))).scalars().all()
    if domain_count and host_count:
        # Both done — permanently dismiss and show a brief success message
        await _save_setting("wizard_dismissed", "true")
        return _tpl("partials/wizard.html", {"request": request, "step": "done"})
    step = 1 if not domain_count else 2
    return _tpl("partials/wizard.html", {
        "request": request,
        "step": step,
        "default_cidr": _detect_cidr(),
    })


@app.post("/wizard/dismiss", response_class=HTMLResponse)
async def wizard_dismiss():
    asyncio.create_task(_save_setting("wizard_dismissed", "true"))
    return HTMLResponse("")


@app.get("/partials/domains", response_class=HTMLResponse)
async def partials_domains(request: Request, db: AsyncSession = Depends(get_db)):
    domains_result = await db.execute(select(Domain))
    domains = domains_result.scalars().all()
    domain_data = []
    for d in domains:
        scans = await db.execute(select(ScanResult).where(ScanResult.domain_id == d.id))
        results = scans.scalars().all()
        acked_ids = set((d.acked_checks or {}).keys())
        domain_data.append({
            "domain": d,
            "score": _score_from_rows(results),
            "fails": sum(1 for r in results if r.status == "fail" and r.check_id not in acked_ids),
            "warns": sum(1 for r in results if r.status == "warn" and r.check_id not in acked_ids),
            "results": results,
        })
    return templates.TemplateResponse("partials/domains_list.html", {
        "request": request,
        "domain_data": domain_data,
        "readonly": getattr(request.state, "readonly", False),
    })


@app.get("/partials/domain-summary", response_class=HTMLResponse)
async def partials_domain_summary(request: Request, db: AsyncSession = Depends(get_db)):
    domains_result = await db.execute(select(Domain))
    domains = domains_result.scalars().all()
    domain_data = []
    for d in domains:
        scans = await db.execute(select(ScanResult).where(ScanResult.domain_id == d.id))
        results = scans.scalars().all()
        acked_ids = set((d.acked_checks or {}).keys())
        domain_data.append({
            "score": _score_from_rows(results),
            "fails": sum(1 for r in results if r.status == "fail" and r.check_id not in acked_ids),
            "warns": sum(1 for r in results if r.status == "warn" and r.check_id not in acked_ids),
        })
    total    = len(domain_data)
    critical = sum(1 for d in domain_data if d["fails"] > 0)
    warning  = sum(1 for d in domain_data if d["fails"] == 0 and d["warns"] > 0)
    passing  = sum(1 for d in domain_data if d["fails"] == 0 and d["warns"] == 0 and d["score"] is not None)
    chips = []
    if total == 0:
        chips.append('<span class="summary-chip muted-chip">No domains added</span>')
    else:
        chips.append(f'<span class="summary-chip neutral-chip">{total} domain{"s" if total != 1 else ""}</span>')
        if critical:
            chips.append(f'<span class="summary-chip fail-chip">{critical} critical</span>')
        if warning:
            chips.append(f'<span class="summary-chip warn-chip">{warning} warning{"s" if warning != 1 else ""}</span>')
        if passing == total:
            chips.append('<span class="summary-chip pass-chip">All passing</span>')
        elif passing:
            chips.append(f'<span class="summary-chip pass-chip">{passing} passing</span>')
    return HTMLResponse("".join(chips))


async def _render_domain_detail(domain_id: str, request: Request, db: AsyncSession):
    domain = await db.get(Domain, domain_id)
    if not domain:
        return HTMLResponse("Not found", status_code=404)
    scans = await db.execute(select(ScanResult).where(ScanResult.domain_id == domain_id))
    results = scans.scalars().all()
    acked_ids = set((domain.acked_checks or {}).keys())
    fails  = [r for r in results if r.status == "fail" and r.check_id not in acked_ids]
    warns  = [r for r in results if r.status == "warn" and r.check_id not in acked_ids]
    passes = [r for r in results if r.status == "pass"]
    acked  = [r for r in results if r.status in ("fail", "warn") and r.check_id in acked_ids]
    score  = _score_from_rows(results)
    return _tpl("domain_detail.html", {
        "request": request,
        "domain":  domain,
        "fails":   fails,
        "warns":   warns,
        "passes":  passes,
        "acked":   acked,
        "score":   score,
    })


@app.get("/domain/{domain_id}", response_class=HTMLResponse)
async def domain_detail(domain_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    return await _render_domain_detail(domain_id, request, db)


@app.post("/domains/{domain_id}/checks/{check_id}/ack", response_class=HTMLResponse)
async def ack_domain_check(
    domain_id: str,
    check_id: str,
    request: Request,
    ack_note: str = Form(""),
    db: AsyncSession = Depends(get_db),
):
    domain = await db.get(Domain, domain_id)
    if not domain:
        return HTMLResponse("Not found", status_code=404)
    acked = dict(domain.acked_checks or {})
    acked[check_id] = {
        "note":     ack_note.strip(),
        "acked_at": datetime.now(timezone.utc).isoformat(),
    }
    domain.acked_checks = acked
    await db.commit()
    await db.refresh(domain)
    return await _render_domain_detail(domain_id, request, db)


@app.delete("/domains/{domain_id}/checks/{check_id}/ack", response_class=HTMLResponse)
async def unack_domain_check(
    domain_id: str,
    check_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    domain = await db.get(Domain, domain_id)
    if not domain:
        return HTMLResponse("Not found", status_code=404)
    acked = dict(domain.acked_checks or {})
    acked.pop(check_id, None)
    domain.acked_checks = acked
    await db.commit()
    await db.refresh(domain)
    return await _render_domain_detail(domain_id, request, db)


# ── Actions ────────────────────────────────────────────────────────────────────

@app.post("/domains/add", response_class=HTMLResponse)
async def add_domain(
    request: Request,
    hostname: str = Form(...),
    background_tasks: BackgroundTasks = BackgroundTasks(),
    db: AsyncSession = Depends(get_db),
):
    hostname = hostname.strip().lower().removeprefix("https://").removeprefix("http://").rstrip("/")
    existing = await db.execute(select(Domain).where(Domain.hostname == hostname))
    if not existing.scalar_one_or_none():
        db.add(Domain(hostname=hostname))
        await db.commit()
    # kick off a scan immediately in the background
    background_tasks.add_task(_scan_and_store, hostname)
    return HTMLResponse(
        f'<div class="toast">Added {hostname} — scanning now...</div>',
        headers={"HX-Trigger": "domainAdded"},
    )


@app.delete("/domains/{domain_id}", response_class=HTMLResponse)
async def delete_domain(domain_id: str, db: AsyncSession = Depends(get_db)):
    await db.execute(delete(ScanResult).where(ScanResult.domain_id == domain_id))
    await db.execute(delete(Domain).where(Domain.id == domain_id))
    await db.commit()
    return HTMLResponse("")


@app.post("/domains/{domain_id}/wpscan", response_class=HTMLResponse)
async def wpscan_domain(
    domain_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    from scanner.checks import wpscan as _wpscan
    domain = await db.get(Domain, domain_id)
    if not domain:
        return HTMLResponse("Not found", status_code=404)

    api_key = _wpscan_api_key if _license.has_feature("pdf") else None
    result  = await _wpscan.run_for_domain(domain.hostname, api_key)

    domain.is_wordpress    = result["detected"]
    domain.wp_version      = result.get("version")
    domain.wp_scan_at      = datetime.now(timezone.utc)
    domain.wp_scan_results = result
    await db.commit()

    # Remove old WP scan result then write fresh one
    await db.execute(delete(ScanResult).where(
        ScanResult.domain_id == domain_id,
        ScanResult.check_id  == "wordpress_vulns",
    ))
    if result["detected"] and result.get("api_used"):
        vulns     = result.get("vulnerabilities", [])
        n_vulns   = len(vulns)
        has_crit  = any(v.get("cvss") and v["cvss"] >= 9 for v in vulns)
        has_high  = any(v.get("cvss") and v["cvss"] >= 7 for v in vulns)
        if n_vulns > 0:
            impact = 12 if has_crit else (8 if has_high else 4)
            titles = "; ".join(v["title"] for v in vulns[:5])
            if n_vulns > 5:
                titles += f" (+{n_vulns - 5} more)"
            db.add(ScanResult(
                domain_id    = domain_id,
                check_id     = "wordpress_vulns",
                status       = "fail",
                title        = f"WordPress: {n_vulns} known vulnerabilit{'y' if n_vulns == 1 else 'ies'}",
                detail       = titles,
                remediation  = "Update WordPress core, plugins and themes to their latest versions.",
                score_impact = impact,
                raw          = {"count": n_vulns, "has_critical": has_crit, "has_high": has_high},
            ))
    await db.commit()
    await db.refresh(domain)

    scans = await db.execute(
        select(ScanResult).where(ScanResult.domain_id == domain_id)
    )
    results = scans.scalars().all()
    return _tpl("domain_detail.html", {
        "request": request,
        "domain":  domain,
        "fails":   [r for r in results if r.status == "fail"],
        "warns":   [r for r in results if r.status == "warn"],
        "passes":  [r for r in results if r.status == "pass"],
        "score":   _score_from_rows(results),
    })


@app.post("/discover", response_class=HTMLResponse)
async def start_discovery(
    request: Request,
    cidr: str = Form(...),
    background_tasks: BackgroundTasks = BackgroundTasks(),
):
    global _discovery_cidr
    if cidr != _discovery_cidr:
        _discovery_cidr = cidr
        asyncio.create_task(_save_setting("discovery_cidr", cidr))

    job_id = str(uuid.uuid4())
    _discovery_jobs[job_id] = {
        "status": "running",
        "stage": "Starting…",
        "hosts_found": 0,
        "scanned": 0,
        "total": 0,
        "cidr": cidr,
    }
    background_tasks.add_task(_run_discovery_job, job_id, cidr)
    return templates.TemplateResponse("partials/discovery_progress.html", {
        "request": request,
        "job": _discovery_jobs[job_id],
        "job_id": job_id,
    })


@app.get("/discover/progress/{job_id}", response_class=HTMLResponse)
async def discovery_progress(
    job_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    job = _discovery_jobs.get(job_id)
    if not job:
        return HTMLResponse("")

    if job["status"] == "done":
        hosts_result = await db.execute(select(Host))
        all_hosts = hosts_result.scalars().all()
        _discovery_jobs.pop(job_id, None)
        return templates.TemplateResponse("partials/host_both_views.html", {
            "request":   request,
            "hosts":     all_hosts,
            "new_cutoff": datetime.now() - timedelta(hours=24),
        })

    if job["status"] == "error":
        _discovery_jobs.pop(job_id, None)
        return HTMLResponse(
            '<p class="empty-state" style="color:var(--fail)">Discovery failed. Check the container logs.</p>'
        )

    return templates.TemplateResponse("partials/discovery_progress.html", {
        "request": request,
        "job": job,
        "job_id": job_id,
    })


@app.get("/host/{host_id}", response_class=HTMLResponse)
async def host_detail(host_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    host = await db.get(Host, host_id)
    if not host:
        return HTMLResponse("Not found", status_code=404)
    ports = enrich_ports(host.open_ports or [])
    flagged_ports = [p for p in ports if p["risk"] in ("critical", "high")]
    all_v6 = host.ipv6_addresses or []
    return _tpl("host_detail.html", {
        "request":       request,
        "host":          host,
        "ports":         ports,
        "flagged_ports": flagged_ports,
        "global_v6":     [a for a in all_v6 if not a.startswith("fe80")],
        "local_v6":      [a for a in all_v6 if a.startswith("fe80")],
    })


@app.post("/hosts/{host_id}/rescan", response_class=HTMLResponse)
async def rescan_host_route(
    host_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    host = await db.get(Host, host_id)
    if not host:
        return HTMLResponse("Not found", status_code=404)

    data = await _rescan_host(host.ip)

    host.hostname   = data.get("hostname", host.hostname)
    host.mac        = data.get("mac") or host.mac
    host.vendor     = data.get("vendor") or host.vendor
    host.os_guess   = data.get("os_guess", host.os_guess)
    host.open_ports = data.get("open_ports", [])
    host.flagged    = data.get("flagged", False)
    host.last_seen  = datetime.now(timezone.utc)
    host.is_vm      = data.get("is_vm", host.is_vm or False)
    await db.commit()
    await db.refresh(host)

    ports = enrich_ports(host.open_ports or [])
    flagged_ports = [p for p in ports if p["risk"] in ("critical", "high")]
    return _tpl("host_detail.html", {
        "request": request,
        "host": host,
        "ports": ports,
        "flagged_ports": flagged_ports,
    })


@app.post("/hosts/{host_id}/wpscan", response_class=HTMLResponse)
async def wpscan_host(
    host_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    from scanner.checks import wpscan as _wpscan
    host = await db.get(Host, host_id)
    if not host:
        return HTMLResponse("Not found", status_code=404)

    api_key = _wpscan_api_key if _license.has_feature("pdf") else None
    result  = await _wpscan.run(host.ip, host.open_ports or [], api_key)

    host.is_wordpress    = result["detected"]
    host.wp_version      = result.get("version")
    host.wp_url          = result.get("url")
    host.wp_scan_at      = datetime.now(timezone.utc)
    host.wp_scan_results = result
    await db.commit()
    await db.refresh(host)

    ports = enrich_ports(host.open_ports or [])
    flagged_ports = [p for p in ports if p["risk"] in ("critical", "high")]
    return _tpl("host_detail.html", {
        "request":      request,
        "host":         host,
        "ports":        ports,
        "flagged_ports": flagged_ports,
    })


@app.post("/hosts/{host_id}/acknowledge", response_class=HTMLResponse)
async def acknowledge_host(
    host_id: str,
    request: Request,
    ack_note: str = Form(""),
    db: AsyncSession = Depends(get_db),
):
    host = await db.get(Host, host_id)
    if not host:
        return HTMLResponse("Not found", status_code=404)
    host.acknowledged = True
    host.ack_note     = ack_note.strip()
    host.ack_at       = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(host)
    ports = enrich_ports(host.open_ports or [])
    flagged_ports = [p for p in ports if p["risk"] in ("critical", "high")]
    return _tpl("host_detail.html", {
        "request": request,
        "host": host,
        "ports": ports,
        "flagged_ports": flagged_ports,
    })


@app.delete("/hosts/{host_id}/acknowledge", response_class=HTMLResponse)
async def unacknowledge_host(
    host_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    host = await db.get(Host, host_id)
    if not host:
        return HTMLResponse("Not found", status_code=404)
    host.acknowledged = False
    host.ack_note     = None
    host.ack_at       = None
    await db.commit()
    await db.refresh(host)
    ports = enrich_ports(host.open_ports or [])
    flagged_ports = [p for p in ports if p["risk"] in ("critical", "high")]
    return _tpl("host_detail.html", {
        "request": request,
        "host": host,
        "ports": ports,
        "flagged_ports": flagged_ports,
    })


@app.delete("/hosts/{host_id}", response_class=HTMLResponse)
async def delete_host(host_id: str, db: AsyncSession = Depends(get_db)):
    await db.execute(delete(Host).where(Host.id == host_id))
    await db.commit()
    return HTMLResponse("")


@app.post("/hosts/{host_id}/tags", response_class=HTMLResponse)
async def add_host_tag(
    host_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    form = await request.form()
    tag  = (form.get("tag") or "").strip()[:40]
    if not tag:
        return HTMLResponse("")
    host = await db.get(Host, host_id)
    if not host:
        return HTMLResponse("Not found", status_code=404)
    current = list(host.tags or [])
    if tag not in current:
        current.append(tag)
        host.tags = current
        await db.commit()
    hosts_result = await db.execute(select(Host))
    return templates.TemplateResponse("partials/host_both_views.html", {
        "request":   request,
        "hosts":     hosts_result.scalars().all(),
        "new_cutoff": datetime.now() - timedelta(hours=24),
    })


@app.delete("/hosts/{host_id}/tags/{tag}", response_class=HTMLResponse)
async def remove_host_tag(
    host_id: str,
    tag: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    host = await db.get(Host, host_id)
    if not host:
        return HTMLResponse("Not found", status_code=404)
    host.tags = [t for t in (host.tags or []) if t != tag]
    await db.commit()
    hosts_result = await db.execute(select(Host))
    return templates.TemplateResponse("partials/host_both_views.html", {
        "request":   request,
        "hosts":     hosts_result.scalars().all(),
        "new_cutoff": datetime.now() - timedelta(hours=24),
    })


@app.post("/domains/{domain_id}/rescan", response_class=HTMLResponse)
async def rescan_domain(
    domain_id: str,
    request: Request,
    background_tasks: BackgroundTasks = BackgroundTasks(),
    db: AsyncSession = Depends(get_db),
):
    domain = await db.get(Domain, domain_id)
    if domain:
        background_tasks.add_task(_scan_and_store, domain.hostname)
    return HTMLResponse('<div class="toast">Rescan started...</div>')


@app.post("/domains/rescan-all", response_class=HTMLResponse)
async def rescan_all_domains(
    request: Request,
    background_tasks: BackgroundTasks = BackgroundTasks(),
    db: AsyncSession = Depends(get_db),
):
    result  = await db.execute(select(Domain))
    domains = result.scalars().all()
    for domain in domains:
        background_tasks.add_task(_scan_and_store, domain.hostname)
    n = len(domains)
    return HTMLResponse(
        f'<div class="toast">Rescanning {n} domain{"s" if n != 1 else ""}…</div>',
        headers={"HX-Trigger": "domainAdded"},
    )


# ── Settings ───────────────────────────────────────────────────────────────────

@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    env_locked = bool(_ENV_USERNAME and _ENV_PASSWORD)
    lan_job    = scheduler.get_job("lan_autodiscovery")
    digest_job = scheduler.get_job("weekly_digest")
    return _tpl("settings.html", {
        "request":          request,
        "current_username": _ENV_USERNAME if env_locked else _auth["username"],
        "env_locked":       env_locked,
        "discovery_cidr":   _discovery_cidr,
        "lan_scan_time":    _lan_scan_time,
        "lan_scan_days":    _lan_scan_days.split(",") if _lan_scan_days else [],
        "lan_next_run":     lan_job.next_run_time if lan_job else None,
        "smtp_host":        _email_cfg.get("host", ""),
        "smtp_port":        _email_cfg.get("port", "587"),
        "smtp_user":        _email_cfg.get("user", ""),
        "smtp_from":        _email_cfg.get("from_addr", ""),
        "smtp_tls":         _email_cfg.get("tls", "starttls"),
        "smtp_password_set": bool(_email_cfg.get("password")),
        "email_recipient":       _email_recipient,
        "email_alerts_enabled":  _email_alerts_enabled,
        "email_digest_enabled":  _email_digest_enabled,
        "digest_day":            _digest_day,
        "digest_time":           _digest_time,
        "digest_next_run":       digest_job.next_run_time if digest_job else None,
        "share_url":        _build_share_url(),
        "base_url":         _base_url,
        "detected_url":     _detect_server_url(),
        "hibp_api_key_set":    bool(_hibp_api_key),
        "wpscan_api_key_set":  bool(_wpscan_api_key),
        "dns_servers":         _dns_servers,
    })


@app.post("/settings/license", response_class=HTMLResponse)
async def update_license(
    request: Request,
    license_key: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    info = verify_license_key(license_key.strip())
    if info.status == LicenseStatus.INVALID:
        return HTMLResponse(
            f'<div class="toast error">Invalid license key: {info.error}</div>'
        )
    if info.status == LicenseStatus.EXPIRED:
        return HTMLResponse(
            '<div class="toast error">License key has expired. Please contact us for a new key.</div>'
        )
    await _save_license(db, license_key.strip())
    plan_label = info.plan.upper()
    return HTMLResponse(
        f'<div class="toast">License activated — {plan_label} plan valid until {info.expires}.</div>',
        headers={"HX-Trigger": "licenseUpdated"},
    )


@app.delete("/settings/license", response_class=HTMLResponse)
async def remove_license(db: AsyncSession = Depends(get_db)):
    await _save_license(db, "")
    return HTMLResponse(
        '<div class="toast">License removed — reverted to Free tier.</div>',
        headers={"HX-Trigger": "licenseUpdated"},
    )


@app.post("/settings/credentials", response_class=HTMLResponse)
async def update_credentials(
    request: Request,
    current_password: str = Form(...),
    new_username:     str = Form(...),
    new_password:     str = Form(...),
    confirm_password: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    if _ENV_USERNAME and _ENV_PASSWORD:
        return HTMLResponse('<div class="toast error">Credentials are set via environment variables and cannot be changed here.</div>')

    if not verify_password(current_password, _auth["password_hash"]):
        return HTMLResponse('<div class="toast error">Current password is incorrect.</div>')

    if new_password != confirm_password:
        return HTMLResponse('<div class="toast error">New passwords do not match.</div>')

    if len(new_password) < 8:
        return HTMLResponse('<div class="toast error">Password must be at least 8 characters.</div>')

    new_hash = hash_password(new_password)

    # update DB
    for key, value in [("auth_username", new_username), ("auth_password_hash", new_hash)]:
        result = await db.execute(select(Setting).where(Setting.key == key))
        row = result.scalar_one_or_none()
        if row:
            row.value = value
        else:
            db.add(Setting(key=key, value=value))
    await db.commit()

    # update in-memory cache
    _auth["username"]      = new_username
    _auth["password_hash"] = new_hash

    return HTMLResponse('<div class="toast">Credentials updated. Use new details on next login.</div>')


# ── Email settings ────────────────────────────────────────────────────────────

@app.post("/settings/email", response_class=HTMLResponse)
async def update_email_settings(
    smtp_host:     str = Form(default=""),
    smtp_port:     str = Form(default="587"),
    smtp_user:     str = Form(default=""),
    smtp_password: str = Form(default=""),
    smtp_from:     str = Form(default=""),
    smtp_tls:      str = Form(default="starttls"),
    email_recipient:       str  = Form(default=""),
    email_alerts_enabled:  str  = Form(default=""),
    email_digest_enabled:  str  = Form(default=""),
    digest_day:            str  = Form(default="mon"),
    digest_time:           str  = Form(default="08:00"),
):
    global _email_cfg, _email_recipient, _email_alerts_enabled
    global _email_digest_enabled, _digest_day, _digest_time

    # Keep existing password if field left blank
    password = smtp_password.strip() or _email_cfg.get("password", "")

    _email_cfg = {
        "host":      smtp_host.strip(),
        "port":      smtp_port.strip() or "587",
        "user":      smtp_user.strip(),
        "password":  password,
        "from_addr": smtp_from.strip(),
        "tls":       smtp_tls,
    }
    _email_recipient      = email_recipient.strip()
    _email_alerts_enabled = email_alerts_enabled == "true"
    _email_digest_enabled = email_digest_enabled == "true"
    _digest_day           = digest_day
    _digest_time          = digest_time or "08:00"

    saves = [
        ("smtp_host",             _email_cfg["host"]),
        ("smtp_port",             _email_cfg["port"]),
        ("smtp_user",             _email_cfg["user"]),
        ("smtp_password",         password),
        ("smtp_from",             _email_cfg["from_addr"]),
        ("smtp_tls",              _email_cfg["tls"]),
        ("email_recipient",       _email_recipient),
        ("email_alerts_enabled",  "true" if _email_alerts_enabled else "false"),
        ("email_digest_enabled",  "true" if _email_digest_enabled else "false"),
        ("digest_day",            _digest_day),
        ("digest_time",           _digest_time),
    ]
    for key, val in saves:
        asyncio.create_task(_save_setting(key, val))

    _apply_digest_schedule()

    job = scheduler.get_job("weekly_digest")
    if job and job.next_run_time:
        nrt = job.next_run_time.strftime("%a %d %b %Y at %H:%M %Z")
        msg = f'<div class="toast">Email settings saved — next digest {nrt}.</div>'
    else:
        msg = '<div class="toast">Email settings saved.</div>'
    return HTMLResponse(msg)


@app.post("/settings/email/test", response_class=HTMLResponse)
async def send_test_email():
    if not _email_cfg.get("host"):
        return HTMLResponse('<div class="toast error">Configure SMTP settings first.</div>')
    if not _email_recipient:
        return HTMLResponse('<div class="toast error">Set a recipient email address first.</div>')
    from mailer.sender import send_email
    try:
        html = "<p style='font-family:sans-serif'><strong>TipOff</strong> — test email. Your SMTP settings are working correctly.</p>"
        await send_email(_email_cfg, _email_recipient, "TipOff — test email", html)
        return HTMLResponse(f'<div class="toast">Test email sent to {_email_recipient}.</div>')
    except Exception as e:
        return HTMLResponse(f'<div class="toast error">Send failed: {e}</div>')


# ── Discovery schedule settings ───────────────────────────────────────────────

@app.post("/settings/discovery", response_class=HTMLResponse)
async def update_discovery_schedule(
    cidr: str = Form(default=""),
    time: str = Form(default="03:00"),
    days: list[str] = Form(default=[]),
):
    global _discovery_cidr, _lan_scan_time, _lan_scan_days
    _discovery_cidr = cidr.strip()
    _lan_scan_time  = time.strip() or "03:00"
    _lan_scan_days  = ",".join(days)

    asyncio.create_task(_save_setting("discovery_cidr", _discovery_cidr))
    asyncio.create_task(_save_setting("lan_scan_time",  _lan_scan_time))
    asyncio.create_task(_save_setting("lan_scan_days",  _lan_scan_days))

    _apply_lan_schedule()

    job = scheduler.get_job("lan_autodiscovery")
    if job and job.next_run_time:
        nrt = job.next_run_time.strftime("%a %d %b %Y at %H:%M %Z")
        msg = f'<div class="toast">Schedule saved — next scan {nrt}.</div>'
    elif _discovery_cidr and _lan_scan_days:
        msg = '<div class="toast">Schedule saved.</div>'
    else:
        msg = '<div class="toast">Auto-discovery disabled — set a CIDR and select at least one day to enable.</div>'

    return HTMLResponse(msg)


# ── Shareable read-only link ──────────────────────────────────────────────────

@app.post("/settings/readonly/generate", response_class=HTMLResponse)
async def generate_readonly_link(base_url: str = Form(default="")):
    global _readonly_token, _base_url
    _readonly_token = secrets.token_urlsafe(24)
    _base_url = base_url.strip().rstrip("/")
    asyncio.create_task(_save_setting("readonly_token", _readonly_token))
    asyncio.create_task(_save_setting("base_url", _base_url))
    share_url = _build_share_url()
    return HTMLResponse(_render_share_link_html(share_url))


@app.delete("/settings/readonly", response_class=HTMLResponse)
async def revoke_readonly_link():
    global _readonly_token
    _readonly_token = ""
    asyncio.create_task(_save_setting("readonly_token", ""))
    return HTMLResponse('<p class="muted" style="margin:0">No active link. Generate one above.</p>')


def _render_share_link_html(share_url: str) -> str:
    safe = share_url.replace("'", "&#39;")
    return (
        f'<div class="share-link-box">'
        f'<span class="share-link-url">{safe}</span>'
        f'<button type="button" class="btn-copy" '
        f"onclick=\"navigator.clipboard.writeText('{safe}').then(()=>{{this.textContent='Copied!';setTimeout(()=>this.textContent='Copy',2000)}})\">Copy</button>"
        f'</div>'
        f'<p class="field-hint" style="margin-top:.4rem">Anyone on the same network with this link gets read-only dashboard access — no login required.</p>'
    )


# ── Breach monitoring routes ─────────────────────────────────────────────────

@app.get("/partials/breach/emails", response_class=HTMLResponse)
async def partials_breach_emails(request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(MonitoredEmail))
    emails = result.scalars().all()
    for me in emails:
        me._breaches_list = json.loads(me.breaches) if me.breaches else []
        me._lc_breaches_list = json.loads(me.lc_breaches) if me.lc_breaches else []
    return _tpl("partials/breach_emails.html", {
        "request": request,
        "emails": emails,
        "hibp_configured": bool(_hibp_api_key),
    })


@app.post("/breach/emails", response_class=HTMLResponse)
async def add_monitored_email(
    request: Request,
    email: str = Form(),
    db: AsyncSession = Depends(get_db),
):
    email = email.strip().lower()
    if not email or "@" not in email:
        return HTMLResponse('<div class="toast error">Enter a valid email address.</div>',
                            headers={"HX-Reswap": "none"})
    existing = await db.execute(select(MonitoredEmail).where(MonitoredEmail.email == email))
    if existing.scalar_one_or_none():
        return HTMLResponse('<div class="toast error">Already monitoring that address.</div>',
                            headers={"HX-Reswap": "none"})
    db.add(MonitoredEmail(email=email))
    await db.commit()
    result = await db.execute(select(MonitoredEmail))
    emails = result.scalars().all()
    for me in emails:
        me._breaches_list = json.loads(me.breaches) if me.breaches else []
        me._lc_breaches_list = json.loads(me.lc_breaches) if me.lc_breaches else []
    return _tpl("partials/breach_emails.html", {
        "request": request,
        "emails": emails,
        "hibp_configured": bool(_hibp_api_key),
    })


@app.delete("/breach/emails/{email_id}", response_class=HTMLResponse)
async def delete_monitored_email(
    email_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    await db.execute(delete(MonitoredEmail).where(MonitoredEmail.id == email_id))
    await db.commit()
    result = await db.execute(select(MonitoredEmail))
    emails = result.scalars().all()
    for me in emails:
        me._breaches_list = json.loads(me.breaches) if me.breaches else []
        me._lc_breaches_list = json.loads(me.lc_breaches) if me.lc_breaches else []
    return _tpl("partials/breach_emails.html", {
        "request": request,
        "emails": emails,
        "hibp_configured": bool(_hibp_api_key),
    })


@app.post("/breach/emails/{email_id}/ack/{source}", response_class=HTMLResponse)
async def ack_breach(email_id: str, source: str, request: Request, ack_note: str = Form(""), db: AsyncSession = Depends(get_db)):
    me = await db.get(MonitoredEmail, email_id)
    if not me:
        return HTMLResponse("Not found", status_code=404)
    if source == "hibp":
        me.hibp_acked = True
        me.hibp_ack_at = datetime.now(timezone.utc)
        me.hibp_ack_note = ack_note.strip()
    elif source == "lc":
        me.lc_acked = True
        me.lc_ack_at = datetime.now(timezone.utc)
        me.lc_ack_note = ack_note.strip()
    await db.commit()
    result = await db.execute(select(MonitoredEmail))
    emails = result.scalars().all()
    for e in emails:
        e._breaches_list = json.loads(e.breaches) if e.breaches else []
        e._lc_breaches_list = json.loads(e.lc_breaches) if e.lc_breaches else []
    return _tpl("partials/breach_emails.html", {"request": request, "emails": emails, "hibp_configured": bool(_hibp_api_key)})


@app.delete("/breach/emails/{email_id}/ack/{source}", response_class=HTMLResponse)
async def unack_breach(email_id: str, source: str, request: Request, db: AsyncSession = Depends(get_db)):
    me = await db.get(MonitoredEmail, email_id)
    if not me:
        return HTMLResponse("Not found", status_code=404)
    if source == "hibp":
        me.hibp_acked = False
        me.hibp_ack_at = None
        me.hibp_ack_note = None
    elif source == "lc":
        me.lc_acked = False
        me.lc_ack_at = None
        me.lc_ack_note = None
    await db.commit()
    result = await db.execute(select(MonitoredEmail))
    emails = result.scalars().all()
    for e in emails:
        e._breaches_list = json.loads(e.breaches) if e.breaches else []
        e._lc_breaches_list = json.loads(e.lc_breaches) if e.lc_breaches else []
    return _tpl("partials/breach_emails.html", {"request": request, "emails": emails, "hibp_configured": bool(_hibp_api_key)})


@app.post("/breach/check", response_class=HTMLResponse)
async def trigger_breach_check():
    asyncio.create_task(_run_breach_checks())
    return HTMLResponse('<div class="toast">Breach check started — results will update shortly.</div>')


@app.post("/breach/passwords/check", response_class=HTMLResponse)
async def check_password(password: str = Form()):
    if not password:
        return HTMLResponse("")
    from scanner.checks.pwned_passwords import check_password_pwned
    try:
        count = await check_password_pwned(password)
        if count == 0:
            return HTMLResponse(
                '<p class="pwned-result pwned-safe">Not found in any known breach dumps.</p>'
            )
        return HTMLResponse(
            f'<p class="pwned-result pwned-danger">Found <strong>{count:,}</strong> time{"s" if count != 1 else ""} '
            f'in known breach dumps — this password should not be used.</p>'
        )
    except Exception as e:
        return HTMLResponse(
            f'<p class="pwned-result pwned-error">Check failed: {e}</p>'
        )


@app.post("/settings/dns", response_class=HTMLResponse)
async def save_dns_settings(dns_servers: str = Form(default="1.1.1.1, 8.8.8.8")):
    global _dns_servers
    from scanner import resolver as _res
    _dns_servers = dns_servers.strip() or "1.1.1.1, 8.8.8.8"
    asyncio.create_task(_save_setting("dns_servers", _dns_servers))
    _res.configure([s.strip() for s in _dns_servers.split(",")])
    return HTMLResponse('<div class="toast">DNS settings saved.</div>')


@app.post("/settings/hibp", response_class=HTMLResponse)
async def save_hibp_settings(hibp_api_key: str = Form(default="")):
    global _hibp_api_key
    _hibp_api_key = hibp_api_key.strip()
    asyncio.create_task(_save_setting("hibp_api_key", _hibp_api_key))
    return HTMLResponse('<div class="toast">HIBP settings saved.</div>')


@app.post("/settings/wpscan", response_class=HTMLResponse)
async def save_wpscan_settings(wpscan_api_key: str = Form(default="")):
    global _wpscan_api_key
    _wpscan_api_key = wpscan_api_key.strip()
    asyncio.create_task(_save_setting("wpscan_api_key", _wpscan_api_key))
    return HTMLResponse('<div class="toast">WPScan settings saved.</div>')


# ── PDF Report ────────────────────────────────────────────────────────────────

@app.get("/report/pdf")
async def download_pdf_report(request: Request, db: AsyncSession = Depends(get_db)):
    if not _license.has_feature("pdf"):
        return HTMLResponse(
            "<p style='font-family:sans-serif;padding:2rem'>PDF reports require a TipOff Pro licence. "
            "<a href='/settings#license'>Activate your key →</a></p>",
            status_code=403,
        )

    from weasyprint import HTML as WeasyHTML
    from sqlalchemy import func as _func
    import asyncio

    # Domains
    domains_result = await db.execute(select(Domain))
    domains = domains_result.scalars().all()
    domain_data = []
    domain_passes = 0
    for d in domains:
        scans = await db.execute(select(ScanResult).where(ScanResult.domain_id == d.id))
        results = scans.scalars().all()
        score = _score_from_rows(results)
        if score is not None and score >= 50:
            domain_passes += 1
        domain_data.append({"domain": d, "score": score, "results": results})

    # Hosts
    hosts_result = await db.execute(select(Host))
    hosts = hosts_result.scalars().all()
    flagged_count = sum(1 for h in hosts if h.flagged and not h.acknowledged)
    acked_count   = sum(1 for h in hosts if h.flagged and h.acknowledged)

    # Monitors + their most recent check
    monitors_result = await db.execute(select(Monitor).where(Monitor.enabled == True))
    monitors = monitors_result.scalars().all()
    if monitors:
        subq = (
            select(UptimeCheck.monitor_id, _func.max(UptimeCheck.checked_at).label("max_at"))
            .where(UptimeCheck.monitor_id.isnot(None))
            .group_by(UptimeCheck.monitor_id)
            .subquery()
        )
        last_checks_res = await db.execute(
            select(UptimeCheck)
            .join(subq, (UptimeCheck.monitor_id == subq.c.monitor_id) &
                        (UptimeCheck.checked_at == subq.c.max_at))
        )
        last_checks = {uc.monitor_id: uc for uc in last_checks_res.scalars().all()}
    else:
        last_checks = {}

    monitor_data = []
    for mon in monitors:
        lc = last_checks.get(mon.id)
        monitor_data.append({
            "monitor":     mon,
            "is_up":       lc.is_up if lc else None,
            "response_ms": lc.response_ms if lc else None,
            "checked_at":  lc.checked_at if lc else None,
        })
    monitors_up = sum(1 for m in monitor_data if m["is_up"] is True)

    # Breach monitoring
    emails_result = await db.execute(select(MonitoredEmail))
    raw_emails = emails_result.scalars().all()
    monitored_emails = []
    for e in raw_emails:
        breach_list = []
        if e.breaches:
            try:
                breach_list = json.loads(e.breaches)
            except Exception:
                pass
        monitored_emails.append({"email": e, "breaches": breach_list})
    emails_breached = sum(1 for m in monitored_emails if m["email"].status == "breached")

    # CE Readiness
    ce_answers = await _load_ce_answers()
    ce_scores  = _ce_score(ce_answers)

    # WordPress sites (from domains and hosts already loaded)
    wp_sites = []
    for d in domain_data:
        dom = d["domain"]
        if dom.is_wordpress:
            wp_sites.append({
                "label":        dom.hostname,
                "version":      dom.wp_version,
                "scan_at":      dom.wp_scan_at,
                "scan_results": dom.wp_scan_results or {},
            })
    for h in hosts:
        if h.is_wordpress:
            wp_sites.append({
                "label":        h.wp_url or h.hostname or h.ip,
                "version":      h.wp_version,
                "scan_at":      h.wp_scan_at,
                "scan_results": h.wp_scan_results or {},
            })

    html_str = templates.env.get_template("pdf/report.html").render({
        "generated_at":     datetime.now(timezone.utc).strftime("%d %B %Y at %H:%M UTC"),
        "domains":          domain_data,
        "domain_passes":    domain_passes,
        "hosts":            hosts,
        "flagged_count":    flagged_count,
        "acked_count":      acked_count,
        "port_info":        PORT_INFO,
        "license":          _license,
        "monitors":         monitor_data,
        "monitors_up":      monitors_up,
        "monitored_emails": monitored_emails,
        "emails_breached":  emails_breached,
        "ce_scores":        ce_scores,
        "ce_areas":         CE_AREAS,
        "wp_sites":         wp_sites,
    })

    loop = asyncio.get_event_loop()
    pdf_bytes = await loop.run_in_executor(
        None,
        lambda: WeasyHTML(string=html_str).write_pdf()
    )

    filename = f"tipoff-report-{datetime.now(timezone.utc).strftime('%Y%m%d')}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── Helpers ────────────────────────────────────────────────────────────────────

async def _run_discovery_job(job_id: str, cidr: str):
    from db.database import SessionLocal
    job = _discovery_jobs[job_id]
    try:
        cidrs = [c.strip() for c in cidr.split(",") if c.strip()]
        seen: dict[str, dict] = {}
        for idx, c in enumerate(cidrs):
            if len(cidrs) > 1:
                job["stage"] = f"Scanning {c} ({idx + 1}/{len(cidrs)})…"
            for h in await discover_network(c, progress=job):
                seen[h["ip"]] = h
        hosts = list(seen.values())
        job["stage"] = "Saving results…"
        port_changes: list[dict] = []
        async with SessionLocal() as db:
            for h in hosts:
                existing = await db.execute(select(Host).where(Host.ip == h["ip"]))
                host_row = existing.scalar_one_or_none()
                if host_row:
                    old_ports = {p["port"] for p in (host_row.open_ports or [])}
                    new_ports = {p["port"] for p in h.get("open_ports", [])}
                    appeared   = new_ports - old_ports
                    disappeared = old_ports - new_ports
                    if appeared or disappeared:
                        label = host_row.hostname or host_row.ip
                        port_changes.append({
                            "host":        label,
                            "ip":          host_row.ip,
                            "appeared":    sorted(appeared),
                            "disappeared": sorted(disappeared),
                        })
                    host_row.hostname   = h.get("hostname", "")
                    host_row.mac        = h.get("mac", "")
                    host_row.vendor     = h.get("vendor", "")
                    host_row.os_guess   = h.get("os_guess", "")
                    host_row.open_ports = h.get("open_ports", [])
                    host_row.flagged    = h.get("flagged", False)
                    host_row.last_seen  = datetime.now(timezone.utc)
                    host_row.is_vm      = h.get("is_vm", False)
                else:
                    db.add(Host(
                        ip=h["ip"],
                        hostname=h.get("hostname", ""),
                        mac=h.get("mac", ""),
                        vendor=h.get("vendor", ""),
                        os_guess=h.get("os_guess", ""),
                        open_ports=h.get("open_ports", []),
                        flagged=h.get("flagged", False),
                        is_vm=h.get("is_vm", False),
                    ))
            await db.commit()
        for change in port_changes:
            if change["appeared"]:
                await _fire_webhooks("port_open", {
                    "name":   change["host"],
                    "status": f"new port(s) open: {', '.join(str(p) for p in change['appeared'])}",
                })
            if change["disappeared"]:
                await _fire_webhooks("port_closed", {
                    "name":   change["host"],
                    "status": f"port(s) closed: {', '.join(str(p) for p in change['disappeared'])}",
                })
        if port_changes:
            await _send_port_change_alert(port_changes)

        # IPv6 neighbor discovery — match by MAC to enrich existing hosts
        job["stage"] = "Discovering IPv6 neighbors…"
        try:
            ipv6_neighbors = await discover_ipv6_neighbors()
            if ipv6_neighbors:
                async with SessionLocal() as db:
                    all_hosts = (await db.execute(select(Host))).scalars().all()
                    mac_to_host = {h.mac.lower(): h for h in all_hosts if h.mac}
                    for neighbor in ipv6_neighbors:
                        host_row = mac_to_host.get(neighbor["mac"].lower())
                        if host_row:
                            addrs = list(host_row.ipv6_addresses or [])
                            if neighbor["ipv6"] not in addrs:
                                addrs.append(neighbor["ipv6"])
                                host_row.ipv6_addresses = addrs
                    await db.commit()
        except Exception as e:
            print(f"IPv6 discovery warning: {e}")

        job["status"] = "done"
        await _check_and_send_alerts()
    except Exception as e:
        job["status"] = "error"
        job["error"] = str(e)
        print(f"Discovery job {job_id} failed: {e}")


async def _scan_and_store(hostname: str):
    from db.database import SessionLocal
    async with SessionLocal() as db:
        result = await db.execute(select(Domain).where(Domain.hostname == hostname))
        domain = result.scalar_one_or_none()
        if not domain:
            return
        try:
            results = await scan_domain(hostname)
            await db.execute(delete(ScanResult).where(
                ScanResult.domain_id == domain.id,
                ScanResult.check_id != "wordpress_vulns",
            ))
            for r in results:
                db.add(ScanResult(
                    domain_id=domain.id,
                    check_id=r.check_id,
                    status=r.status.value,
                    title=r.title,
                    detail=r.detail,
                    remediation=r.remediation,
                    score_impact=r.score_impact,
                    raw=r.raw,
                ))
            domain.last_scan_at = datetime.utcnow()
            domain.next_scan_at = datetime.utcnow() + timedelta(hours=24)
            await db.commit()
        except Exception as e:
            print(f"Background scan failed for {hostname}: {e}")


# ── Cyber Essentials ──────────────────────────────────────────────────────────

from ce.questions import CE_AREAS, CE_QUESTIONS, score_answers as _ce_score


async def _load_ce_answers() -> dict:
    from db.database import SessionLocal
    async with SessionLocal() as db:
        r = await db.execute(select(Setting).where(Setting.key == "ce_answers"))
        row = r.scalar_one_or_none()
        if row and row.value:
            try:
                return json.loads(row.value)
            except Exception:
                pass
    return {}


async def _save_ce_answers(answers: dict):
    await _save_setting("ce_answers", json.dumps(answers))


async def _get_scan_evidence(db: AsyncSession) -> dict:
    """Collect scan findings that can inform CE auto-hints."""
    evidence = {"dangerous_ports": [], "ssl_issues": []}
    hosts_result = await db.execute(select(Host).where(Host.flagged == True))
    for h in hosts_result.scalars().all():
        for p in (h.open_ports or []):
            if p.get("dangerous"):
                evidence["dangerous_ports"].append(
                    f"{h.ip} — port {p['port']}/{p.get('service','')}"
                )
    domains_result = await db.execute(select(Domain))
    for d in domains_result.scalars().all():
        scans = await db.execute(
            select(ScanResult).where(
                ScanResult.domain_id == d.id,
                ScanResult.status == "fail",
                ScanResult.check_id.in_(["ssl_valid", "ssl_expiry", "tls_version", "https_redirect"]),
            )
        )
        for r in scans.scalars().all():
            evidence["ssl_issues"].append(f"{d.hostname} — {r.title}")
    return evidence


@app.get("/ce", response_class=HTMLResponse)
async def ce_page(request: Request, db: AsyncSession = Depends(get_db)):
    answers  = await _load_ce_answers()
    scores   = _ce_score(answers)
    evidence = await _get_scan_evidence(db)
    return _tpl("ce.html", {
        "request":  request,
        "areas":    CE_AREAS,
        "answers":  answers,
        "scores":   scores,
        "evidence": evidence,
    })


@app.post("/ce/answer", response_class=HTMLResponse)
async def save_ce_answer(
    question_id: str = Form(),
    answer:      str = Form(default=""),
    note:        str = Form(default=""),
):
    answers = await _load_ce_answers()
    if answer in ("yes", "no", "na"):
        answers[question_id] = {"answer": answer, "note": note.strip()}
    elif question_id in answers and answer == "":
        answers[question_id]["note"] = note.strip()
    await _save_ce_answers(answers)
    scores = _ce_score(answers)
    q      = CE_QUESTIONS.get(question_id, {})
    area_id = q.get("area_id", "")
    s = scores["areas"].get(area_id, {})
    badge_cls = "pass" if s.get("ready") else ("warn" if s.get("passed", 0) > 0 else "fail")
    overall_cls = "pass" if scores["ready"] else ("warn" if scores["pct"] >= 50 else "fail")
    return HTMLResponse(
        f'<span id="area-score-{area_id}" class="badge {badge_cls}">'
        f'{s.get("passed",0)}/{s.get("total",0)}</span>'
        f'<span id="overall-score" class="score-large score-{"good" if scores["pct"]>=80 else ("ok" if scores["pct"]>=50 else "bad")}"'
        f' hx-swap-oob="true">{scores["pct"]}%</span>'
    )


@app.post("/ce/note", response_class=HTMLResponse)
async def save_ce_note(question_id: str = Form(), note: str = Form(default="")):
    answers = await _load_ce_answers()
    if question_id in answers:
        answers[question_id]["note"] = note.strip()
        await _save_ce_answers(answers)
    return HTMLResponse("")


# ── Uptime / Status Page ───────────────────────────────────────────────────────

@app.post("/domains/{domain_id}/public-status", response_class=HTMLResponse)
async def toggle_public_status(domain_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    domain = await db.get(Domain, domain_id)
    if not domain:
        return HTMLResponse("")
    domain.public_status = not domain.public_status
    await db.commit()
    enabled = domain.public_status
    return HTMLResponse(
        f'<button hx-post="/domains/{domain_id}/public-status" hx-swap="outerHTML" '
        f'class="btn-sm {"btn-active" if enabled else "btn-secondary"}" '
        f'title="{"Remove from" if enabled else "Add to"} public status page">'
        f'{"Public ✓" if enabled else "Public"}</button>'
    )


@app.get("/status", response_class=HTMLResponse)
async def status_page(request: Request, db: AsyncSession = Depends(get_db)):
    from datetime import timedelta
    from sqlalchemy import and_
    now = datetime.now(timezone.utc)
    days = 90

    domains_result = await db.execute(select(Domain).where(Domain.public_status == True))
    domains = domains_result.scalars().all()

    items = []
    for domain in domains:
        cutoff = now - timedelta(days=days)
        checks_result = await db.execute(
            select(UptimeCheck).where(
                UptimeCheck.domain_id == domain.id,
                UptimeCheck.checked_at >= cutoff,
            ).order_by(UptimeCheck.checked_at.asc())
        )
        checks = checks_result.scalars().all()

        # Build daily buckets for the grid
        daily = {}
        for c in checks:
            day_key = c.checked_at.date()
            if day_key not in daily:
                daily[day_key] = {"up": 0, "total": 0}
            daily[day_key]["total"] += 1
            if c.is_up:
                daily[day_key]["up"] += 1

        grid = []
        for i in range(days):
            day = (now - timedelta(days=days - 1 - i)).date()
            if day in daily:
                b = daily[day]
                pct = b["up"] / b["total"] if b["total"] else 0
                state = "up" if pct >= 0.8 else ("degraded" if pct >= 0.4 else "down")
            else:
                state = "nodata"
            grid.append({"date": day.strftime("%d %b %Y"), "state": state})

        total_checks = sum(d["total"] for d in daily.values())
        up_checks    = sum(d["up"] for d in daily.values())
        uptime_pct   = round(up_checks / total_checks * 100, 2) if total_checks else None

        # Current status = most recent check
        latest_result = await db.execute(
            select(UptimeCheck).where(UptimeCheck.domain_id == domain.id)
            .order_by(UptimeCheck.checked_at.desc())
        )
        latest = latest_result.scalars().first()
        current_up = latest.is_up if latest else None

        items.append({
            "label":      domain.hostname,
            "sublabel":   None,
            "domain":     domain,
            "grid":       grid,
            "uptime_pct": uptime_pct,
            "current_up": current_up,
        })

    # ── Custom monitors ─────────────────────────────────────────────────────
    monitors_result = await db.execute(select(Monitor).where(
        Monitor.public_status == True, Monitor.enabled == True
    ))
    for mon in monitors_result.scalars().all():
        cutoff = now - timedelta(days=days)
        checks_result = await db.execute(
            select(UptimeCheck).where(
                UptimeCheck.monitor_id == mon.id,
                UptimeCheck.checked_at >= cutoff,
            ).order_by(UptimeCheck.checked_at.asc())
        )
        checks = checks_result.scalars().all()
        daily = {}
        for c in checks:
            day_key = c.checked_at.date()
            if day_key not in daily:
                daily[day_key] = {"up": 0, "total": 0}
            daily[day_key]["total"] += 1
            if c.is_up:
                daily[day_key]["up"] += 1
        grid = []
        for i in range(days):
            day = (now - timedelta(days=days - 1 - i)).date()
            if day in daily:
                b = daily[day]
                pct = b["up"] / b["total"] if b["total"] else 0
                state = "up" if pct >= 0.8 else ("degraded" if pct >= 0.4 else "down")
            else:
                state = "nodata"
            grid.append({"date": day.strftime("%d %b %Y"), "state": state})
        total_checks = sum(d["total"] for d in daily.values())
        up_checks    = sum(d["up"] for d in daily.values())
        uptime_pct   = round(up_checks / total_checks * 100, 2) if total_checks else None
        latest_result = await db.execute(
            select(UptimeCheck).where(UptimeCheck.monitor_id == mon.id)
            .order_by(UptimeCheck.checked_at.desc())
        )
        latest = latest_result.scalars().first()
        items.append({
            "label":      f"{mon.name}",
            "sublabel":   f"{mon.host}:{mon.port} ({mon.protocol.upper()})",
            "grid":       grid,
            "uptime_pct": uptime_pct,
            "current_up": latest.is_up if latest else None,
        })

    all_up = all(i["current_up"] for i in items if i["current_up"] is not None)
    return _tpl("status.html", {
        "request":  request,
        "items":    items,
        "all_up":   all_up,
        "readonly": True,
    })


# ── Custom Monitors ────────────────────────────────────────────────────────────

@app.get("/monitors", response_class=HTMLResponse)
async def monitors_page(request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Monitor).order_by(Monitor.added_at))
    monitors = result.scalars().all()

    # Attach latest check to each monitor
    items = []
    for mon in monitors:
        latest_result = await db.execute(
            select(UptimeCheck).where(UptimeCheck.monitor_id == mon.id)
            .order_by(UptimeCheck.checked_at.desc())
        )
        latest = latest_result.scalars().first()
        items.append({"monitor": mon, "latest": latest})

    return _tpl("monitors.html", {"request": request, "items": items})


@app.post("/monitors", response_class=HTMLResponse)
async def add_monitor(
    request: Request,
    name:            str = Form(),
    host:            str = Form(),
    port:            int = Form(),
    protocol:        str = Form(default="tcp"),
    expected_status: str = Form(default=""),
    db: AsyncSession = Depends(get_db),
):
    mon = Monitor(
        name=name.strip(),
        host=host.strip(),
        port=port,
        protocol=protocol,
        expected_status=expected_status.strip() or None,
    )
    db.add(mon)
    await db.commit()
    return HTMLResponse("", headers={"HX-Redirect": "/monitors"})


@app.delete("/monitors/{monitor_id}", response_class=HTMLResponse)
async def delete_monitor(monitor_id: str, db: AsyncSession = Depends(get_db)):
    mon = await db.get(Monitor, monitor_id)
    if mon:
        await db.execute(delete(UptimeCheck).where(UptimeCheck.monitor_id == monitor_id))
        await db.delete(mon)
        await db.commit()
    return HTMLResponse("")


@app.post("/monitors/{monitor_id}/toggle-enabled", response_class=HTMLResponse)
async def toggle_monitor_enabled(monitor_id: str, db: AsyncSession = Depends(get_db)):
    mon = await db.get(Monitor, monitor_id)
    if not mon:
        return HTMLResponse("")
    mon.enabled = not mon.enabled
    await db.commit()
    return HTMLResponse("", headers={"HX-Redirect": "/monitors"})


@app.post("/monitors/{monitor_id}/toggle-public", response_class=HTMLResponse)
async def toggle_monitor_public(monitor_id: str, db: AsyncSession = Depends(get_db)):
    mon = await db.get(Monitor, monitor_id)
    if not mon:
        return HTMLResponse("")
    mon.public_status = not mon.public_status
    await db.commit()
    return HTMLResponse("", headers={"HX-Redirect": "/monitors"})


# ── Webhooks ───────────────────────────────────────────────────────────────────

@app.get("/webhooks", response_class=HTMLResponse)
async def webhooks_page(request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Webhook).order_by(Webhook.added_at))
    webhooks = result.scalars().all()
    items = []
    for wh in webhooks:
        items.append({"webhook": wh, "events": json.loads(wh.events or "[]")})
    return _tpl("webhooks.html", {"request": request, "items": items})


@app.post("/webhooks", response_class=HTMLResponse)
async def add_webhook(
    request:      Request,
    name:         str  = Form(),
    url:          str  = Form(),
    webhook_type: str  = Form(default="json"),
    events:       list = Form(default=[]),
    db: AsyncSession = Depends(get_db),
):
    wh = Webhook(name=name.strip(), url=url.strip(),
                 webhook_type=webhook_type, events=json.dumps(events))
    db.add(wh)
    await db.commit()
    return HTMLResponse("", headers={"HX-Redirect": "/webhooks"})


@app.delete("/webhooks/{webhook_id}", response_class=HTMLResponse)
async def delete_webhook(webhook_id: str, db: AsyncSession = Depends(get_db)):
    wh = await db.get(Webhook, webhook_id)
    if wh:
        await db.delete(wh)
        await db.commit()
    return HTMLResponse("")


@app.post("/webhooks/{webhook_id}/toggle", response_class=HTMLResponse)
async def toggle_webhook(webhook_id: str, db: AsyncSession = Depends(get_db)):
    wh = await db.get(Webhook, webhook_id)
    if not wh:
        return HTMLResponse("")
    wh.enabled = not wh.enabled
    await db.commit()
    return HTMLResponse("", headers={"HX-Redirect": "/webhooks"})


@app.post("/webhooks/{webhook_id}/test", response_class=HTMLResponse)
async def test_webhook(webhook_id: str, db: AsyncSession = Depends(get_db)):
    wh = await db.get(Webhook, webhook_id)
    if not wh:
        return HTMLResponse("Not found", status_code=404)
    import httpx
    now  = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    body = f"{wh.name} — this is a test notification"
    msg  = f"TipOff • {body}"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            if wh.webhook_type == "ntfy":
                r = await client.post(
                    wh.url,
                    content=body.encode(),
                    headers={"Title": "TipOff", "Priority": "3", "Tags": "bell"},
                )
            elif wh.webhook_type == "matrix":
                txn_url = wh.url.replace("{txn_id}", str(uuid.uuid4()))
                r = await client.put(txn_url, json={
                    "msgtype": "m.text",
                    "body":    msg,
                })
            else:
                r = await client.post(wh.url, json={
                    "content":   msg,
                    "text":      msg,
                    "event":     "test",
                    "name":      wh.name,
                    "status":    "test",
                    "timestamp": now,
                })
        colour = "pass" if r.status_code < 300 else "fail"
        try:
            detail = r.json()
        except Exception:
            detail = r.text[:200]
        return HTMLResponse(
            f'<span class="badge {colour}" id="test-result-{webhook_id}" '
            f'title="{detail}">{r.status_code}</span> '
            f'<code style="font-size:11px;color:var(--muted)">{detail}</code>'
        )
    except Exception as e:
        return HTMLResponse(
            f'<span class="badge fail" id="test-result-{webhook_id}">Failed: {e}</span>'
        )
