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
    Domain, Host, ScanResult, Setting, MonitoredEmail,
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

from discovery.lan import discover_network, rescan_host as _rescan_host
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
    """Check all monitored emails against HIBP. Called from the hourly scheduler."""
    import asyncio as _asyncio
    from db.database import SessionLocal
    from scanner.checks.hibp_email import check_email_breaches
    async with SessionLocal() as db:
        result = await db.execute(select(MonitoredEmail))
        emails = result.scalars().all()
        for me in emails:
            result = await check_email_breaches(me.email, _hibp_api_key)
            me.status        = result["status"]
            me.breach_count  = result["count"]
            me.breaches      = json.dumps(result["breaches"])
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
        now = datetime.now(timezone.utc)
        result = await db.execute(
            select(Domain).where(Domain.next_scan_at <= now)
        )
        domains = result.scalars().all()
        for domain in domains:
            try:
                results = await scan_domain(domain.hostname)
                await db.execute(
                    delete(ScanResult).where(ScanResult.domain_id == domain.id)
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
    scheduler.start()
    _apply_lan_schedule()
    _apply_digest_schedule()
    asyncio.create_task(run_due_scans())
    yield
    scheduler.shutdown()


app = FastAPI(lifespan=lifespan)

@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    if request.url.path.startswith("/static"):
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

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, db: AsyncSession = Depends(get_db)):
    domains_result = await db.execute(select(Domain))
    domains = domains_result.scalars().all()

    domain_data = []
    for d in domains:
        scans = await db.execute(select(ScanResult).where(ScanResult.domain_id == d.id))
        results = scans.scalars().all()
        score = _score_from_rows(results)
        fails  = sum(1 for r in results if r.status == "fail")
        warns  = sum(1 for r in results if r.status == "warn")
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
        "host_total":      len(hosts),
        "host_flagged":    sum(1 for h in hosts if h.flagged and not h.acknowledged),
        "host_acked":      sum(1 for h in hosts if h.flagged and h.acknowledged),
        "breach_monitored": len(emails),
        "breach_count":     sum(1 for e in emails if e.status == "breached"),
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
        domain_data.append({
            "domain": d,
            "score": _score_from_rows(results),
            "fails": sum(1 for r in results if r.status == "fail"),
            "warns": sum(1 for r in results if r.status == "warn"),
            "results": results,
        })
    return templates.TemplateResponse("partials/domains_list.html", {
        "request": request,
        "domain_data": domain_data,
        "readonly": getattr(request.state, "readonly", False),
    })


@app.get("/domain/{domain_id}", response_class=HTMLResponse)
async def domain_detail(domain_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    domain = await db.get(Domain, domain_id)
    if not domain:
        return HTMLResponse("Not found", status_code=404)

    scans = await db.execute(
        select(ScanResult).where(ScanResult.domain_id == domain_id)
    )
    results = scans.scalars().all()
    fails  = [r for r in results if r.status == "fail"]
    warns  = [r for r in results if r.status == "warn"]
    passes = [r for r in results if r.status == "pass"]
    score  = _score_from_rows(results)

    return _tpl("domain_detail.html", {
        "request": request,
        "domain": domain,
        "fails": fails,
        "warns": warns,
        "passes": passes,
        "score": score,
    })


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
    return _tpl("host_detail.html", {
        "request": request,
        "host": host,
        "ports": ports,
        "flagged_ports": flagged_ports,
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
    return _tpl("partials/breach_emails.html", {
        "request": request,
        "emails": emails,
        "hibp_configured": bool(_hibp_api_key),
    })


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
    import asyncio

    # gather all data
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

    hosts_result = await db.execute(select(Host))
    hosts = hosts_result.scalars().all()
    flagged_count  = sum(1 for h in hosts if h.flagged and not h.acknowledged)
    acked_count    = sum(1 for h in hosts if h.flagged and h.acknowledged)

    html_str = templates.env.get_template("pdf/report.html").render({
        "generated_at":  datetime.now(timezone.utc).strftime("%d %B %Y at %H:%M UTC"),
        "domains":       domain_data,
        "domain_passes": domain_passes,
        "hosts":         hosts,
        "flagged_count": flagged_count,
        "acked_count":   acked_count,
        "port_info":     PORT_INFO,
        "license":       _license,
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
        async with SessionLocal() as db:
            for h in hosts:
                existing = await db.execute(select(Host).where(Host.ip == h["ip"]))
                host_row = existing.scalar_one_or_none()
                if host_row:
                    host_row.hostname   = h.get("hostname", "")
                    host_row.mac        = h.get("mac", "")
                    host_row.vendor     = h.get("vendor", "")
                    host_row.os_guess   = h.get("os_guess", "")
                    host_row.open_ports = h.get("open_ports", [])
                    host_row.flagged    = h.get("flagged", False)
                    host_row.last_seen  = datetime.now(timezone.utc)
                else:
                    db.add(Host(
                        ip=h["ip"],
                        hostname=h.get("hostname", ""),
                        mac=h.get("mac", ""),
                        vendor=h.get("vendor", ""),
                        os_guess=h.get("os_guess", ""),
                        open_ports=h.get("open_ports", []),
                        flagged=h.get("flagged", False),
                    ))
            await db.commit()
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
            await db.execute(delete(ScanResult).where(ScanResult.domain_id == domain.id))
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
            domain.last_scan_at = datetime.now(timezone.utc)
            domain.next_scan_at = datetime.now(timezone.utc) + timedelta(hours=24)
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
