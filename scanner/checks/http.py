import httpx
from scanner.models import CheckResult, Status

SECURITY_HEADERS = {
    "strict-transport-security": (
        "HSTS Missing",
        "Browsers aren't forced to use HTTPS — a downgrade attack could expose traffic.",
        "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        7,
    ),
    "x-frame-options": (
        "Clickjacking Protection Missing",
        "Your site could be embedded in a hidden iframe to trick users into clicking things.",
        "Add header: X-Frame-Options: DENY",
        5,
    ),
    "x-content-type-options": (
        "MIME Sniffing Protection Missing",
        "Browsers may misinterpret file types, enabling certain injection attacks.",
        "Add header: X-Content-Type-Options: nosniff",
        3,
    ),
    "content-security-policy": (
        "No Content Security Policy",
        "Without a CSP, XSS attacks have more room to execute.",
        "Add a Content-Security-Policy header. Start with: default-src 'self'",
        5,
    ),
}


async def check_headers(domain: str) -> list[CheckResult]:
    results = []
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
            resp = await client.get(f"https://{domain}")
            headers = {k.lower(): v for k, v in resp.headers.items()}

        for header, (title, detail, remediation, impact) in SECURITY_HEADERS.items():
            if header not in headers:
                results.append(CheckResult(
                    check_id=f"header_missing_{header.replace('-', '_')}",
                    status=Status.WARN,
                    title=title,
                    detail=detail,
                    remediation=remediation,
                    score_impact=impact,
                    raw={},
                ))
            else:
                results.append(CheckResult(
                    check_id=f"header_present_{header.replace('-', '_')}",
                    status=Status.PASS,
                    title=title.replace("Missing", "").replace("No ", "").strip() + " Header",
                    detail="Present.",
                    remediation="",
                    score_impact=0,
                    raw={"value": headers[header]},
                ))

        # HTTPS redirect check
        try:
            async with httpx.AsyncClient(follow_redirects=False, timeout=10) as client:
                http_resp = await client.get(f"http://{domain}")
            location = http_resp.headers.get("location", "")
            if http_resp.status_code not in (301, 302, 307, 308) or not location.startswith("https"):
                results.append(CheckResult(
                    check_id="no_https_redirect",
                    status=Status.FAIL,
                    title="HTTP Not Redirecting to HTTPS",
                    detail="Visiting the site over plain HTTP doesn't redirect to the secure version.",
                    remediation="Configure your web server to redirect all HTTP traffic to HTTPS.",
                    score_impact=8,
                    raw={"status_code": http_resp.status_code},
                ))
            else:
                results.append(CheckResult(
                    check_id="https_redirect_ok",
                    status=Status.PASS,
                    title="HTTPS Redirect",
                    detail="HTTP correctly redirects to HTTPS.",
                    remediation="",
                    score_impact=0,
                    raw={},
                ))
        except Exception:
            pass  # don't fail the whole check if HTTP redirect check errors

    except (httpx.ConnectError, httpx.TimeoutException):
        results.append(CheckResult(
            check_id="site_unreachable",
            status=Status.ERROR,
            title="Website Unreachable",
            detail=f"Could not connect to {domain}.",
            remediation="Check the domain is correct and the site is online.",
            score_impact=0,
            raw={},
        ))

    return results
