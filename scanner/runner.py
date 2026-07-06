import asyncio
from datetime import datetime
from scanner.checks.ssl import check_ssl
from scanner.checks.dns import check_spf, check_dmarc, check_dkim, check_mx
from scanner.checks.http import check_headers
from scanner.checks.whois_check import check_domain_expiry, check_result_for_expiry
from scanner.models import CheckResult, Status


async def scan_domain(
    domain: str,
    monitor_web: bool = True,
    check_mail: bool = True,
    is_subdomain: bool = False,
    manual_expiry: datetime | None = None,
) -> tuple[list[CheckResult], bool | None]:
    """Run checks for a domain. Returns (results, has_mx).

    monitor_web=False skips SSL + HTTP header checks (no web server here).
    check_mail=False skips SPF/DMARC/DKIM entirely. When mail checks run,
    missing SPF/DMARC on a domain without MX records is softened to a
    low-impact warning, and DKIM (meaningless without mail) is skipped.

    is_subdomain=True skips WHOIS expiry entirely (only the registrable
    domain has one) and, if this subdomain has no MX of its own, skips
    mail checks too — spoofing protection for a name that never sends
    mail is the apex domain's job, not a false alarm here.

    manual_expiry substitutes for WHOIS when it can't return a date
    (registrar privacy, or a TLD like .au that doesn't publish one).
    """
    has_mx = await check_mx(domain) if check_mail else None
    run_mail = check_mail and not (is_subdomain and not has_mx)

    tasks = []
    if not is_subdomain:
        tasks.append(check_domain_expiry(domain))
    if monitor_web:
        tasks += [check_ssl(domain), check_headers(domain)]
    if run_mail:
        tasks += [check_spf(domain, has_mx), check_dmarc(domain, has_mx)]
        if has_mx:
            tasks.append(check_dkim(domain))

    task_groups = await asyncio.gather(*tasks, return_exceptions=True)

    flat: list[CheckResult] = []
    for result in task_groups:
        if isinstance(result, Exception):
            continue
        if isinstance(result, list):
            flat.extend(result)
        elif isinstance(result, CheckResult):
            flat.append(result)

    if not is_subdomain and manual_expiry is not None:
        for i, r in enumerate(flat):
            if r.check_id in ("domain_expiry_unknown", "domain_expiry_error"):
                flat[i] = check_result_for_expiry(manual_expiry, source="manual")
                break

    return flat, has_mx


def calculate_score(results: list[CheckResult]) -> int:
    max_deductible = sum(r.score_impact for r in results if r.score_impact > 0) or 1
    deducted = sum(
        r.score_impact for r in results
        if r.status in (Status.FAIL, Status.WARN)
    )
    # external scan = 60 points; questionnaire will add up to 40 later
    return max(0, 60 - int((deducted / max_deductible) * 60))
