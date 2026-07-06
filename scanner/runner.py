import asyncio
from scanner.checks.ssl import check_ssl
from scanner.checks.dns import check_spf, check_dmarc, check_dkim, check_mx
from scanner.checks.http import check_headers
from scanner.checks.whois_check import check_domain_expiry
from scanner.models import CheckResult, Status


async def scan_domain(
    domain: str,
    monitor_web: bool = True,
    check_mail: bool = True,
) -> tuple[list[CheckResult], bool | None]:
    """Run checks for a domain. Returns (results, has_mx).

    monitor_web=False skips SSL + HTTP header checks (no web server here).
    check_mail=False skips SPF/DMARC/DKIM entirely. When mail checks run,
    missing SPF/DMARC on a domain without MX records is softened to a
    low-impact warning, and DKIM (meaningless without mail) is skipped.
    """
    has_mx = await check_mx(domain) if check_mail else None

    tasks = [check_domain_expiry(domain)]
    if monitor_web:
        tasks += [check_ssl(domain), check_headers(domain)]
    if check_mail:
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

    return flat, has_mx


def calculate_score(results: list[CheckResult]) -> int:
    max_deductible = sum(r.score_impact for r in results if r.score_impact > 0) or 1
    deducted = sum(
        r.score_impact for r in results
        if r.status in (Status.FAIL, Status.WARN)
    )
    # external scan = 60 points; questionnaire will add up to 40 later
    return max(0, 60 - int((deducted / max_deductible) * 60))
