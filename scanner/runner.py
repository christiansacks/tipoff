import asyncio
from scanner.checks.ssl import check_ssl
from scanner.checks.dns import check_spf, check_dmarc, check_dkim
from scanner.checks.http import check_headers
from scanner.checks.whois_check import check_domain_expiry
from scanner.models import CheckResult, Status


async def scan_domain(domain: str) -> list[CheckResult]:
    task_groups = await asyncio.gather(
        check_ssl(domain),
        check_spf(domain),
        check_dmarc(domain),
        check_dkim(domain),
        check_headers(domain),
        check_domain_expiry(domain),
        return_exceptions=True,
    )

    flat: list[CheckResult] = []
    for result in task_groups:
        if isinstance(result, Exception):
            continue
        if isinstance(result, list):
            flat.extend(result)
        elif isinstance(result, CheckResult):
            flat.append(result)

    return flat


def calculate_score(results: list[CheckResult]) -> int:
    max_deductible = sum(r.score_impact for r in results if r.score_impact > 0) or 1
    deducted = sum(
        r.score_impact for r in results
        if r.status in (Status.FAIL, Status.WARN)
    )
    # external scan = 60 points; questionnaire will add up to 40 later
    return max(0, 60 - int((deducted / max_deductible) * 60))
