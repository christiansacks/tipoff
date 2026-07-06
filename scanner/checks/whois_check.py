import asyncio
from datetime import datetime
from scanner.models import CheckResult, Status


async def check_domain_expiry(domain: str) -> CheckResult:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _whois_lookup, domain)


def check_result_for_expiry(expiry: datetime, source: str = "WHOIS") -> CheckResult:
    """Build the days-left threshold CheckResult for a known expiry date.

    Shared by the automatic WHOIS lookup and manual expiry overrides (some
    registries, e.g. .au, don't publish expiry via WHOIS at all).
    """
    if hasattr(expiry, "tzinfo") and expiry.tzinfo:
        expiry = expiry.replace(tzinfo=None)

    days_left = (expiry - datetime.utcnow()).days
    expiry_str = expiry.strftime("%d %b %Y")
    via = "" if source == "WHOIS" else " (manually entered)"
    raw = {"days_left": days_left, "expiry": expiry_str, "source": source}

    if days_left < 0:
        return CheckResult(
            check_id="domain_expired",
            status=Status.FAIL,
            title="Domain Expired",
            detail=f"Domain expired {abs(days_left)} day{'s' if abs(days_left) != 1 else ''} ago ({expiry_str}){via}.",
            remediation="Renew your domain immediately — it may already be at risk of being taken.",
            score_impact=10,
            raw=raw,
        )
    elif days_left <= 30:
        return CheckResult(
            check_id="domain_expiring_soon",
            status=Status.FAIL,
            title="Domain Expiring Soon",
            detail=f"Domain expires in {days_left} day{'s' if days_left != 1 else ''} on {expiry_str}{via}.",
            remediation="Renew your domain now to avoid losing it.",
            score_impact=8,
            raw=raw,
        )
    elif days_left <= 60:
        return CheckResult(
            check_id="domain_renewal_due",
            status=Status.WARN,
            title="Domain Renewal Due Soon",
            detail=f"Domain expires in {days_left} days on {expiry_str}{via}.",
            remediation="Consider renewing your domain in the next few weeks.",
            score_impact=3,
            raw=raw,
        )
    else:
        return CheckResult(
            check_id="domain_expiry_ok",
            status=Status.PASS,
            title="Domain Expiry",
            detail=f"Registered until {expiry_str} ({days_left} days remaining){via}.",
            remediation="",
            score_impact=0,
            raw=raw,
        )


def _whois_lookup(domain: str) -> CheckResult:
    try:
        import whois
        w = whois.whois(domain)
        expiry = w.expiration_date

        if isinstance(expiry, list):
            expiry = expiry[0]

        if expiry is None:
            return CheckResult(
                check_id="domain_expiry_unknown",
                status=Status.WARN,
                title="Domain Expiry Unknown",
                detail="WHOIS returned no expiry date — registrar may use privacy protection, or your TLD doesn't publish it (e.g. .au).",
                remediation="Log in to your domain registrar to confirm the renewal date, or enter it manually below.",
                score_impact=0,
                raw={},
            )

        return check_result_for_expiry(expiry, source="WHOIS")

    except Exception as e:
        return CheckResult(
            check_id="domain_expiry_error",
            status=Status.WARN,
            title="Domain Expiry Check Failed",
            detail="Could not query WHOIS for this domain.",
            remediation="Check manually at your domain registrar, or enter the expiry date manually below.",
            score_impact=0,
            raw={"error": str(e)},
        )
