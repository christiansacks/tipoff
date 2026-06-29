import dns.resolver
from scanner.models import CheckResult, Status
from scanner import resolver as _res

DKIM_SELECTORS = [
    "google", "default", "mail", "dkim",
    "selector1", "selector2",  # Microsoft 365
    "k1",                       # Mailchimp
    "s1", "s2",
]


async def check_spf(domain: str) -> CheckResult:
    r = _res.get()
    try:
        answers = r.resolve(domain, "TXT")
        spf = next(
            (a.to_text().strip('"') for a in answers if "v=spf1" in a.to_text()),
            None
        )
        if not spf:
            return CheckResult(
                check_id="spf_missing",
                status=Status.FAIL,
                title="No SPF Record",
                detail="Anyone can send email pretending to be from your domain, enabling phishing attacks on your customers.",
                remediation="Add a TXT DNS record: v=spf1 include:<your-mail-provider> ~all — your email provider will give you the exact value.",
                score_impact=10,
                raw={},
            )
        if "+all" in spf:
            return CheckResult(
                check_id="spf_too_permissive",
                status=Status.FAIL,
                title="SPF Record Too Permissive",
                detail='SPF ends with "+all" meaning any server can send email as you. This provides no protection.',
                remediation='Change "+all" to "~all" or "-all" in your SPF record.',
                score_impact=8,
                raw={"record": spf},
            )
        return CheckResult(
            check_id="spf_present", status=Status.PASS,
            title="SPF Record", detail="Present and configured.",
            remediation="", score_impact=0, raw={"record": spf},
        )
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return CheckResult(
            check_id="spf_missing", status=Status.FAIL,
            title="No SPF Record", detail="SPF record not found.",
            remediation="Add a TXT DNS record for SPF.",
            score_impact=10, raw={},
        )


async def check_dmarc(domain: str) -> CheckResult:
    r = _res.get()
    try:
        answers = r.resolve(f"_dmarc.{domain}", "TXT")
        dmarc = next(
            (a.to_text().strip('"') for a in answers if "v=DMARC1" in a.to_text()),
            None
        )
        if not dmarc:
            return CheckResult(
                check_id="dmarc_missing", status=Status.FAIL,
                title="No DMARC Record",
                detail="Without DMARC, email providers won't know what to do with spoofed emails from your domain.",
                remediation='Add TXT record: _dmarc.yourdomain.com → v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com',
                score_impact=10, raw={},
            )
        if "p=none" in dmarc:
            return CheckResult(
                check_id="dmarc_policy_weak", status=Status.WARN,
                title="DMARC Policy: Monitor Only",
                detail="DMARC is set to 'none' — spoofed emails are still delivered, just logged.",
                remediation='Change p=none to p=quarantine or p=reject.',
                score_impact=5, raw={"record": dmarc},
            )
        return CheckResult(
            check_id="dmarc_present", status=Status.PASS,
            title="DMARC Record", detail="Present and enforcing.",
            remediation="", score_impact=0, raw={"record": dmarc},
        )
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return CheckResult(
            check_id="dmarc_missing", status=Status.FAIL,
            title="No DMARC Record", detail="DMARC record not found.",
            remediation='Add _dmarc TXT record to your DNS.',
            score_impact=10, raw={},
        )


async def check_dkim(domain: str) -> CheckResult:
    r = _res.get()
    for selector in DKIM_SELECTORS:
        try:
            r.resolve(f"{selector}._domainkey.{domain}", "TXT")
            return CheckResult(
                check_id="dkim_present", status=Status.PASS,
                title="DKIM Record",
                detail=f"Found (selector: {selector}).",
                remediation="", score_impact=0, raw={"selector": selector},
            )
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            continue

    return CheckResult(
        check_id="dkim_not_found", status=Status.WARN,
        title="DKIM Not Detected",
        detail="No DKIM record found for common selectors. DKIM may still be configured with a custom selector.",
        remediation="Ask your email provider to confirm DKIM is enabled.",
        score_impact=5, raw={"selectors_tried": DKIM_SELECTORS},
    )
