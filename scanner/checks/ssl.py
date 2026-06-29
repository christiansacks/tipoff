import ssl, socket, datetime
from scanner.models import CheckResult, Status


async def check_ssl(domain: str) -> list[CheckResult]:
    results = []
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.create_connection((domain, 443), timeout=10),
            server_hostname=domain
        ) as sock:
            cert = sock.getpeercert()
            tls_version = sock.version()

        expiry = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days_left = (expiry - datetime.datetime.utcnow()).days

        if days_left < 0:
            results.append(CheckResult(
                check_id="ssl_expired",
                status=Status.FAIL,
                title="SSL Certificate Expired",
                detail=f"Your SSL certificate expired {abs(days_left)} days ago. Visitors see a browser security warning.",
                remediation="Renew your SSL certificate immediately. Let's Encrypt is free and auto-renews.",
                score_impact=15,
                raw={"days_left": days_left},
            ))
        elif days_left < 14:
            results.append(CheckResult(
                check_id="ssl_expiring_soon",
                status=Status.WARN,
                title="SSL Certificate Expiring Soon",
                detail=f"Your SSL certificate expires in {days_left} days.",
                remediation="Renew your SSL certificate before it expires.",
                score_impact=8,
                raw={"days_left": days_left},
            ))
        else:
            results.append(CheckResult(
                check_id="ssl_valid",
                status=Status.PASS,
                title="SSL Certificate",
                detail=f"Valid. Expires in {days_left} days.",
                remediation="",
                score_impact=0,
                raw={"days_left": days_left},
            ))

        if tls_version in ("TLSv1", "TLSv1.1"):
            results.append(CheckResult(
                check_id="ssl_weak_tls",
                status=Status.FAIL,
                title="Outdated TLS Version",
                detail=f"Server supports {tls_version} which is deprecated and insecure.",
                remediation="Disable TLS 1.0 and 1.1 in your web server config. Only TLS 1.2+ should be allowed.",
                score_impact=10,
                raw={"tls_version": tls_version},
            ))

    except ssl.SSLCertVerificationError:
        results.append(CheckResult(
            check_id="ssl_invalid",
            status=Status.FAIL,
            title="SSL Certificate Invalid",
            detail="Certificate could not be verified. Visitors will see a security warning.",
            remediation="Check your certificate is correctly installed and matches your domain.",
            score_impact=15,
            raw={},
        ))
    except (socket.timeout, ConnectionRefusedError, OSError):
        results.append(CheckResult(
            check_id="ssl_unreachable",
            status=Status.ERROR,
            title="HTTPS Unreachable",
            detail="Could not connect on port 443. Site may not support HTTPS.",
            remediation="Ensure your site is accessible over HTTPS.",
            score_impact=15,
            raw={},
        ))

    return results
