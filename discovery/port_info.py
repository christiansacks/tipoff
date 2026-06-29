"""Plain-English knowledge base for common ports shown in host detail."""

PORT_INFO = {
    21: {
        "name": "FTP",
        "risk": "high",
        "description": "File Transfer Protocol — sends files and credentials with no encryption.",
        "detail": "Anyone on the same network can intercept FTP passwords and file contents in plaintext.",
        "remediation": "Replace with SFTP (runs over SSH on port 22) or FTPS. Disable FTP entirely if not actively used.",
    },
    22: {
        "name": "SSH",
        "risk": "low",
        "description": "Secure Shell — encrypted remote terminal access.",
        "detail": "SSH is generally safe. The main risk is weak passwords or keys being exposed.",
        "remediation": "Disable password authentication and use SSH keys only. Restrict access with AllowUsers in sshd_config.",
    },
    23: {
        "name": "Telnet",
        "risk": "critical",
        "description": "Unencrypted remote access — transmits everything including passwords in plaintext.",
        "detail": "Telnet has no encryption whatsoever. It was replaced by SSH over 20 years ago and should never be used.",
        "remediation": "Disable Telnet immediately. Use SSH instead.",
    },
    80: {
        "name": "HTTP",
        "risk": "info",
        "description": "Web server — unencrypted HTTP traffic.",
        "detail": "HTTP is acceptable if it immediately redirects to HTTPS. Serving content over plain HTTP exposes data to interception.",
        "remediation": "Ensure all HTTP traffic redirects to HTTPS. Never serve login pages or sensitive data over HTTP.",
    },
    443: {
        "name": "HTTPS",
        "risk": "info",
        "description": "Secure web server — encrypted HTTPS traffic.",
        "detail": "HTTPS is expected for any web-facing service. Ensure the certificate is valid and not expired.",
        "remediation": "",
    },
    445: {
        "name": "SMB",
        "risk": "high",
        "description": "Windows / Samba file sharing.",
        "detail": (
            "SMB (port 445) is the protocol exploited by WannaCry, NotPetya, and many ransomware attacks. "
            "On a local network it is normal for NAS devices and Windows file shares, but it must never be "
            "exposed to the internet. On a Raspberry Pi this is almost certainly a Samba share."
        ),
        "remediation": (
            "Confirm your router/firewall blocks port 445 inbound from the internet. "
            "In Samba's smb.conf, add 'hosts allow = 192.168.1.0/24' to restrict access to your local subnet only."
        ),
    },
    3389: {
        "name": "RDP",
        "risk": "critical",
        "description": "Windows Remote Desktop Protocol.",
        "detail": (
            "RDP is one of the most heavily attacked services on the internet. "
            "Credential-stuffing and brute-force attacks are relentless. "
            "Several critical RDP vulnerabilities (BlueKeep etc.) allow unauthenticated remote code execution."
        ),
        "remediation": (
            "Never expose RDP directly to the internet — put it behind a VPN. "
            "Enable Network Level Authentication (NLA). "
            "Keep Windows fully patched. Consider moving to a non-standard port as a minor deterrent."
        ),
    },
    5900: {
        "name": "VNC",
        "risk": "high",
        "description": "Virtual Network Computing — graphical remote desktop.",
        "detail": "VNC is frequently targeted and historically has had severe vulnerabilities. Many deployments use weak or no passwords.",
        "remediation": "Never expose VNC to the internet. Access it via SSH tunnel or VPN. Set a strong password in VNC server settings.",
    },
    8080: {
        "name": "HTTP (alt)",
        "risk": "info",
        "description": "Web service on alternate port 8080.",
        "detail": "Often a management interface, development server, or reverse proxy. Admin UIs on 8080 should not be internet-facing.",
        "remediation": "Identify the service and ensure it is not accessible from the internet if it is an admin interface.",
    },
    8443: {
        "name": "HTTPS (alt)",
        "risk": "info",
        "description": "Secure web service on alternate port 8443.",
        "detail": "Common for management interfaces such as Proxmox, router admin panels, or NAS UIs. Generally fine on a LAN.",
        "remediation": "",
    },
}

RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def enrich_ports(open_ports: list) -> list:
    """Attach plain-English info to each port dict from a scan result."""
    enriched = []
    for p in open_ports:
        info = PORT_INFO.get(p["port"], {})
        enriched.append({
            **p,
            "display_name": info.get("name", p.get("service", "unknown")),
            "risk":         info.get("risk", "info"),
            "description":  info.get("description", ""),
            "detail":       info.get("detail", ""),
            "remediation":  info.get("remediation", ""),
        })
    enriched.sort(key=lambda x: RISK_ORDER.get(x["risk"], 99))
    return enriched
