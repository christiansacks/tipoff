"""
Cyber Essentials question definitions.
Each question maps to one of the 5 CE control areas.
auto_check values are matched against scan evidence gathered at route time.
"""

CE_AREAS = [
    {
        "id": "firewalls",
        "name": "Firewalls",
        "description": "Boundary and device-level firewall protection preventing unauthorised access.",
        "questions": [
            {
                "id": "FW1",
                "text": "Do you have a firewall protecting your internet connection?",
                "help": "This can be the firewall built into your ISP router, a dedicated appliance, or a software firewall. CE requires a firewall at the network boundary.",
                "remediation": "Install a firewall at your network boundary. Most business routers include one — ensure it is enabled and configured. Consider a dedicated firewall appliance for more control.",
                "auto_check": None,
            },
            {
                "id": "FW2",
                "text": "Have the default passwords been changed on all routers, firewalls, and network devices?",
                "help": "Default credentials for common devices are publicly documented. Attackers scan for them routinely.",
                "remediation": "Log in to each network device and change the default admin password to a strong, unique password. Document the new credentials securely.",
                "auto_check": None,
            },
            {
                "id": "FW3",
                "text": "Is your firewall configured to block inbound connections unless specifically required?",
                "help": "A deny-by-default inbound policy means only services you explicitly need are reachable from the internet.",
                "remediation": "Review your firewall rules and remove any inbound allow rules that are not required for business. Default posture should be to deny all inbound traffic.",
                "auto_check": None,
            },
            {
                "id": "FW4",
                "text": "Are all unused or unnecessary network services and ports disabled or blocked?",
                "help": "Services like Telnet (port 23), FTP (port 21), or unneeded SMB shares should be disabled to reduce the attack surface.",
                "remediation": "Audit open ports and services on all devices. Disable anything not actively needed. Pay particular attention to Telnet, FTP, unnecessary RDP, and unprotected SMB.",
                "auto_check": "dangerous_ports",
            },
            {
                "id": "FW5",
                "text": "Is administrative access to your firewall and routers restricted to specific trusted IP addresses or networks?",
                "help": "Admin interfaces should never be accessible from the internet. Restrict management access to your internal network or a specific admin device.",
                "remediation": "Configure your firewall/router to only allow admin access from specific trusted IPs. Disable remote management from the internet entirely if not needed.",
                "auto_check": None,
            },
        ],
    },
    {
        "id": "secure_config",
        "name": "Secure Configuration",
        "description": "Devices and software configured securely to minimise unnecessary vulnerabilities.",
        "questions": [
            {
                "id": "SC1",
                "text": "Have default passwords been changed on all computers, servers, and other devices before use?",
                "help": "Any device shipped with a default username/password must have those credentials changed before deployment.",
                "remediation": "Establish a build checklist that includes changing default credentials as a mandatory step before any device goes into service.",
                "auto_check": "dangerous_ports",
            },
            {
                "id": "SC2",
                "text": "Have unnecessary software, services, and user accounts been removed or disabled?",
                "help": "Every piece of software or service running on a device is a potential attack vector. Remove what you don't need.",
                "remediation": "Audit all devices and uninstall software that is not required. Disable services that are not in use. Remove demo, guest, or built-in accounts that are not needed.",
                "auto_check": None,
            },
            {
                "id": "SC3",
                "text": "Are administrator/privileged accounts only used for administrative tasks and not for general day-to-day activities such as email or web browsing?",
                "help": "Using admin accounts for everyday tasks increases the risk of malware gaining elevated privileges.",
                "remediation": "Create a separate standard user account for daily tasks (email, web browsing). Only log in with admin accounts when performing administrative work.",
                "auto_check": None,
            },
            {
                "id": "SC4",
                "text": "Are all computers and devices protected by a PIN, password, or biometric lock?",
                "help": "This applies to laptops, desktops, smartphones, tablets, and any other device that can access business data.",
                "remediation": "Enable screen lock with a minimum 8-character password or 6-digit PIN on all devices. Configure auto-lock after a short period of inactivity (5–10 minutes).",
                "auto_check": None,
            },
            {
                "id": "SC5",
                "text": "Is auto-run/auto-play disabled for removable media (USB drives, DVDs) on all computers?",
                "help": "Auto-run malware is a common infection vector via USB drives.",
                "remediation": "Disable AutoRun/AutoPlay in Windows Group Policy or via Registry. On macOS this is disabled by default. Consider blocking USB storage devices entirely if not required.",
                "auto_check": None,
            },
        ],
    },
    {
        "id": "user_access",
        "name": "User Access Control",
        "description": "Access to systems and data restricted to those with a legitimate need.",
        "questions": [
            {
                "id": "UA1",
                "text": "Does every user have their own separate account — no shared logins?",
                "help": "Shared accounts make it impossible to audit who did what and mean a compromised password affects multiple people.",
                "remediation": "Create individual accounts for every user. Retire any shared or generic accounts (e.g. 'reception', 'accounts'). Document account ownership.",
                "auto_check": None,
            },
            {
                "id": "UA2",
                "text": "Are administrator/privileged rights only granted to users who genuinely need them?",
                "help": "Limiting admin rights reduces the damage a compromised account can do. Most users should not be local administrators on their machines.",
                "remediation": "Review all accounts with admin rights. Remove admin privileges from any account that doesn't require them. Standard users should run without local admin rights.",
                "auto_check": None,
            },
            {
                "id": "UA3",
                "text": "Are accounts and access rights removed or disabled promptly when a user leaves or changes role?",
                "help": "Dormant accounts are a significant risk — ex-employees or contractors may still be able to log in.",
                "remediation": "Establish an offboarding process that includes disabling accounts on the same day a user leaves. Review all accounts quarterly and remove any that are no longer needed.",
                "auto_check": None,
            },
            {
                "id": "UA4",
                "text": "Is multi-factor authentication (MFA) used for all remote access to your systems?",
                "help": "MFA is now a CE requirement for remote access. This includes VPN, remote desktop, cloud services, and email accessed from outside the office.",
                "remediation": "Enable MFA on all remote access services. Most cloud providers (Microsoft 365, Google Workspace) offer free MFA. Use an authenticator app rather than SMS where possible.",
                "auto_check": None,
            },
            {
                "id": "UA5",
                "text": "Do you have a password policy requiring passwords of at least 8 characters (or 12 for admin accounts)?",
                "help": "CE requires minimum password lengths. Longer is better — consider passphrases. Password managers make this easy for staff.",
                "remediation": "Enforce a minimum 8-character password policy for all accounts, 12 characters for admin accounts. Consider implementing a password manager across the organisation.",
                "auto_check": None,
            },
        ],
    },
    {
        "id": "malware",
        "name": "Malware Protection",
        "description": "Protection against viruses, ransomware, and other malicious software.",
        "questions": [
            {
                "id": "MP1",
                "text": "Is anti-malware software installed on all computers and devices that can access the internet or email?",
                "help": "This includes Windows Defender (built into Windows 10/11), or a third-party product. macOS and mobile devices also need protection.",
                "remediation": "Deploy anti-malware on all devices. Windows Defender is free and sufficient for CE purposes. Ensure it is enabled and not disabled by users.",
                "auto_check": None,
            },
            {
                "id": "MP2",
                "text": "Is anti-malware software kept up-to-date with the latest signatures and definitions?",
                "help": "Out-of-date anti-malware cannot detect the latest threats. Definitions should update automatically at least daily.",
                "remediation": "Configure anti-malware to update definitions automatically. Check that automatic updates have not been disabled. Verify last update time on each device regularly.",
                "auto_check": None,
            },
            {
                "id": "MP3",
                "text": "Are known malicious websites blocked — either via a web filter, DNS filtering, or browser-based protection?",
                "help": "DNS filtering services (e.g. Cloudflare Gateway, Cisco Umbrella) can block malicious domains before a connection is made.",
                "remediation": "Implement DNS filtering using a service like Cloudflare Gateway (free tier available) or configure your router to use a protective DNS service. Enable browser-based safe browsing.",
                "auto_check": None,
            },
            {
                "id": "MP4",
                "text": "Are only approved/trusted applications permitted to run on your devices?",
                "help": "Application whitelisting or using only software from trusted sources (official app stores, known publishers) reduces the risk of malicious software running.",
                "remediation": "Consider enabling Windows Defender Application Control or AppLocker. At minimum, train staff not to install unapproved software and enforce this via policy.",
                "auto_check": None,
            },
        ],
    },
    {
        "id": "patching",
        "name": "Patch Management",
        "description": "Software and operating systems kept up-to-date to fix known vulnerabilities.",
        "questions": [
            {
                "id": "PM1",
                "text": "Are operating systems on all devices patched within 14 days of updates becoming available?",
                "help": "CE requires a maximum 14-day window for applying OS patches. Automatic updates achieve this easily on most platforms.",
                "remediation": "Enable automatic updates on all devices. For servers, test patches in a staging environment then apply within 14 days. Document your patch process.",
                "auto_check": None,
            },
            {
                "id": "PM2",
                "text": "Are all applications (not just the OS) patched within 14 days of security updates being released?",
                "help": "This includes browsers, Office, PDF readers, and any other software. Browser auto-update should be enabled.",
                "remediation": "Enable auto-update on all applications where possible. Use a patch management tool if you have many devices. Prioritise internet-facing software (browsers, email clients).",
                "auto_check": "ssl_issues",
            },
            {
                "id": "PM3",
                "text": "Have all unsupported software and operating systems been removed or isolated from the network?",
                "help": "Software that no longer receives security updates (e.g. Windows 7, Windows Server 2012, EOL versions of applications) must not be in use or must be completely isolated.",
                "remediation": "Audit all devices for end-of-life software. Upgrade or replace unsupported systems. If isolation is necessary, ensure the device has no network access to other business systems.",
                "auto_check": "ssl_issues",
            },
            {
                "id": "PM4",
                "text": "Do you have a documented process for identifying and applying security patches?",
                "help": "CE expects you to have a defined process — even a simple written procedure covering who is responsible and the 14-day requirement.",
                "remediation": "Write a simple patch management policy: who checks for updates, how often, the 14-day deadline, and how compliance is verified. Review it annually.",
                "auto_check": None,
            },
        ],
    },
]

# Flat lookup by question id
CE_QUESTIONS: dict[str, dict] = {
    q["id"]: {**q, "area_id": area["id"], "area_name": area["name"]}
    for area in CE_AREAS
    for q in area["questions"]
}


def score_answers(answers: dict) -> dict:
    """Returns per-area and overall readiness scores."""
    total = sum(len(a["questions"]) for a in CE_AREAS)
    passed = 0
    area_scores = {}
    for area in CE_AREAS:
        qs = area["questions"]
        area_pass = sum(
            1 for q in qs
            if answers.get(q["id"], {}).get("answer") in ("yes", "na")
        )
        area_scores[area["id"]] = {
            "passed": area_pass,
            "total": len(qs),
            "pct": round(area_pass / len(qs) * 100) if qs else 0,
            "ready": area_pass == len(qs),
        }
        passed += area_pass
    return {
        "passed": passed,
        "total": total,
        "pct": round(passed / total * 100) if total else 0,
        "areas": area_scores,
        "ready": passed == total,
    }
