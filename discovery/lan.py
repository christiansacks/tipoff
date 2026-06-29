import asyncio, ipaddress, socket
import nmap
import manuf as manuf_lib


def _read_arp_cache() -> dict[str, dict]:
    """Read the kernel ARP cache from /proc/net/arp — populated automatically by ping."""
    result = {}
    parser = manuf_lib.MacParser()
    try:
        with open("/proc/net/arp") as f:
            next(f)  # skip header line
            for line in f:
                parts = line.split()
                # flags 0x2 = complete entry (not incomplete/stale)
                if len(parts) >= 4 and parts[2] == "0x2" and parts[3] != "00:00:00:00:00:00":
                    ip  = parts[0]
                    mac = parts[3]
                    result[ip] = {
                        "mac": mac,
                        "vendor": parser.get_manuf_long(mac) or parser.get_manuf(mac) or "Unknown",
                    }
    except Exception:
        pass
    return result


async def _ping(ip: str) -> str | None:
    proc = await asyncio.create_subprocess_exec(
        "ping", "-c", "1", "-W", "1", ip,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    await proc.wait()
    return ip if proc.returncode == 0 else None


async def ping_sweep(cidr: str) -> list[str]:
    network = ipaddress.ip_network(cidr, strict=False)
    tasks = [_ping(str(ip)) for ip in network.hosts()]
    results = await asyncio.gather(*tasks)
    return [ip for ip in results if ip is not None]


def port_scan(ip: str) -> dict:
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, "21,22,23,80,443,445,3389,5900,8080,8443", arguments="-sV -T4 --open")
    except Exception:
        return {"ip": ip, "hostname": "", "os_guess": "Unknown", "open_ports": [], "flagged": False}

    host_data = nm[ip] if ip in nm.all_hosts() else {}
    open_ports = []
    flagged = False

    for port, info in host_data.get("tcp", {}).items():
        if info["state"] == "open":
            dangerous = port in {21, 23, 3389, 445, 5900}
            if dangerous:
                flagged = True
            open_ports.append({
                "port": port,
                "service": info.get("name", ""),
                "version": info.get("version", ""),
                "dangerous": dangerous,
            })

    hostname = ""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        pass

    return {
        "ip": ip,
        "hostname": hostname,
        "os_guess": host_data.get("osmatch", [{}])[0].get("name", "Unknown") if host_data else "Unknown",
        "open_ports": open_ports,
        "flagged": flagged,
    }


async def rescan_host(ip: str) -> dict:
    """Run a fresh port scan on a single IP and return the updated host dict."""
    loop = asyncio.get_event_loop()
    scan_data = await loop.run_in_executor(None, port_scan, ip)
    arp_cache = _read_arp_cache()
    arp_data = arp_cache.get(ip, {"mac": "", "vendor": ""})
    return {**arp_data, **scan_data}


async def discover_network(cidr: str, progress: dict | None = None) -> list[dict]:
    """Ping sweep → ARP cache for MACs → parallel nmap per live host.

    progress dict is updated in-place so callers can poll it:
      {"stage": str, "hosts_found": int, "scanned": int, "total": int}
    """
    def _update(stage=None, **kw):
        if progress is not None:
            if stage:
                progress["stage"] = stage
            progress.update(kw)

    _update(stage=f"Finding live hosts on {cidr}…")
    live_ips = await ping_sweep(cidr)
    _update(hosts_found=len(live_ips))

    arp_cache = _read_arp_cache()

    _update(stage=f"Port scanning {len(live_ips)} live hosts…", total=len(live_ips), scanned=0)

    loop = asyncio.get_event_loop()
    sem = asyncio.Semaphore(8)  # max 8 concurrent nmap scans

    async def _scan(ip: str) -> dict:
        async with sem:
            result = await loop.run_in_executor(None, port_scan, ip)
            if progress is not None:
                progress["scanned"] = progress.get("scanned", 0) + 1
                progress["stage"] = f"Scanning hosts… {progress['scanned']}/{progress['total']}"
            return result

    scan_results = await asyncio.gather(*[_scan(ip) for ip in live_ips])

    hosts = []
    for ip, scan_data in zip(live_ips, scan_results):
        arp_data = arp_cache.get(ip, {"mac": "", "vendor": ""})
        hosts.append({**arp_data, **scan_data})

    return hosts
