import asyncio, ipaddress, socket, struct, subprocess, re
import nmap
import manuf as manuf_lib
import dns.message
import dns.query
import dns.rdatatype
import dns.reversename

# Known hypervisor/virtualisation MAC OUI prefixes (first 3 octets, lowercase)
_VM_OUIS = {
    "00:50:56",  # VMware
    "00:0c:29",  # VMware Workstation/Player
    "00:05:69",  # VMware (legacy)
    "08:00:27",  # VirtualBox
    "00:15:5d",  # Hyper-V
    "52:54:00",  # QEMU/KVM/Proxmox
    "00:16:3e",  # Xen
    "00:1c:42",  # Parallels
    "50:6b:8d",  # Nutanix AHV
}
_CUSTOM_VM_OUIS: set[str] = set()


def set_custom_vm_ouis(ouis: set[str]) -> None:
    global _CUSTOM_VM_OUIS
    _CUSTOM_VM_OUIS = {o.lower()[:8] for o in ouis if o}


def _is_vm_mac(mac: str) -> bool:
    if not mac:
        return False
    prefix = mac.lower()[:8]
    if prefix in _VM_OUIS or prefix in _CUSTOM_VM_OUIS:
        return True
    # Locally Administered Address bit (0x02 in first octet) — set by Proxmox/QEMU
    # when generating random MACs for VMs; real NIC hardware uses globally unique MACs
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except Exception:
        return False


def _read_arp_cache() -> dict[str, dict]:
    """Read the kernel ARP cache from /proc/net/arp."""
    result = {}
    parser = manuf_lib.MacParser()
    try:
        with open("/proc/net/arp") as f:
            next(f)
            for line in f:
                parts = line.split()
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


async def _ping(ip: str) -> tuple[str | None, int | None, float | None]:
    """Ping once; return (ip, ttl, rtt_ms) on success or (None, None, None) on failure."""
    proc = await asyncio.create_subprocess_exec(
        "ping", "-c", "1", "-W", "1", ip,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await proc.communicate()
    if proc.returncode == 0:
        out = stdout.decode()
        m = re.search(r"\bttl=(\d+)\b", out, re.IGNORECASE)
        t = re.search(r"time=([\d.]+)", out)
        return ip, int(m.group(1)) if m else None, float(t.group(1)) if t else None
    return None, None, None


async def ping_sweep(cidr: str) -> list[tuple[str, int | None, float | None]]:
    network = ipaddress.ip_network(cidr, strict=False)
    # Guard against sweeping ranges that can't be enumerated: an IPv6 /64 is
    # 2^64 addresses and will exhaust all memory building the task list.
    if network.version == 6:
        raise ValueError(
            f"{cidr}: IPv6 ranges can't be swept — IPv6 hosts are discovered "
            "via NDP neighbor discovery after each IPv4 scan"
        )
    if network.num_addresses > 65536:
        raise ValueError(
            f"{cidr}: range too large to sweep ({network.num_addresses:,} "
            "addresses) — /16 is the largest supported"
        )
    sem = asyncio.Semaphore(100)

    async def _ping_limited(ip: str):
        async with sem:
            return await _ping(ip)

    results = await asyncio.gather(*[_ping_limited(str(ip)) for ip in network.hosts()])
    return [(ip, ttl, rtt) for ip, ttl, rtt in results if ip is not None]


def _hop_count_from_ttl(ttl: int) -> int:
    """Estimate hop count from ICMP reply TTL (assumes common initial values 64/128/255)."""
    if ttl > 128:
        return 255 - ttl
    if ttl > 64:
        return 128 - ttl
    return 64 - ttl


async def _traceroute_first_hop(ip: str) -> str | None:
    """Return the first responding intermediate hop IP when tracing to ip."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "traceroute", "-n", "-m", "4", "-q", "1", "-w", "1", ip,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        for line in stdout.decode().splitlines()[1:]:  # skip header
            parts = line.split()
            if len(parts) >= 2 and parts[1] != "*":
                try:
                    candidate = parts[1]
                    ipaddress.ip_address(candidate)
                    if candidate != ip:
                        return candidate
                except ValueError:
                    pass
    except Exception:
        pass
    return None


# ── Hostname resolution ────────────────────────────────────────────────────────

async def _lookup_hostname(ip: str) -> str:
    """Try reverse DNS → mDNS → NetBIOS in order, return first hit."""
    loop = asyncio.get_event_loop()

    # 1. Reverse DNS (PTR record) — normalize to short name like mDNS/NetBIOS
    # below, since PTR records are inconsistently registered as FQDN vs short
    # name depending on the device/DHCP server, and showing a mix of both on
    # the same network is more confusing than showing the domain at all.
    try:
        name = await loop.run_in_executor(None, lambda: socket.gethostbyaddr(ip)[0])
        if name and name != ip:
            return name.split(".")[0]
    except Exception:
        pass

    # 2. mDNS — unicast query directly to device on port 5353 (Apple, Linux)
    name = await _mdns_lookup(ip, loop)
    if name:
        return name

    # 3. NetBIOS node status — Windows and Samba machines
    name = await _netbios_lookup(ip, loop)
    if name:
        return name

    return ""


async def _mdns_lookup(ip: str, loop: asyncio.AbstractEventLoop) -> str | None:
    """Send a unicast mDNS PTR query to the device on port 5353."""
    def _query():
        try:
            rev = dns.reversename.from_address(ip)
            request = dns.message.make_query(rev, dns.rdatatype.PTR)
            request.flags = 0  # clear RD flag — mDNS doesn't use recursion
            response = dns.query.udp(request, ip, port=5353, timeout=0.5)
            for rrset in response.answer:
                for rdata in rrset:
                    name = str(rdata.target).rstrip(".")
                    # Strip .local suffix, return just the hostname part
                    return name.replace(".local", "").split(".")[0] or None
        except Exception:
            pass
        return None

    try:
        return await asyncio.wait_for(loop.run_in_executor(None, _query), timeout=1.0)
    except Exception:
        return None


# NetBIOS Node Status Request:
#   header (12) + encoded wildcard name (34) + type/class (4)
_NETBIOS_QUERY = (
    b"\xa4\x91\x00\x00"  # transaction ID + flags (standard query)
    b"\x00\x01"          # QDCOUNT = 1
    b"\x00\x00\x00\x00\x00\x00"  # ANCOUNT, NSCOUNT, ARCOUNT
    b"\x20"              # name length = 32
    + b"CK" + b"CA" * 14 + b"AA"  # "*" + 14 spaces + null byte, NetBIOS-encoded
    + b"\x00"            # end of name
    + b"\x00\x21"        # type NBSTAT
    + b"\x00\x01"        # class IN
)


async def _netbios_lookup(ip: str, loop: asyncio.AbstractEventLoop) -> str | None:
    """Send a NetBIOS Node Status request and extract the machine name."""
    def _query():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.5)
        try:
            sock.sendto(_NETBIOS_QUERY, (ip, 137))
            data, _ = sock.recvfrom(1024)
            return _parse_netbios(data)
        except Exception:
            return None
        finally:
            sock.close()

    try:
        return await asyncio.wait_for(loop.run_in_executor(None, _query), timeout=1.0)
    except Exception:
        return None


def _parse_netbios(data: bytes) -> str | None:
    """Extract the workstation name from a NetBIOS Node Status response."""
    try:
        if len(data) < 12:
            return None

        qdcount = struct.unpack("!H", data[4:6])[0]
        ancount = struct.unpack("!H", data[6:8])[0]
        if ancount == 0:
            return None

        offset = 12

        # Skip question section — parse it rather than assume fixed length,
        # because some devices compress the name in the response
        for _ in range(qdcount):
            while offset < len(data):
                length = data[offset]
                if length == 0:
                    offset += 1
                    break
                if length & 0xC0 == 0xC0:
                    offset += 2
                    break
                offset += 1 + length
            offset += 4  # QTYPE + QCLASS

        # Walk answer records
        for _ in range(ancount):
            if offset >= len(data):
                return None
            # Skip answer name
            if data[offset] & 0xC0 == 0xC0:
                offset += 2
            else:
                while offset < len(data) and data[offset]:
                    offset += data[offset] + 1
                offset += 1

            if offset + 10 > len(data):
                return None
            rtype = struct.unpack("!H", data[offset:offset + 2])[0]
            rdlen = struct.unpack("!H", data[offset + 8:offset + 10])[0]
            offset += 10

            if rtype == 0x0021:  # NBSTAT
                if offset >= len(data):
                    return None
                num_names = data[offset]
                offset += 1
                for _ in range(min(num_names, 20)):
                    if offset + 18 > len(data):
                        break
                    name  = data[offset:offset + 15].decode("ascii", errors="ignore").rstrip()
                    ntype = data[offset + 15]
                    flags = struct.unpack("!H", data[offset + 16:offset + 18])[0]
                    offset += 18
                    # type 0x00 = workstation/server; skip group names (0x8000 flag)
                    if ntype == 0x00 and not (flags & 0x8000):
                        return name.strip() or None
            else:
                offset += rdlen

        return None
    except Exception:
        return None


# ── Port scanning ──────────────────────────────────────────────────────────────

def port_scan(ip: str) -> dict:
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, "21,22,23,80,443,445,3389,5900,8080,8443", arguments="-sV -T4 --open")
    except Exception:
        return {"ip": ip, "os_guess": "Unknown", "open_ports": [], "flagged": False}

    host_data = nm[ip] if ip in nm.all_hosts() else {}
    open_ports = []
    flagged    = False

    for port, info in host_data.get("tcp", {}).items():
        if info["state"] == "open":
            dangerous = port in {21, 23, 3389, 445, 5900}
            if dangerous:
                flagged = True
            open_ports.append({
                "port":    port,
                "service": info.get("name", ""),
                "version": info.get("version", ""),
                "dangerous": dangerous,
            })

    return {
        "ip":         ip,
        "os_guess":   host_data.get("osmatch", [{}])[0].get("name", "Unknown") if host_data else "Unknown",
        "open_ports": open_ports,
        "flagged":    flagged,
    }


async def rescan_host(ip: str) -> dict:
    loop = asyncio.get_event_loop()
    scan_data = await loop.run_in_executor(None, port_scan, ip)
    hostname  = await _lookup_hostname(ip)
    arp_cache = _read_arp_cache()
    arp_data  = arp_cache.get(ip, {"mac": "", "vendor": ""})
    result    = {**arp_data, **scan_data, "hostname": hostname}
    result["is_vm"] = _is_vm_mac(result.get("mac", ""))
    _, ttl, rtt = await _ping(ip)
    hop_count = _hop_count_from_ttl(ttl) if ttl is not None else None
    gateway_ip = None
    if hop_count is not None and hop_count >= 1:
        gateway_ip = await _traceroute_first_hop(ip)
    result["ttl"]        = ttl
    result["hop_count"]  = hop_count
    result["gateway_ip"] = gateway_ip
    result["ping_ms"]    = rtt
    return result


async def discover_network(cidr: str, progress: dict | None = None) -> list[dict]:
    """Ping sweep → ARP cache for MACs → parallel nmap + hostname lookup per live host."""
    def _update(stage=None, **kw):
        if progress is not None:
            if stage:
                progress["stage"] = stage
            progress.update(kw)

    _update(stage=f"Finding live hosts on {cidr}…")
    live_pairs = await ping_sweep(cidr)
    ttl_map    = {ip: ttl for ip, ttl, _rtt in live_pairs}
    rtt_map    = {ip: rtt for ip, _ttl, rtt in live_pairs}
    live_ips   = list(ttl_map.keys())
    _update(hosts_found=len(live_ips))

    # Wait for ARP cache to settle after ping sweep before reading it
    await asyncio.sleep(1.0)
    arp_cache = _read_arp_cache()

    _update(stage=f"Port scanning {len(live_ips)} live hosts…", total=len(live_ips), scanned=0)

    loop = asyncio.get_event_loop()
    sem  = asyncio.Semaphore(8)

    async def _scan(ip: str) -> dict:
        async with sem:
            scan_data = await loop.run_in_executor(None, port_scan, ip)
            hostname  = await _lookup_hostname(ip)
            if progress is not None:
                progress["scanned"] = progress.get("scanned", 0) + 1
                progress["stage"]   = f"Scanning hosts… {progress['scanned']}/{progress['total']}"
            arp_data  = arp_cache.get(ip, {"mac": "", "vendor": ""})
            result    = {**arp_data, **scan_data, "hostname": hostname}
            result["is_vm"] = _is_vm_mac(result.get("mac", ""))
            ttl       = ttl_map.get(ip)
            hop_count = _hop_count_from_ttl(ttl) if ttl is not None else None
            gateway_ip = None
            if hop_count is not None and hop_count >= 1:
                gateway_ip = await _traceroute_first_hop(ip)
            result["ttl"]        = ttl
            result["hop_count"]  = hop_count
            result["gateway_ip"] = gateway_ip
            result["ping_ms"]    = rtt_map.get(ip)
            return result

    return await asyncio.gather(*[_scan(ip) for ip in live_ips])


# Prefixes of virtual/tunnel interfaces to skip for IPv6 multicast ping
_SKIP_IFACE_PREFIXES = ("lo", "docker", "br-", "veth", "tun", "tap", "zt", "virbr", "vmnet", "vnet", "wg")


def _ipv6_interfaces() -> list[str]:
    """Return physical/VM LAN interface names that have an IPv6 address."""
    ifaces = []
    # Read /proc/net/if_inet6 — always available, no iproute2 needed
    # Format: addr iface_idx prefix_len scope flags ifname
    try:
        with open("/proc/net/if_inet6") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 6:
                    iface = parts[5]
                    if any(iface.startswith(p) for p in _SKIP_IFACE_PREFIXES):
                        continue
                    if iface not in ifaces:
                        ifaces.append(iface)
    except Exception:
        pass
    if ifaces:
        return ifaces
    # Fallback: ip -6 addr show (requires iproute2)
    try:
        out = subprocess.run(["ip", "-6", "addr", "show"], capture_output=True, text=True, timeout=5).stdout
        current = None
        for line in out.splitlines():
            m = re.match(r"^\d+:\s+(\S+?)[@:]", line)
            if m:
                current = m.group(1)
                continue
            if current and not any(current.startswith(p) for p in _SKIP_IFACE_PREFIXES) and current not in ifaces and "inet6" in line:
                ifaces.append(current)
    except Exception:
        pass
    return ifaces


def _read_ipv6_neighbors() -> list[dict]:
    """Parse the kernel NDP neighbor table (ip -6 neigh show) into
    {ipv6, mac, link_local} dicts; skips FAILED/INCOMPLETE entries."""
    neighbors = []
    try:
        out = subprocess.run(
            ["ip", "-6", "neigh", "show"], capture_output=True, text=True, timeout=5
        ).stdout
        for line in out.splitlines():
            parts = line.split()
            # format: <addr> dev <iface> lladdr <mac> <STATE>
            if "lladdr" not in parts:
                continue
            idx  = parts.index("lladdr")
            ipv6 = parts[0]
            mac  = parts[idx + 1]
            state = parts[-1] if len(parts) > idx + 2 else ""
            if state in ("FAILED", "INCOMPLETE"):
                continue
            # skip multicast/loopback addresses
            try:
                addr = ipaddress.ip_address(ipv6)
                if addr.is_multicast or addr.is_loopback:
                    continue
            except ValueError:
                continue
            neighbors.append({
                "ipv6":       ipv6,
                "mac":        mac,
                "link_local": ipv6.startswith("fe80"),
            })
    except Exception:
        pass
    return neighbors


async def discover_ipv6_neighbors(rounds: int = 3, round_gap: float = 2.0) -> list[dict]:
    """
    Discover IPv6 hosts on the local network:
    1. Ping ff02::1 (all-nodes multicast) on each IPv6 interface to wake the NDP cache.
    2. Read the kernel NDP neighbor table (ip -6 neigh show).

    A single probe only catches whatever happens to answer within a ~2 second
    window — sleeping/slow devices or a dropped multicast packet (common on
    WiFi) mean a lot of real hosts get missed. Repeating the probe a few times
    with a gap in between and accumulating results catches far more without
    much extra cost — each round is cheap, and this only runs as part of a
    background discovery job.

    Returns a deduplicated list of {ipv6, mac, link_local} dicts.
    """
    ifaces = _ipv6_interfaces()
    if not ifaces:
        return []

    loop = asyncio.get_event_loop()

    async def _ping_multicast(iface: str):
        try:
            await loop.run_in_executor(
                None,
                lambda i=iface: subprocess.run(
                    ["ping", "-6", "-c", "2", "-W", "1", f"ff02::1%{i}"],
                    capture_output=True, timeout=5,
                ),
            )
        except Exception:
            pass

    seen: dict[str, dict] = {}
    for round_num in range(rounds):
        await asyncio.gather(*[_ping_multicast(i) for i in ifaces])
        await asyncio.sleep(1.0)
        for neighbor in await loop.run_in_executor(None, _read_ipv6_neighbors):
            seen[neighbor["ipv6"]] = neighbor
        if round_num < rounds - 1:
            await asyncio.sleep(round_gap)

    return list(seen.values())
