import hashlib
import httpx


async def check_password_pwned(password: str) -> int:
    """Returns how many times this password appears in known breach dumps (0 = not found)."""
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"Add-Padding": "true"},
        )
        resp.raise_for_status()
    for line in resp.text.splitlines():
        parts = line.split(":")
        if len(parts) == 2 and parts[0] == suffix:
            return int(parts[1])
    return 0
