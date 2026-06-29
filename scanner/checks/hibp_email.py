import httpx

_HIBP_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{}"


async def check_email_breaches(email: str, api_key: str) -> dict:
    if not api_key:
        return {"status": "no_key", "breaches": [], "count": 0}
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            resp = await client.get(
                _HIBP_URL.format(email),
                headers={"hibp-api-key": api_key, "user-agent": "CyberReady/1.0"},
                params={"truncateResponse": "false"},
            )
            if resp.status_code == 404:
                return {"status": "clean", "breaches": [], "count": 0}
            if resp.status_code == 401:
                return {"status": "invalid_key", "breaches": [], "count": 0}
            if resp.status_code == 429:
                return {"status": "rate_limited", "breaches": [], "count": 0}
            resp.raise_for_status()
            data = resp.json()
            names = [b["Name"] for b in data]
            return {"status": "breached", "breaches": names, "count": len(names)}
        except httpx.TimeoutException:
            return {"status": "error", "breaches": [], "count": 0}
        except Exception as e:
            return {"status": "error", "breaches": [], "count": 0, "error": str(e)}
