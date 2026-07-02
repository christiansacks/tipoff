import httpx

_LEAKCHECK_URL = "https://leakcheck.io/api/public?check={}"


async def check_email_leakcheck(email: str) -> dict:
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            resp = await client.get(
                _LEAKCHECK_URL.format(email),
                headers={"user-agent": "TipOff/1.0"},
            )
            if resp.status_code == 429:
                return {"status": "rate_limited", "breaches": [], "count": 0}
            resp.raise_for_status()
            data = resp.json()
            if not data.get("success"):
                return {"status": "clean", "breaches": [], "count": 0}
            sources = [s["name"] for s in data.get("sources", [])]
            return {"status": "breached", "breaches": sources, "count": data.get("found", len(sources))}
        except httpx.TimeoutException:
            return {"status": "error", "breaches": [], "count": 0}
        except Exception as e:
            return {"status": "error", "breaches": [], "count": 0, "error": str(e)}
