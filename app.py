import os
import requests
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, Response

app = FastAPI()

SUPABASE_URL = (os.getenv("SUPABASE_URL") or "").rstrip("/")
SERVICE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_SERVICE_KEY")
TIMEOUT = 10

if not SUPABASE_URL or not SERVICE_KEY:
    raise RuntimeError("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY/SUPABASE_SERVICE_KEY")


def _headers() -> dict:
    return {
        "apikey": SERVICE_KEY,
        "Authorization": f"Bearer {SERVICE_KEY}",
        "Content-Type": "application/json",
        "Prefer": "return=minimal",
    }


@app.get("/health")
async def health():
    return {"ok": True}


@app.get("/ssrf/{scan_id}/{probe_id}")
async def ssrf_callback(scan_id: str, probe_id: str, request: Request):
    ip = request.headers.get("x-forwarded-for") or (request.client.host if request.client else None)
    ua = request.headers.get("user-agent")

    url = f"{SUPABASE_URL}/rest/v1/ssrf_canary_callbacks"
    payload = {
        "scan_id": scan_id,
        "probe_id": probe_id,
        "source_ip": ip,
        "user_agent": ua,
    }

    try:
        r = requests.post(url, headers=_headers(), json=payload, timeout=TIMEOUT)
        if r.status_code >= 400:
            raise HTTPException(status_code=500, detail=f"failed to store callback: {r.status_code} {r.text[:300]}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"failed to store callback: {e}")

    return Response(status_code=204)


@app.get("/api/ssrf-seen/{scan_id}/{probe_id}")
async def ssrf_seen(scan_id: str, probe_id: str):
    url = (
        f"{SUPABASE_URL}/rest/v1/ssrf_canary_callbacks"
        f"?scan_id=eq.{scan_id}&probe_id=eq.{probe_id}&select=seen_at&order=seen_at.desc&limit=1"
    )

    try:
        r = requests.get(url, headers=_headers(), timeout=TIMEOUT)
        if r.status_code >= 400:
            raise HTTPException(status_code=500, detail=f"failed to query callback: {r.status_code} {r.text[:300]}")
        rows = r.json() if r.text else []
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"failed to query callback: {e}")

    return JSONResponse(
        {
            "received": len(rows) > 0,
            "last_seen_at": rows[0]["seen_at"] if rows else None,
        }
    )


