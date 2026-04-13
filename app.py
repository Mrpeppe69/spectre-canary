from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, Response
from supabase import create_client
import os

app = FastAPI()

supabase_url = os.getenv("SUPABASE_URL")
service_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_SERVICE_KEY")

if not supabase_url or not service_key:
    raise RuntimeError("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY/SUPABASE_SERVICE_KEY")

sb = create_client(supabase_url, service_key)

@app.get("/health")
async def health():
    return {"ok": True}

@app.get("/ssrf/{scan_id}/{probe_id}")
async def ssrf_callback(scan_id: str, probe_id: str, request: Request):
    ip = request.headers.get("x-forwarded-for") or (request.client.host if request.client else None)
    ua = request.headers.get("user-agent")
    try:
        sb.table("ssrf_canary_callbacks").insert({
            "scan_id": scan_id,
            "probe_id": probe_id,
            "source_ip": ip,
            "user_agent": ua
        }).execute()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"failed to store callback: {e}")
    return Response(status_code=204)

@app.get("/api/ssrf-seen/{scan_id}/{probe_id}")
async def ssrf_seen(scan_id: str, probe_id: str):
    try:
        rows = (
            sb.table("ssrf_canary_callbacks")
            .select("seen_at")
            .eq("scan_id", scan_id)
            .eq("probe_id", probe_id)
            .order("seen_at", desc=True)
            .limit(1)
            .execute()
            .data or []
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"failed to query callback: {e}")

    return JSONResponse({
        "received": len(rows) > 0,
        "last_seen_at": rows[0]["seen_at"] if rows else None
    })

