from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from supabase import create_client
import os

app = FastAPI()
sb = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_SERVICE_ROLE_KEY"])

@app.get("/ssrf/{scan_id}/{probe_id}")
async def ssrf_callback(scan_id: str, probe_id: str, request: Request):
    ip = request.headers.get("x-forwarded-for") or (request.client.host if request.client else None)
    ua = request.headers.get("user-agent")
    sb.table("ssrf_canary_callbacks").insert({
        "scan_id": scan_id,
        "probe_id": probe_id,
        "source_ip": ip,
        "user_agent": ua
    }).execute()
    return Response(status_code=204)

@app.get("/api/ssrf-seen/{scan_id}/{probe_id}")
async def ssrf_seen(scan_id: str, probe_id: str):
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
    return JSONResponse({
        "received": len(rows) > 0,
        "last_seen_at": rows[0]["seen_at"] if rows else None
    })
