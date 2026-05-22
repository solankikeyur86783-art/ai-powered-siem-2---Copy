"""
Honeypot API — Control honeypots, view captures
"""
from fastapi import APIRouter, Depends, Query
from app.services.honeypot import honeypot_service
from app.core.auth_middleware import get_current_user

router = APIRouter(prefix="/api/honeypot", tags=["Honeypot"])


@router.get("/status")
async def honeypot_status(user: dict = Depends(get_current_user)):
    return honeypot_service.get_status()


@router.post("/start")
async def start_honeypot(data: dict, user: dict = Depends(get_current_user)):
    service = data.get("service", "ssh")
    port = data.get("port")
    result = await honeypot_service.start_honeypot(service, port)
    return result


@router.post("/stop")
async def stop_honeypot(data: dict, user: dict = Depends(get_current_user)):
    service = data.get("service", "ssh")
    result = await honeypot_service.stop_honeypot(service)
    return result


@router.post("/stop-all")
async def stop_all(user: dict = Depends(get_current_user)):
    await honeypot_service.stop_all()
    return {"success": True}


@router.get("/captures")
async def get_captures(
    hours: int = Query(24, ge=1, le=720),
    limit: int = Query(100, ge=1, le=500),
    user: dict = Depends(get_current_user)
):
    captures = await honeypot_service.get_captures(hours, limit)
    return {"captures": captures, "total": len(captures)}


@router.get("/stats")
async def get_stats(
    hours: int = Query(24, ge=1, le=720),
    user: dict = Depends(get_current_user)
):
    return await honeypot_service.get_stats(hours)
