"""
Forensics API — Evidence collection and case management
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Optional
from bson import ObjectId
from app.services.forensics import forensics_service
from app.core.auth_middleware import get_current_user
from app.database.db import col

router = APIRouter(prefix="/api/forensics", tags=["Forensics"])


@router.post("/collect/{alert_id}")
async def collect_evidence(alert_id: str, user: dict = Depends(get_current_user)):
    """Collect forensic evidence for an alert"""
    result = await forensics_service.collect_evidence(
        alert_id, collected_by=user.get("username", "system")
    )
    if "error" in result:
        raise HTTPException(404, result["error"])
    return {"success": True, "case": result}


@router.get("/cases")
async def list_cases(
    limit: int = Query(20, ge=1, le=100),
    user: dict = Depends(get_current_user)
):
    cases = await forensics_service.list_cases(limit)
    return {"cases": cases, "total": len(cases)}


@router.get("/cases/{case_id}")
async def get_case(case_id: str, user: dict = Depends(get_current_user)):
    case = await forensics_service.get_case(case_id)
    if not case:
        raise HTTPException(404, "Case not found")
    return case


@router.post("/cases/{case_id}/note")
async def add_note(case_id: str, data: dict, user: dict = Depends(get_current_user)):
    note = data.get("note", "")
    if not note:
        raise HTTPException(400, "Note text required")
    await forensics_service.add_note(case_id, note, user.get("username", "unknown"))
    return {"success": True}


@router.post("/cases/{case_id}/artifact")
async def add_artifact(case_id: str, data: dict, user: dict = Depends(get_current_user)):
    name = data.get("name")
    if not name:
        raise HTTPException(400, "Artifact name required")
    await forensics_service.add_artifact(case_id, data)
    return {"success": True}


@router.get("/cases/{case_id}/export")
async def export_case(case_id: str, user: dict = Depends(get_current_user)):
    """Export case as JSON"""
    case = await forensics_service.get_case(case_id)
    if not case:
        raise HTTPException(404, "Case not found")
    from fastapi.responses import JSONResponse
    return JSONResponse(
        content=case,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=forensic_case_{case_id}.json"}
    )


@router.post("/timeline/{ip}")
async def ip_timeline(
    ip: str,
    data: dict = {},
    user: dict = Depends(get_current_user)
):
    hours = data.get("hours", 48)
    timeline = await forensics_service.ip_timeline(ip, hours)
    return {"ip": ip, "timeline": timeline, "total_events": len(timeline)}


@router.delete("/cases/{case_id}")
async def delete_case(case_id: str, user: dict = Depends(get_current_user)):
    try:
        result = await col("forensic_cases").delete_one({"_id": ObjectId(case_id)})
        if result.deleted_count == 0:
            raise HTTPException(404, "Case not found")
        return {"success": True}
    except Exception as e:
        raise HTTPException(400, str(e))
