"""
Report API — Generate, List, Download reports
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from typing import Optional
from bson import ObjectId
from app.services.report_service import report_service
from app.core.auth_middleware import get_current_user
from app.database.db import col

router = APIRouter(prefix="/api/reports", tags=["Reports"])


@router.post("/generate")
async def generate_report(data: dict, user: dict = Depends(get_current_user)):
    """Generate a new security report"""
    report_type = data.get("report_type", "executive")
    hours = data.get("hours", 24)

    report = await report_service.generate_report(
        report_type=report_type,
        hours=hours,
        generated_by=user.get("username", "system")
    )
    return {"success": True, "report": report}


@router.get("/")
async def list_reports(
    limit: int = Query(20, ge=1, le=100),
    user: dict = Depends(get_current_user)
):
    """List generated reports"""
    reports = await report_service.list_reports(limit)
    return {"reports": reports}


@router.get("/{report_id}")
async def get_report(report_id: str, user: dict = Depends(get_current_user)):
    """Get full report details"""
    report = await report_service.get_report(report_id)
    if not report:
        raise HTTPException(404, "Report not found")
    return report


@router.delete("/{report_id}")
async def delete_report(report_id: str, user: dict = Depends(get_current_user)):
    try:
        result = await col("reports").delete_one({"_id": ObjectId(report_id)})
        if result.deleted_count == 0:
            raise HTTPException(404, "Report not found")
        return {"success": True}
    except Exception as e:
        raise HTTPException(400, str(e))
