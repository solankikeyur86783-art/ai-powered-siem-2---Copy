"""
Threat Intelligence API — IP lookup, GeoIP, Map data
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Optional
from app.services.threat_intel import threat_intel
from app.core.auth_middleware import get_current_user
from app.database.db import col
from bson import ObjectId
from datetime import datetime

router = APIRouter(prefix="/api/intel", tags=["Threat Intelligence"])


@router.get("/ip/{ip}")
async def lookup_ip(ip: str, user: dict = Depends(get_current_user)):
    """Full IP intelligence — AbuseIPDB + GeoIP"""
    result = await threat_intel.enrich_ip(ip)
    return result


@router.get("/map-data")
async def get_map_data(
    hours: int = Query(24, ge=1, le=720),
    user: dict = Depends(get_current_user)
):
    """Get threat IP locations for map visualization"""
    data = await threat_intel.get_map_data(hours)
    return {"threats": data, "total": len(data)}


@router.post("/enrich/{alert_id}")
async def enrich_alert(alert_id: str, user: dict = Depends(get_current_user)):
    """Enrich an alert with threat intelligence"""
    try:
        doc = await col("alerts").find_one({"_id": ObjectId(alert_id)})
        if not doc:
            raise HTTPException(404, "Alert not found")

        ip = doc.get("source_ip")
        if not ip:
            return {"success": False, "message": "No source IP in alert"}

        intel = await threat_intel.enrich_ip(ip)

        await col("alerts").update_one(
            {"_id": ObjectId(alert_id)},
            {"$set": {
                "threat_intel": intel,
                "updated_at": datetime.utcnow()
            }}
        )

        return {"success": True, "alert_id": alert_id, "intel": intel}
    except Exception as e:
        raise HTTPException(400, str(e))


@router.get("/geoip/{ip}")
async def get_geoip(ip: str, user: dict = Depends(get_current_user)):
    """Get GeoIP data for an IP"""
    geo = await threat_intel.get_geoip(ip)
    return geo


@router.get("/abuse/{ip}")
async def get_abuse_info(ip: str, user: dict = Depends(get_current_user)):
    """Get AbuseIPDB data for an IP"""
    abuse = await threat_intel.abuseipdb.check_ip(ip)
    return abuse
