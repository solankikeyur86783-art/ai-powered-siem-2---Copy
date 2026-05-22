from fastapi import APIRouter, Query, HTTPException
from typing import Optional
from datetime import datetime, timedelta
from bson import ObjectId

from app.database.db import col
from app.schemas.schemas import AlertUpdate
from app.services.llm_service import llm_service

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])


def _serialize(doc) -> dict:
    if doc is None:
        return {}
    doc["id"] = str(doc.pop("_id", ""))
    return doc


@router.get("/")
async def get_alerts(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    hours: int = Query(24, ge=1, le=720),
    search: Optional[str] = None
):
    query = {"created_at": {"$gte": datetime.utcnow() - timedelta(hours=hours)}}
    if severity:
        query["severity"] = severity
    if status:
        query["status"] = status
    if search:
        query["$or"] = [
            {"title": {"$regex": search, "$options": "i"}},
            {"description": {"$regex": search, "$options": "i"}},
            {"source_ip": {"$regex": search, "$options": "i"}}
        ]

    total = await col("alerts").count_documents(query)
    skip = (page - 1) * limit
    cursor = col("alerts").find(query).sort("created_at", -1).skip(skip).limit(limit)
    docs = [_serialize(doc) async for doc in cursor]

    return {"total": total, "page": page, "pages": (total + limit - 1) // limit, "alerts": docs}


@router.get("/summary")
async def get_alert_summary(hours: int = Query(24, ge=1, le=168)):
    since = datetime.utcnow() - timedelta(hours=hours)
    query = {"created_at": {"$gte": since}}

    total = await col("alerts").count_documents(query)
    open_count = await col("alerts").count_documents({**query, "status": "open"})
    critical = await col("alerts").count_documents({**query, "severity": "critical"})
    high = await col("alerts").count_documents({**query, "severity": "high"})
    medium = await col("alerts").count_documents({**query, "severity": "medium"})
    low = await col("alerts").count_documents({**query, "severity": "low"})

    # Trend by hour
    pipeline_agg = [
        {"$match": query},
        {"$group": {
            "_id": {
                "hour": {"$dateToString": {"format": "%Y-%m-%dT%H:00:00Z", "date": "$created_at"}},
                "severity": "$severity"
            },
            "count": {"$sum": 1}
        }},
        {"$sort": {"_id.hour": 1}}
    ]
    trend = [doc async for doc in col("alerts").aggregate(pipeline_agg)]

    return {
        "total": total,
        "open": open_count,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "trend": trend
    }


@router.get("/{alert_id}")
async def get_alert(alert_id: str):
    try:
        doc = await col("alerts").find_one({"_id": ObjectId(alert_id)})
        if not doc:
            raise HTTPException(404, "Alert not found")
        return _serialize(doc)
    except Exception as e:
        raise HTTPException(400, str(e))


@router.patch("/{alert_id}")
async def update_alert(alert_id: str, update: AlertUpdate):
    try:
        update_data = {k: v for k, v in update.model_dump().items() if v is not None}
        update_data["updated_at"] = datetime.utcnow()
        result = await col("alerts").update_one(
            {"_id": ObjectId(alert_id)},
            {"$set": update_data}
        )
        if result.matched_count == 0:
            raise HTTPException(404, "Alert not found")
        doc = await col("alerts").find_one({"_id": ObjectId(alert_id)})
        return _serialize(doc)
    except Exception as e:
        raise HTTPException(400, str(e))


@router.post("/{alert_id}/investigate")
async def investigate_alert(alert_id: str):
    """Trigger LLM deep investigation of an alert"""
    try:
        doc = await col("alerts").find_one({"_id": ObjectId(alert_id)})
        if not doc:
            raise HTTPException(404, "Alert not found")

        # Get related threat logs
        threat_logs = []
        if doc.get("source_ip"):
            cursor = col("threat_logs").find(
                {"source_ip": doc["source_ip"]},
                {"raw": 0}
            ).sort("timestamp", -1).limit(5)
            threat_logs = [_serialize(t) async for t in cursor]

        investigation = await llm_service.investigate_alert(
            {**doc, "id": str(doc["_id"])},
            threat_logs
        )

        # Save investigation result
        await col("alerts").update_one(
            {"_id": ObjectId(alert_id)},
            {"$set": {
                "investigation": investigation,
                "status": "investigating",
                "updated_at": datetime.utcnow()
            }}
        )

        return {"alert_id": alert_id, "investigation": investigation}
    except Exception as e:
        raise HTTPException(400, str(e))


@router.delete("/{alert_id}")
async def delete_alert(alert_id: str):
    try:
        result = await col("alerts").delete_one({"_id": ObjectId(alert_id)})
        if result.deleted_count == 0:
            raise HTTPException(404, "Alert not found")
        return {"success": True}
    except Exception as e:
        raise HTTPException(400, str(e))
