from fastapi import APIRouter, Query, HTTPException
from typing import Optional, List
from datetime import datetime, timedelta
from bson import ObjectId
from loguru import logger

from app.database.db import col
from app.schemas.schemas import RawLogCreate
from app.pipeline.ingestion_pipeline import pipeline

router = APIRouter(prefix="/api/logs", tags=["Logs"])


def _serialize(doc) -> dict:
    if doc is None:
        return {}
    doc["id"] = str(doc.pop("_id", ""))
    return doc


@router.post("/ingest")
async def ingest_log(log: RawLogCreate):
    """Manually ingest a log entry through the full pipeline"""
    result = await pipeline.ingest_sync(log.model_dump())
    return {"success": True, "result": result}


@router.post("/ingest/bulk")
async def ingest_bulk(logs: List[RawLogCreate]):
    """Bulk ingest multiple logs"""
    results = []
    for log in logs[:100]:  # Cap at 100 per request
        result = await pipeline.ingest_sync(log.model_dump())
        results.append(result)
    return {"success": True, "count": len(results), "results": results}


@router.post("/ingest/raw")
async def ingest_raw(data: dict):
    """Ingest raw log data (Winlogbeat format, syslog, etc.)"""
    result = await pipeline.ingest_sync(data)
    return {"success": True, "result": result}


@router.get("/")
async def get_logs(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    source: Optional[str] = None,
    hostname: Optional[str] = None,
    log_level: Optional[str] = None,
    hours: int = Query(24, ge=1, le=168),
    search: Optional[str] = None
):
    """Get paginated raw logs"""
    query = {"timestamp": {"$gte": datetime.utcnow() - timedelta(hours=hours)}}
    if source:
        query["source"] = source
    if hostname:
        query["hostname"] = {"$regex": hostname, "$options": "i"}
    if log_level:
        query["log_level"] = log_level.upper()
    if search:
        query["message"] = {"$regex": search, "$options": "i"}

    total = await col("raw_logs").count_documents(query)
    skip = (page - 1) * limit
    cursor = col("raw_logs").find(query, {"raw": 0}).sort("timestamp", -1).skip(skip).limit(limit)
    docs = [_serialize(doc) async for doc in cursor]

    return {
        "total": total,
        "page": page,
        "pages": (total + limit - 1) // limit,
        "logs": docs
    }


@router.get("/threats")
async def get_threat_logs(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    severity: Optional[str] = None,
    threat_type: Optional[str] = None,
    hours: int = Query(24, ge=1, le=168),
    status: Optional[str] = None
):
    """Get threat logs"""
    query = {"timestamp": {"$gte": datetime.utcnow() - timedelta(hours=hours)}}
    if severity:
        query["severity"] = severity
    if threat_type:
        query["threat_type"] = threat_type
    if status:
        query["status"] = status

    total = await col("threat_logs").count_documents(query)
    skip = (page - 1) * limit
    cursor = col("threat_logs").find(query).sort("timestamp", -1).skip(skip).limit(limit)
    docs = [_serialize(doc) async for doc in cursor]

    return {"total": total, "page": page, "logs": docs}


@router.get("/stats")
async def get_log_stats(hours: int = Query(24, ge=1, le=168)):
    """Get log statistics"""
    since = datetime.utcnow() - timedelta(hours=hours)

    total = await col("raw_logs").count_documents({"timestamp": {"$gte": since}})
    threats = await col("threat_logs").count_documents({"timestamp": {"$gte": since}})

    # Per-hour breakdown
    pipeline_agg = [
        {"$match": {"timestamp": {"$gte": since}}},
        {"$group": {
            "_id": {"$dateToString": {"format": "%Y-%m-%dT%H:00:00Z", "date": "$timestamp"}},
            "count": {"$sum": 1}
        }},
        {"$sort": {"_id": 1}}
    ]
    hourly = [doc async for doc in col("raw_logs").aggregate(pipeline_agg)]

    # Top sources
    source_agg = [
        {"$match": {"timestamp": {"$gte": since}, "source_ip": {"$ne": None}}},
        {"$group": {"_id": "$source_ip", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 10}
    ]
    top_ips = [{"ip": d["_id"], "count": d["count"]} async for d in col("raw_logs").aggregate(source_agg)]

    return {
        "total_logs": total,
        "total_threats": threats,
        "threat_rate": round(threats / total * 100, 2) if total > 0 else 0,
        "hourly_breakdown": hourly,
        "top_source_ips": top_ips,
        "pipeline_stats": pipeline.get_stats()
    }


@router.get("/{log_id}")
async def get_log(log_id: str):
    """Get a specific log by ID"""
    try:
        doc = await col("raw_logs").find_one({"_id": ObjectId(log_id)})
        if not doc:
            raise HTTPException(status_code=404, detail="Log not found")
        return _serialize(doc)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
