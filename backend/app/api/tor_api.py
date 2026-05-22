"""
Tor Detection API
━━━━━━━━━━━━━━━━
GET  /api/tor/status           — Feed health, node count, last refresh
GET  /api/tor/check-ip/{ip}   — Check if IP is a known Tor exit node
POST /api/tor/scan             — Scan recent threat logs against Tor list
POST /api/tor/behavioral       — Behavioral signal analysis for an event
POST /api/tor/ir/{ip}          — Trigger full IR workflow for a Tor IP
GET  /api/tor/alerts           — Get all Tor-related alerts
GET  /api/tor/tickets          — Get IR tickets for Tor incidents
POST /api/tor/refresh          — Force-refresh the Tor exit node list
"""
from fastapi import APIRouter, HTTPException, Query, Depends
from typing import Optional
from datetime import datetime, timedelta
from app.services.tor_detection import tor_detection
from app.core.auth_middleware import get_current_user
from app.database.db import col

router = APIRouter(prefix="/api/tor", tags=["Tor Detection"])


def _serialize(doc) -> dict:
    if doc is None:
        return {}
    doc["id"] = str(doc.pop("_id", ""))
    return doc


# ── Feed Status ──────────────────────────────────────────────

@router.get("/status")
async def get_tor_status(user: dict = Depends(get_current_user)):
    """Feed health, node count, last refresh time."""
    status = tor_detection.get_status()
    # Also pull DB-persisted metadata
    meta = await col("tor_feed_meta").find_one({"_id": "status"})
    if meta:
        meta.pop("_id", None)
        status["db_meta"] = meta
    return status


# ── IP Check ─────────────────────────────────────────────────

@router.get("/check-ip/{ip}")
async def check_ip(ip: str, user: dict = Depends(get_current_user)):
    """Check if an IP address is a known Tor exit node."""
    try:
        result = await tor_detection.check_ip(ip)
        # If it's a Tor node, also trigger alert creation
        if result["is_tor_exit_node"]:
            alert_id = await tor_detection.create_tor_alert_for_ip(ip)
            result["alert_created"] = alert_id is not None
            result["alert_id"] = alert_id
        return result
    except Exception as e:
        raise HTTPException(500, f"Check failed: {e}")


# ── Scan Recent Logs ─────────────────────────────────────────

@router.post("/scan")
async def scan_logs(
    hours: int = Query(24, ge=1, le=168),
    user: dict = Depends(get_current_user)
):
    """Scan recent threat logs for Tor exit-node IPs. Creates HIGH alerts on match."""
    try:
        result = await tor_detection.scan_recent_logs(hours=hours)
        return result
    except Exception as e:
        raise HTTPException(500, f"Scan failed: {e}")


# ── Behavioral Analysis ──────────────────────────────────────

@router.post("/behavioral")
async def behavioral_analysis(event: dict, user: dict = Depends(get_current_user)):
    """
    Analyze a log event for Tor-like behavioral signals.
    Body: { source_ip, dest_port, request_count, unique_ua_count, user_agent, protocol, is_encrypted }
    Flags SUSPICIOUS if ≥3 signals match.
    """
    result = tor_detection.analyze_behavioral_signals(event)

    # If suspicious, create a behavioral Tor alert
    if result["is_suspicious"]:
        ip = event.get("source_ip", "unknown")
        doc = {"count": event.get("request_count", 1), "threat_types": ["behavioral_tor"]}
        alert_id = await tor_detection._create_tor_alert(ip, doc)
        result["alert_created"] = alert_id is not None
        result["alert_id"] = alert_id

    return result


# ── IR Workflow ──────────────────────────────────────────────

@router.post("/ir/{ip}")
async def trigger_ir_workflow(
    ip: str,
    alert_id: Optional[str] = None,
    user: dict = Depends(get_current_user)
):
    """
    Trigger full Incident Response workflow for a Tor IP:
    block → IR ticket → SOC webhook → forensic log.
    """
    try:
        result = await tor_detection.trigger_ir_workflow(ip, alert_id)
        return result
    except Exception as e:
        raise HTTPException(500, f"IR workflow failed: {e}")


# ── Force Refresh ────────────────────────────────────────────

@router.post("/refresh")
async def force_refresh(user: dict = Depends(get_current_user)):
    """Force an immediate refresh of the Tor exit-node list."""
    result = await tor_detection.refresh_feed()
    return result


# ── Tor Alerts ───────────────────────────────────────────────

@router.get("/alerts")
async def get_tor_alerts(
    hours: int = Query(24, ge=1, le=720),
    limit: int = Query(50, ge=1, le=200),
    user: dict = Depends(get_current_user)
):
    """Get all Tor-related alerts ordered by creation time."""
    since = datetime.utcnow() - timedelta(hours=hours)
    cursor = col("alerts").find(
        {"rule_id": {"$in": ["TOR_EXIT_NODE", "builtin_tor_traffic", "builtin_tor_bruteforce", "builtin_tor_exfil"]}, "created_at": {"$gte": since}}
    ).sort("created_at", -1).limit(limit)
    docs = [_serialize(doc) async for doc in cursor]
    total = await col("alerts").count_documents(
        {"rule_id": {"$in": ["TOR_EXIT_NODE", "builtin_tor_traffic", "builtin_tor_bruteforce", "builtin_tor_exfil"]}, "created_at": {"$gte": since}}
    )
    return {"total": total, "alerts": docs}


# ── IR Tickets ───────────────────────────────────────────────

@router.get("/tickets")
async def get_ir_tickets(
    limit: int = Query(50, ge=1, le=200),
    user: dict = Depends(get_current_user)
):
    """Get IR tickets created for Tor incidents."""
    cursor = col("ir_tickets").find(
        {"type": "tor_incident"}
    ).sort("created_at", -1).limit(limit)
    docs = [_serialize(doc) async for doc in cursor]
    return {"total": len(docs), "tickets": docs}


# ── Blocked Tor IPs ──────────────────────────────────────────

@router.get("/blocked")
async def get_blocked_tor_ips(user: dict = Depends(get_current_user)):
    """Get IPs that were auto-blocked due to Tor detection."""
    cursor = col("blocked_ips").find(
        {"reason": "tor_exit_node"}
    ).sort("blocked_at", -1)
    docs = [_serialize(doc) async for doc in cursor]
    return {"total": len(docs), "blocked_ips": docs}


# ── Dashboard Stats ──────────────────────────────────────────

@router.get("/stats")
async def get_tor_stats(
    hours: int = Query(24, ge=1, le=720),
    user: dict = Depends(get_current_user)
):
    """Aggregated Tor detection stats for the dashboard widget."""
    since = datetime.utcnow() - timedelta(hours=hours)
    alerts_count = await col("alerts").count_documents(
        {"rule_id": {"$in": ["TOR_EXIT_NODE", "builtin_tor_traffic", "builtin_tor_bruteforce", "builtin_tor_exfil"]}, "created_at": {"$gte": since}}
    )
    tickets_count = await col("ir_tickets").count_documents(
        {"type": "tor_incident", "created_at": {"$gte": since}}
    )
    blocked_count = await col("blocked_ips").count_documents(
        {"reason": "tor_exit_node"}
    )
    status = tor_detection.get_status()
    return {
        "feed_ok": status["feed_ok"],
        "node_count": status["node_count"],
        "last_refresh": status["last_refresh"],
        "tor_alerts_24h": alerts_count,
        "ir_tickets_24h": tickets_count,
        "blocked_ips_total": blocked_count,
        "hours": hours,
    }
