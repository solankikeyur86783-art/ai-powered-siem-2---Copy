"""
Notification API — Settings, Test, History
"""
from fastapi import APIRouter, Depends
from datetime import datetime, timedelta
from app.database.db import col
from app.services.notifications import notification_manager
from app.core.auth_middleware import get_current_user

router = APIRouter(prefix="/api/notifications", tags=["Notifications"])


def _serialize(doc):
    if doc is None:
        return {}
    doc["id"] = str(doc.pop("_id", ""))
    return doc


@router.get("/settings")
async def get_notification_settings(user: dict = Depends(get_current_user)):
    return await notification_manager.get_settings()


@router.put("/settings")
async def update_notification_settings(settings: dict, user: dict = Depends(get_current_user)):
    return await notification_manager.update_settings(settings)


@router.post("/test")
async def test_notification(data: dict, user: dict = Depends(get_current_user)):
    """Send a test Slack notification"""
    sev = data.get("severity", "high")
    test_alert = {
        "title": "🧪 Test Alert — CortexSIEM",
        "description": "This is a test notification from CortexSIEM v3.0",
        "severity": sev,
        "source_ip": "192.168.1.100",
        "hostname": "TEST-WORKSTATION",
        "rule_id": "test_rule",
        "timestamp": datetime.utcnow().isoformat(),
    }

    result = await notification_manager.slack.send(test_alert)
    
    # Log it so UI updates
    await col("notification_log").insert_one({
        "timestamp": datetime.utcnow(),
        "alert_title": test_alert["title"],
        "severity": sev,
        "channels": ["slack (test)"],
        "results": [result],
        "status": "sent" if result.get("sent") else "failed"
    })

    return {"success": True, "results": [result]}


@router.get("/history")
async def get_notification_history(
    limit: int = 50,
    hours: int = 24,
    user: dict = Depends(get_current_user)
):
    since = datetime.utcnow() - timedelta(hours=hours)
    cursor = col("notification_log").find(
        {"timestamp": {"$gte": since}}
    ).sort("timestamp", -1).limit(limit)
    docs = [_serialize(doc) async for doc in cursor]
    total = await col("notification_log").count_documents({"timestamp": {"$gte": since}})
    return {"total": total, "notifications": docs}
