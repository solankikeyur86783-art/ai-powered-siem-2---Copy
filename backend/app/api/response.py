from fastapi import APIRouter, HTTPException
from datetime import datetime
from bson import ObjectId
from app.database.db import col
from app.services.llm_service import llm_service

router = APIRouter(prefix="/api/response", tags=["Response"])


def _serialize(doc) -> dict:
    if doc is None:
        return {}
    doc["id"] = str(doc.pop("_id", ""))
    return doc


@router.post("/recommend/{alert_id}")
async def get_response_recommendation(alert_id: str):
    """Get LLM-powered response recommendations for an alert"""
    try:
        doc = await col("alerts").find_one({"_id": ObjectId(alert_id)})
        if not doc:
            raise HTTPException(404, "Alert not found")
        doc["id"] = str(doc.pop("_id"))

        threat_doc = None
        if doc.get("threat_log_id"):
            threat_doc = await col("threat_logs").find_one({"_id": ObjectId(doc["threat_log_id"])})
            if threat_doc:
                threat_doc["id"] = str(threat_doc.pop("_id"))

        result = await llm_service.recommend_response(threat_doc or doc)

        # Save recommendations
        await col("alerts").update_one(
            {"_id": ObjectId(alert_id)},
            {"$set": {
                "response_recommendation": result,
                "recommended_actions": result.get("actions", []),
                "updated_at": datetime.utcnow()
            }}
        )
        return {"alert_id": alert_id, "recommendation": result}
    except Exception as e:
        raise HTTPException(400, str(e))


@router.post("/block-ip")
async def block_ip(data: dict):
    """Simulate IP blocking action (integrate with your firewall)"""
    ip = data.get("ip")
    reason = data.get("reason", "Threat detected by SIEM")
    if not ip:
        raise HTTPException(400, "IP address required")

    # Log the action
    action = {
        "timestamp": datetime.utcnow(),
        "agent_type": "responder",
        "action": f"block_ip:{ip}",
        "result": f"IP {ip} blocked — {reason}",
        "success": True,
        "details": {"ip": ip, "reason": reason}
    }
    await col("agent_actions").insert_one(action)

    # In production: call firewall API / Windows Firewall / pfSense / etc.
    return {"success": True, "message": f"IP {ip} blocked", "logged": True}


@router.post("/playbook/brute-force")
async def run_brute_force_playbook(data: dict):
    """Execute brute force response playbook"""
    source_ip = data.get("source_ip")
    alert_id = data.get("alert_id")

    steps = []

    # Step 1: Block IP
    steps.append({"step": 1, "action": "block_ip", "target": source_ip, "status": "executed"})

    # Step 2: Reset affected accounts
    steps.append({"step": 2, "action": "flag_accounts_for_reset", "status": "flagged"})

    # Step 3: Enable enhanced logging
    steps.append({"step": 3, "action": "enable_enhanced_logging", "status": "executed"})

    # Step 4: Notify SOC
    steps.append({"step": 4, "action": "notify_soc_team", "status": "sent"})

    # Log playbook execution
    await col("agent_actions").insert_one({
        "timestamp": datetime.utcnow(),
        "agent_type": "responder",
        "alert_id": alert_id,
        "action": "playbook:brute_force",
        "result": f"Brute force playbook executed against {source_ip}",
        "success": True,
        "details": {"steps": steps, "source_ip": source_ip}
    })

    if alert_id:
        try:
            await col("alerts").update_one(
                {"_id": ObjectId(alert_id)},
                {"$set": {"status": "investigating", "updated_at": datetime.utcnow()}}
            )
        except Exception:
            pass

    return {"success": True, "playbook": "brute_force", "steps_executed": steps}


@router.get("/history")
async def get_response_history(limit: int = 50):
    cursor = col("agent_actions").find().sort("timestamp", -1).limit(limit)
    docs = [_serialize(doc) async for doc in cursor]
    return {"actions": docs}
