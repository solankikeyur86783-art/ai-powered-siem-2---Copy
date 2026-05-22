import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..'))

from fastapi import APIRouter, HTTPException, Query
from typing import Optional, Any
from datetime import datetime, timedelta
from bson import ObjectId
from app.database.db import col

router = APIRouter(prefix="/api/agents", tags=["Agents"])


def _serialize(obj) -> Any:
    if isinstance(obj, dict):
        return {k: _serialize(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_serialize(i) for i in obj]
    elif isinstance(obj, (datetime, ObjectId)):
        return str(obj)
    return obj


@router.get("/actions")
async def get_agent_actions(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    agent_type: Optional[str] = None,
    hours: int = Query(24, ge=1, le=168)
):
    from loguru import logger
    since = datetime.utcnow() - timedelta(hours=hours)
    match_query = {"timestamp": {"$gte": since}}
    if agent_type:
        match_query["agent_type"] = agent_type

    pipeline = [
        {"$match": match_query},
        {"$sort": {"timestamp": -1}},
        {"$skip": (page - 1) * limit},
        {"$limit": limit},
        # Join with alerts to get human-readable titles
        {"$lookup": {
            "from": "alerts",
            "let": {"aid": "$alert_id"},
            "pipeline": [
                {"$match": {
                    "$expr": {
                        "$and": [
                            {"$ne": ["$$aid", None]},
                            {"$or": [
                                {"$eq": ["$_id", {"$convert": {"input": "$$aid", "to": "objectId", "onError": "$$aid"}}]},
                                {"$eq": ["$id", "$$aid"]}
                            ]}
                        ]
                    }
                }},
                {"$project": {"title": 1, "hostname": 1, "severity": 1, "source_ip": 1}}
            ],
            "as": "alert_info"
        }},
        {"$unwind": {"path": "$alert_info", "preserveNullAndEmptyArrays": True}}
    ]

    cursor = col("agent_actions").aggregate(pipeline)
    docs = []
    async for doc in cursor:
        try:
            # Robust serialization
            doc["id"] = str(doc.pop("_id", "")) if "_id" in doc else doc.get("id", "")
            doc["alert_title"] = doc.get("alert_info", {}).get("title") or doc.get("alert_id") or "System Task"
            doc["hostname"] = doc.get("alert_info", {}).get("hostname") or "N/A"
            doc["alert_severity"] = doc.get("alert_info", {}).get("severity") or "unknown"
            doc["source_ip"] = doc.get("alert_info", {}).get("source_ip") or "N/A"
            
            # Normalize legacy records: fallback agent_type from agent field
            if not doc.get("agent_type") and doc.get("agent"):
                doc["agent_type"] = doc["agent"]
            # Normalize legacy records: infer success from status field
            if "success" not in doc or doc["success"] is None:
                doc["success"] = doc.get("status") in ("completed", "success")

            # Ensure timestamp is string for serialization
            if "timestamp" in doc and isinstance(doc["timestamp"], datetime):
                doc["timestamp"] = doc["timestamp"].isoformat()

            docs.append(doc)
        except Exception as e:
            logger.error(f"Error processing action doc: {e}")

    total = await col("agent_actions").count_documents(match_query)
    return _serialize({"total": total, "page": page, "actions": docs})


@router.get("/live-feed")
async def get_live_feed(
    limit: int = Query(30, ge=1, le=100),
    hours: int = Query(24, ge=1, le=168)
):
    """Get recent agent activity with full details for the live feed."""
    since = datetime.utcnow() - timedelta(hours=hours)
    
    cursor = col("agent_actions").find(
        {"timestamp": {"$gte": since}}
    ).sort("timestamp", -1).limit(limit)
    
    actions = []
    async for doc in cursor:
        doc["id"] = str(doc.pop("_id", ""))
        if isinstance(doc.get("timestamp"), datetime):
            doc["timestamp"] = doc["timestamp"].isoformat()
        
        # Normalize legacy records: fallback agent_type from agent field
        if not doc.get("agent_type") and doc.get("agent"):
            doc["agent_type"] = doc["agent"]
        # Normalize legacy records: infer success from status field
        if "success" not in doc or doc["success"] is None:
            doc["success"] = doc.get("status") in ("completed", "success")

        # Get alert title
        alert_id = doc.get("alert_id")
        if alert_id:
            try:
                query = {"_id": ObjectId(alert_id)} if len(alert_id) == 24 else {"id": alert_id}
                alert_doc = await col("alerts").find_one(query, {"title": 1, "severity": 1, "source_ip": 1})
                if alert_doc:
                    doc["alert_title"] = alert_doc.get("title", "Unknown")
                    doc["alert_severity"] = alert_doc.get("severity", "unknown")
                    doc["source_ip"] = alert_doc.get("source_ip", "N/A")
            except Exception:
                pass
        
        actions.append(doc)
    
    # Get pipeline stats
    total_today = await col("agent_actions").count_documents({"timestamp": {"$gte": since}})
    successful = await col("agent_actions").count_documents({"timestamp": {"$gte": since}, "success": True})
    blocked_count = await col("blocked_ips").count_documents({"active": True})
    forensic_count = await col("forensic_cases").count_documents({"collected_by": "forensics_agent_auto"})
    
    return _serialize({
        "actions": actions,
        "stats": {
            "total_actions": total_today,
            "successful": successful,
            "success_rate": round(successful / total_today * 100, 1) if total_today > 0 else 0,
            "blocked_ips": blocked_count,
            "auto_forensic_cases": forensic_count,
        }
    })


@router.get("/blocked-ips")
async def get_blocked_ips():
    """Get all auto-blocked IPs."""
    cursor = col("blocked_ips").find({"active": True}).sort("blocked_at", -1)
    blocked = []
    async for doc in cursor:
        doc["id"] = str(doc.pop("_id", ""))
        if isinstance(doc.get("blocked_at"), datetime):
            doc["blocked_at"] = doc["blocked_at"].isoformat()
        blocked.append(doc)
    
    total_ever = await col("blocked_ips").count_documents({})
    active = await col("blocked_ips").count_documents({"active": True})
    
    return _serialize({
        "blocked": blocked,
        "total_ever_blocked": total_ever,
        "currently_active": active,
    })


@router.post("/unblock/{ip}")
async def unblock_ip(ip: str):
    """Unblock a previously blocked IP."""
    from agents.agent_manager import agent_manager
    result = await agent_manager.unblock_ip(ip)
    if not result.get("success"):
        raise HTTPException(500, result.get("error", "Unblock failed"))
    return result


@router.post("/run/{alert_id}")
async def run_agents_on_alert(alert_id: str):
    """Trigger all agents to analyze and respond to an alert"""
    try:
        # Handle both real ObjectId and simulated IDs
        from bson import ObjectId
        if len(alert_id) == 24 and all(c in "0123456789abcdef" for c in alert_id.lower()):
            query = {"_id": ObjectId(alert_id)}
        else:
            query = {"id": alert_id}

        doc = await col("alerts").find_one(query)
        if not doc:
            raise HTTPException(404, "Alert not found")
        
        doc["id"] = str(doc.pop("_id", "")) if "_id" in doc else doc.get("id")
        from agents.agent_manager import agent_manager
        result = await agent_manager.handle_alert(doc)
        return {"success": True, "alert_id": alert_id, "result": result}
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(500, f"Error: {e}")


@router.post("/deploy")
async def deploy_agent(data: dict):
    """Register and deploy a new security agent"""
    name = data.get("name")
    agent_type = data.get("type", "custom_agent")
    if not name:
        raise HTTPException(400, "Agent name is required")
    
    agent = {
        "name": name,
        "type": agent_type,
        "status": "operational",
        "created_at": datetime.utcnow()
    }
    await col("agents").update_one({"name": name}, {"$set": agent}, upsert=True)
    return {"success": True, "agent": name}


@router.delete("/{agent_id}")
async def delete_agent(agent_id: str):
    """Remove a registered agent and its action history"""
    from loguru import logger
    from bson import ObjectId

    # Try matching by ObjectId first, then by name
    query = None
    if len(agent_id) == 24 and all(c in "0123456789abcdef" for c in agent_id.lower()):
        query = {"_id": ObjectId(agent_id)}
    else:
        query = {"_id": ObjectId(agent_id)} if ObjectId.is_valid(agent_id) else {"name": agent_id}

    doc = await col("agents").find_one(query)
    if not doc:
        raise HTTPException(404, "Agent not found")

    agent_name = doc.get("name", "")
    result = await col("agents").delete_one({"_id": doc["_id"]})

    # Clean up action logs for this agent
    deleted_actions = await col("agent_actions").delete_many({"agent_type": agent_name})
    logger.info(f"🗑️ Deleted agent '{agent_name}' and {deleted_actions.deleted_count} action logs")

    return {
        "success": True,
        "deleted_agent": agent_name,
        "deleted_actions": deleted_actions.deleted_count
    }


@router.get("/status")
async def agent_status():
    """Get agent system status"""
    # 1. Get agents from database
    agents_cursor = col("agents").find()
    agents_list = []
    async for doc in agents_cursor:
        doc["id"] = str(doc.pop("_id", "")) if "_id" in doc else doc.get("id", "")
        if "created_at" in doc and isinstance(doc["created_at"], datetime):
            doc["created_at"] = doc["created_at"].isoformat()
        if "last_active" in doc and isinstance(doc["last_active"], datetime):
            doc["last_active"] = doc["last_active"].isoformat()
        agents_list.append(doc)
    
    # 2. auto-initialize if empty
    if not agents_list:
        defaults = [
            {
                "name": "soc_agent", 
                "type": "ai_agent", 
                "status": "operational",
                "description": "Initial triage and severity assessment of security alerts.",
                "icon": "Shield",
                "category": "Core"
            },
            {
                "name": "analyst_agent", 
                "type": "ai_agent", 
                "status": "operational",
                "description": "Deep investigation and correlation of related security events.",
                "icon": "Search",
                "category": "Investigation"
            },
            {
                "name": "responder_agent", 
                "type": "ai_agent", 
                "status": "operational",
                "description": "Automated containment, IP blocking, and remediation for confirmed threats.",
                "icon": "Zap",
                "category": "Response"
            },
            {
                "name": "hunter_agent", 
                "type": "hunter_agent", 
                "status": "operational",
                "description": "Proactive threat hunting — scans for credential stuffing, repeat offenders, and multi-vector attacks.",
                "icon": "Crosshair",
                "category": "Proactive"
            },
            {
                "name": "forensics_agent", 
                "type": "forensics_agent", 
                "status": "operational",
                "description": "Auto-collects evidence, builds timelines, creates forensic cases for investigation.",
                "icon": "Archive",
                "category": "Investigation"
            }
        ]
        for d in defaults:
            d["created_at"] = datetime.utcnow()
            d["last_active"] = datetime.utcnow()
            res = await col("agents").insert_one(d)
            d["id"] = str(res.inserted_id)
            agents_list.append(d)

    since = datetime.utcnow() - timedelta(hours=24)
    total = await col("agent_actions").count_documents({"timestamp": {"$gte": since}})
    successful = await col("agent_actions").count_documents({"timestamp": {"$gte": since}, "success": True})
    blocked_count = await col("blocked_ips").count_documents({"active": True})
    forensic_auto = await col("forensic_cases").count_documents({"collected_by": "forensics_agent_auto"})

    by_type_agg = [
        {"$match": {"timestamp": {"$gte": since}}},
        {"$group": {"_id": "$agent_type", "count": {"$sum": 1}, "success": {"$sum": {"$cond": ["$success", 1, 0]}}}},
    ]
    by_type = [doc async for doc in col("agent_actions").aggregate(by_type_agg)]

    return _serialize({
        "status": "operational",
        "agents": agents_list,
        "actions_today": total,
        "success_rate": round(successful / total * 100, 1) if total > 0 else 0,
        "by_agent_type": by_type,
        "blocked_ips_count": blocked_count,
        "auto_forensic_cases": forensic_auto,
    })


@router.post("/test_all")
async def security_drill():
    """Run a full security drill testing all 5 agent types"""
    try:
        from agents.agent_manager import agent_manager
        
        # 1. Find a suitable high-priority target
        doc = await col("alerts").find_one({"severity": {"$in": ["high", "critical"]}}, sort=[("created_at", -1)])
        if not doc:
            # Create a mock internal threat if none exist for the drill
            doc = {
                "id": f"drill-{datetime.utcnow().strftime('%S')}",
                "title": "Drill: Unauthorized Admin Privilege Escalation",
                "severity": "critical",
                "source_ip": "10.0.0.99",
                "hostname": "PROD-DC-01"
            }
        else:
            doc["id"] = str(doc.pop("_id"))
            
        # 2. Sequential execution to simulate real-time checking in
        results = await agent_manager.handle_alert(doc)
        
        # 3. Format drill report for UI visualization
        report = [
            {"agent": "soc_agent", "label": "SOC Triage", "result": results.get("soc", {}), "icon": "Shield"},
            {"agent": "analyst_agent", "label": "Deep Analysis", "result": results.get("analyst", {}), "icon": "Search"},
            {"agent": "responder_agent", "label": "Active Mitigation", "result": results.get("responder", {}), "icon": "Zap"},
            {"agent": "hunter_agent", "label": "Threat Hunting", "result": results.get("hunter", {}), "icon": "Crosshair"},
            {"agent": "forensics_agent", "label": "Digital Forensics", "result": results.get("forensics", {}), "icon": "Archive"}
        ]
        
        return {
            "success": True,
            "target": doc.get("title"),
            "report": report,
            "auto_blocked": results.get("auto_block", {}).get("blocked", False),
            "forensic_case_id": results.get("forensics", {}).get("forensic_case_id"),
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(500, f"Drill failed: {e}")
