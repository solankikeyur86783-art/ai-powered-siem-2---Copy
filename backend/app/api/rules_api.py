"""
Custom Detection Rules API — CRUD for user-defined rules
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from datetime import datetime
from typing import Optional, List
from bson import ObjectId
from pydantic import BaseModel
from app.database.db import col
from app.core.auth_middleware import get_current_user
from app.core.rule_engine import run_rules, RULES
import re
import yaml
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/rules", tags=["Detection Rules"])


class RuleCondition(BaseModel):
    field: str  # event_id, message, source_ip, log_level, etc.
    operator: str  # equals, contains, regex, in, gt, lt
    value: str


class CustomRuleCreate(BaseModel):
    name: str
    description: str = ""
    severity: str = "medium"
    threat_type: str = "unknown"
    conditions: List[RuleCondition]
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    enabled: bool = True


def _serialize(doc):
    if doc is None:
        return {}
    doc["id"] = str(doc.pop("_id", ""))
    return doc


@router.get("/")
async def list_rules(user: dict = Depends(get_current_user)):
    """List all detection rules (built-in + custom)"""
    
    # Dynamically calculate hits by aggregating alerts
    counts = {}
    cursor = col("alerts").aggregate([
        {"$group": {"_id": "$rule_name", "count": {"$sum": 1}}}
    ])
    async for doc in cursor:
        if doc.get("_id"):
            counts[doc["_id"]] = doc["count"]

    print("DEBUG COUNTS API:", counts)

    # Built-in rules
    builtin = []
    for r in RULES:
        rule_name = r["name"]
        builtin.append({
            "id": f"builtin_{r['name'].lower().replace(' ', '_').replace('-', '_')}",
            "name": rule_name,
            "severity": r["severity"],
            "threat_type": r["threat_type"],
            "mitre_tactic": r.get("mitre_tactic"),
            "mitre_technique": r.get("mitre_technique"),
            "builtin": True,
            "enabled": True,
            "hit_count": counts.get(rule_name, counts.get(f"builtin_{rule_name}", 0)),
        })

    # Custom rules from DB
    cursor = col("custom_rules").find().sort("created_at", -1)
    custom = []
    async for doc in cursor:
        doc["id"] = str(doc.pop("_id"))
        doc["builtin"] = False
        doc["hit_count"] = counts.get(doc.get("name"), doc.get("hit_count", 0))
        custom.append(doc)

    return {"rules": builtin + custom, "builtin_count": len(builtin), "custom_count": len(custom)}


@router.post("/")
async def create_rule(rule: CustomRuleCreate, user: dict = Depends(get_current_user)):
    """Create a custom detection rule"""
    doc = {
        **rule.model_dump(),
        "conditions": [c.model_dump() for c in rule.conditions],
        "created_by": user.get("username", "unknown"),
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
        "hit_count": 0,
    }
    result = await col("custom_rules").insert_one(doc)
    doc["id"] = str(result.inserted_id)
    doc.pop("_id", None)
    return {"success": True, "rule": doc}


@router.put("/{rule_id}")
async def update_rule(rule_id: str, updates: dict, user: dict = Depends(get_current_user)):
    """Update a custom rule"""
    if rule_id.startswith("builtin_"):
        raise HTTPException(400, "Cannot modify built-in rules")
    try:
        allowed = {"name", "description", "severity", "threat_type", "conditions",
                    "mitre_tactic", "mitre_technique", "enabled"}
        filtered = {k: v for k, v in updates.items() if k in allowed}
        filtered["updated_at"] = datetime.utcnow()

        result = await col("custom_rules").update_one(
            {"_id": ObjectId(rule_id)},
            {"$set": filtered}
        )
        if result.matched_count == 0:
            raise HTTPException(404, "Rule not found")
        return {"success": True}
    except Exception as e:
        raise HTTPException(400, str(e))


@router.delete("/{rule_id}")
async def delete_rule(rule_id: str, user: dict = Depends(get_current_user)):
    """Delete a custom rule"""
    if rule_id.startswith("builtin_"):
        raise HTTPException(400, "Cannot delete built-in rules")
    try:
        result = await col("custom_rules").delete_one({"_id": ObjectId(rule_id)})
        if result.deleted_count == 0:
            raise HTTPException(404, "Rule not found")
        return {"success": True}
    except Exception as e:
        raise HTTPException(400, str(e))


@router.post("/{rule_id}/toggle")
async def toggle_rule(rule_id: str, user: dict = Depends(get_current_user)):
    """Enable/disable a rule"""
    if rule_id.startswith("builtin_"):
        raise HTTPException(400, "Cannot toggle built-in rules")
    try:
        doc = await col("custom_rules").find_one({"_id": ObjectId(rule_id)})
        if not doc:
            raise HTTPException(404, "Rule not found")
        new_state = not doc.get("enabled", True)
        await col("custom_rules").update_one(
            {"_id": ObjectId(rule_id)},
            {"$set": {"enabled": new_state, "updated_at": datetime.utcnow()}}
        )
        return {"success": True, "enabled": new_state}
    except Exception as e:
        raise HTTPException(400, str(e))


@router.post("/test")
async def test_rule(data: dict, user: dict = Depends(get_current_user)):
    """Test a rule against sample log data"""
    conditions = data.get("conditions", [])
    sample_log = data.get("sample_log", {})

    if not conditions or not sample_log:
        raise HTTPException(400, "conditions and sample_log required")

    matched = _evaluate_conditions(conditions, sample_log)
    return {
        "matched": matched,
        "sample_log": sample_log,
        "conditions_tested": len(conditions),
    }


@router.post("/import")
async def import_sigma(data: dict, user: dict = Depends(get_current_user)):
    """Import a SIGMA rule from YAML"""
    yaml_text = data.get("yaml", "")
    if not yaml_text:
        raise HTTPException(400, "YAML content required")
    
    try:
        sigma = yaml.safe_load(yaml_text)
        
        # 1. Map SIGMA fields to our CustomRule model
        name = sigma.get("title", "Imported Rule")
        description = sigma.get("description", "")
        level = sigma.get("level", "medium").lower()
        
        # Severity mapping
        sev_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "informational": "info"}
        severity = sev_map.get(level, "medium")
        
        # 2. Extract detection conditions (Better mapping)
        detection = sigma.get("detection", {})
        conditions = []
        
        for key, val in detection.items():
            if key in ["condition", "status", "timeframe"]:
                continue
            
            # If val is a dict (like selection: { event_id: 4688 }), map the inner keys!
            if isinstance(val, dict):
                for sub_key, sub_val in val.items():
                    operator = "equals"
                    value = str(sub_val)
                    if isinstance(sub_val, (list, tuple)):
                        operator = "in"
                        value = ",".join(str(v) for v in sub_val)
                    elif str(sub_val).startswith("/") and str(sub_val).endswith("/"):
                        operator = "regex"
                        value = str(sub_val)[1:-1]
                    
                    conditions.append({"field": sub_key, "operator": operator, "value": value})
            else:
                operator = "equals"
                value = str(val)
                if isinstance(val, (list, tuple)):
                    operator = "in"
                    value = ",".join(str(v) for v in val)
                elif str(val).startswith("/") and str(val).endswith("/"):
                    operator = "regex"
                    value = str(val)[1:-1]
                conditions.append({"field": key, "operator": operator, "value": value})

        # 3. Handle tags properly without crashing
        raw_tags = sigma.get("tags") or []
        tags = raw_tags if isinstance(raw_tags, list) else [raw_tags]
        threat_type = tags[0] if tags else "imported"
        mitre_tactic = ""
        mitre_technique = ""
        for t in tags:
            t = str(t).lower()
            if t.startswith("attack.t"): mitre_technique = t.split(".")[1].upper()
            elif t.startswith("attack."): mitre_tactic = t.split(".")[1].capitalize()

        # 4. Save as custom rule
        doc = {
            "name": name,
            "description": description,
            "severity": severity,
            "threat_type": threat_type,
            "conditions": conditions,
            "mitre_tactic": mitre_tactic,
            "mitre_technique": mitre_technique,
            "enabled": True,
            "created_by": user.get("username", "admin"),
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "hit_count": 0,
            "sigma": True
        }
        
        result = await col("custom_rules").insert_one(doc)
        doc["id"] = str(result.inserted_id)
        doc.pop("_id", None)
        
        return {"success": True, "rule": doc}
        
    except Exception as e:
        logger.error(f"SIGMA import error: {e}")
        raise HTTPException(400, f"Failed to parse SIGMA YAML: {e}")


def _evaluate_conditions(conditions: list, log: dict) -> bool:
    """Evaluate rule conditions against a log entry"""
    for cond in conditions:
        field = cond.get("field", "")
        operator = cond.get("operator", "equals")
        value = str(cond.get("value", ""))
        log_value = str(log.get(field, ""))

        if operator == "equals" and log_value != value:
            return False
        elif operator == "contains" and value.lower() not in log_value.lower():
            return False
        elif operator == "regex":
            try:
                if not re.search(value, log_value, re.IGNORECASE):
                    return False
            except re.error:
                return False
        elif operator == "in":
            vals = [v.strip() for v in value.split(",")]
            if log_value not in vals:
                return False
        elif operator == "gt":
            try:
                if float(log_value) <= float(value):
                    return False
            except (ValueError, TypeError):
                return False
        elif operator == "lt":
            try:
                if float(log_value) >= float(value):
                    return False
            except (ValueError, TypeError):
                return False

    return True
