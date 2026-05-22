"""
Enhanced Threat Hunt Service — Saved queries, templates, natural language search
"""
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from loguru import logger
from bson import ObjectId
from app.database.db import col
from app.llm.router import llm_analyze

# Pre-built hunt templates
HUNT_TEMPLATES = [
    {
        "id": "tmpl_brute_force",
        "name": "Brute Force Detection",
        "description": "Find IPs with multiple failed login attempts or suspicious successful logons",
        "category": "Credential Access",
        "collection": "raw_logs",
        "query": {"$or": [
            {"event_id": {"$in": [4625, 4771, 4776, 4723]}},
            {"winlog.event_id": {"$in": [4625, 4771, 4776, 4723]}},
            {"message": {"$regex": "Logon Type: (3|10)", "$options": "i"}}
        ]},
        "group_by": "source_ip",
        "threshold": 5,
        "mitre": "T1110",
    },
    {
        "id": "tmpl_lateral_movement",
        "name": "Lateral Movement Hunt",
        "description": "Detect remote logon sessions (Type 3/10) and Remote Management",
        "category": "Lateral Movement",
        "collection": "raw_logs",
        "query": {
            "$or": [
                {"event_id": 4624}, 
                {"winlog.event_id": 4624},
                {"event_id": 4104} # PowerShell Script Block Logging
            ],
            "message": {"$regex": "Type (3|10)|Enter-PSSession|Invoke-Command", "$options": "i"}
        },
        "group_by": "source_ip",
        "threshold": 2,
        "mitre": "T1021",
    },
    {
        "id": "tmpl_suspicious_process",
        "name": "Suspicious Process Execution",
        "description": "Find known malicious process names and LOLBins",
        "category": "Execution",
        "collection": "raw_logs",
        "query": {
            "$or": [
                {"event_id": {"$in": [4688, 1, 4697]}}, # 4697 is service install
                {"winlog.event_id": {"$in": [4688, 1, 4697]}}
            ],
            "message": {"$regex": "mimikatz|meterpreter|cobalt|psexec|powershell.*-enc|certutil|bitsadmin", "$options": "i"}
        },
        "group_by": "hostname",
        "threshold": 1,
        "mitre": "T1059",
    },
    {
        "id": "tmpl_data_exfil",
        "name": "Data Exfiltration Indicators",
        "description": "Detect unusual outbound data transfers and staging",
        "category": "Exfiltration",
        "collection": "raw_logs",
        "query": {"message": {"$regex": "exfil|large transfer|unusual upload|7z|zip|rar", "$options": "i"}},
        "group_by": "source_ip",
        "threshold": 1,
        "mitre": "T1048",
    },
    {
        "id": "tmpl_privilege_escalation",
        "name": "Privilege Escalation",
        "description": "Detect special privilege assignments and group changes",
        "category": "Privilege Escalation",
        "collection": "raw_logs",
        "query": {
            "$or": [
                {"event_id": {"$in": [4672, 4673, 4674, 4720, 4732]}},
                {"winlog.event_id": {"$in": [4672, 4673, 4674, 4720, 4732]}}
            ]
        },
        "group_by": "hostname",
        "threshold": 3,
        "mitre": "T1068",
    },
    {
        "id": "tmpl_beaconing",
        "name": "C2 Beaconing Detection",
        "description": "Find regular interval connections (potential C2)",
        "category": "Command and Control",
        "collection": "threat_logs",
        "query": {"threat_type": {"$in": ["malware", "data_exfiltration"]}},
        "group_by": "source_ip",
        "threshold": 3,
        "mitre": "T1071",
    },
    {
        "id": "tmpl_persistence",
        "name": "Persistence Mechanisms",
        "description": "Detect newly created accounts and scheduled tasks",
        "category": "Persistence",
        "collection": "raw_logs",
        "query": {
            "$or": [
                {"event_id": {"$in": [4720, 4702, 4697, 4735]}}, # 4702 (task), 4697 (service), 4735 (group change)
                {"winlog.event_id": {"$in": [4720, 4702, 4697, 4735]}}
            ]
        },
        "group_by": "hostname",
        "threshold": 1,
        "mitre": "T1136",
    },
    {
        "id": "tmpl_audit_tampering",
        "name": "Audit Log Tampering",
        "description": "Detect changes to audit policies or service shutdowns",
        "category": "Defense Evasion",
        "collection": "raw_logs",
        "query": {"$or": [
            {"event_id": {"$in": [4719, 4906, 1102, 1100]}},
            {"winlog.event_id": {"$in": [4719, 4906, 1102, 1100]}}
        ]},
        "group_by": "hostname",
        "threshold": 1,
        "mitre": "T1562",
    },
]

NL_QUERY_SYSTEM = """You are a MongoDB query translator for a SIEM platform.
Convert natural language security queries to MongoDB query JSON.
Available collections: raw_logs, threat_logs, alerts
Available fields for raw_logs: timestamp, source, hostname, source_ip, dest_ip, source_port, dest_port, event_id, log_level, message
Available fields for threat_logs: timestamp, source_ip, dest_ip, hostname, threat_type, severity, rule_matched, description
Available fields for alerts: created_at, title, description, severity, status, source_ip, hostname, rule_id, tags

Return ONLY valid JSON:
{"collection": "raw_logs", "query": {mongodb_query}, "sort": {"timestamp": -1}, "limit": 50}
For time-based queries, use "$gte" with ISO date strings relative to current time."""


class ThreatHuntService:
    async def execute_hunt(self, template_id: str = None, custom_query: dict = None,
                           hours: int = 24) -> Dict[str, Any]:
        """Execute a threat hunt using template or custom query"""
        since = datetime.utcnow() - timedelta(hours=hours)

        if template_id:
            template = next((t for t in HUNT_TEMPLATES if t["id"] == template_id), None)
            if not template:
                return {"error": "Template not found"}
            collection = template["collection"]
            query = {**template["query"], "timestamp": {"$gte": since}}
            group_by = template.get("group_by", "source_ip")
        elif custom_query:
            collection = custom_query.get("collection", "raw_logs")
            query = custom_query.get("query", {})
            query["timestamp"] = {"$gte": since}
            group_by = custom_query.get("group_by", "source_ip")
        else:
            return {"error": "Provide template_id or custom_query"}

        # Execute query
        total = await col(collection).count_documents(query)

        # Get grouped results
        pipeline = [
            {"$match": query},
            {"$group": {
                "_id": f"${group_by}",
                "count": {"$sum": 1},
                "first_seen": {"$min": "$timestamp"},
                "last_seen": {"$max": "$timestamp"},
            }},
            {"$sort": {"count": -1}},
            {"$limit": 20}
        ]
        groups = [doc async for doc in col(collection).aggregate(pipeline)]

        # Get sample matches
        cursor = col(collection).find(query, {"raw": 0}).sort("timestamp", -1).limit(20)
        samples = []
        async for doc in cursor:
            doc["id"] = str(doc.pop("_id"))
            samples.append(doc)

        return {
            "total_matches": total,
            "groups": groups,
            "samples": samples,
            "query_used": query,
            "collection": collection,
        }

    async def nl_to_query(self, natural_language: str) -> Dict:
        """Convert natural language to MongoDB query using LLM"""
        try:
            prompt = f"""Convert this security query to MongoDB:
"{natural_language}"
Current time: {datetime.utcnow().isoformat()}"""
            result = await llm_analyze(NL_QUERY_SYSTEM, prompt)
            return result
        except Exception as e:
            logger.error(f"NL query translation failed: {e}")
            # Fallback: simple keyword search
            return {
                "collection": "raw_logs",
                "query": {"message": {"$regex": natural_language, "$options": "i"}},
                "sort": {"timestamp": -1},
                "limit": 50,
                "fallback": True,
            }

    async def save_query(self, name: str, query: dict, created_by: str) -> str:
        doc = {
            "name": name,
            "query": query,
            "created_by": created_by,
            "created_at": datetime.utcnow(),
            "run_count": 0,
        }
        result = await col("saved_queries").insert_one(doc)
        return str(result.inserted_id)

    async def list_saved_queries(self) -> list:
        cursor = col("saved_queries").find().sort("created_at", -1).limit(50)
        docs = []
        async for doc in cursor:
            doc["id"] = str(doc.pop("_id"))
            docs.append(doc)
        return docs

    async def delete_saved_query(self, query_id: str):
        await col("saved_queries").delete_one({"_id": ObjectId(query_id)})

    def get_templates(self) -> list:
        return HUNT_TEMPLATES


threat_hunt_service = ThreatHuntService()
