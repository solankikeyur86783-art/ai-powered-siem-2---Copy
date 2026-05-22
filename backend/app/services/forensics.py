"""
Forensics Service — Evidence collection and case management
"""
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from loguru import logger
from bson import ObjectId
from app.database.db import col


def _serialize(obj):
    """Recursively convert BSON types to JSON-serializable types."""
    if isinstance(obj, dict):
        return {k: _serialize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_serialize(i) for i in obj]
    if isinstance(obj, ObjectId):
        return str(obj)
    if isinstance(obj, datetime):
        return obj.isoformat()
    return obj



class ForensicsService:
    """Digital forensics evidence collection and case management"""

    async def collect_evidence(self, alert_id: str, collected_by: str = "system") -> Dict[str, Any]:
        """Collect all evidence related to an alert into a forensic case"""
        alert = await col("alerts").find_one({"_id": ObjectId(alert_id)})
        if not alert:
            return {"error": "Alert not found"}

        ip = alert.get("source_ip")
        hostname = alert.get("hostname")

        # Build evidence package
        evidence = {
            "alert_snapshot": self._clean_doc(alert),
            "timeline": await self._build_timeline(ip, hostname),
            "related_threats": await self._get_related_threats(ip),
            "related_alerts": await self._get_related_alerts(ip),
            "network_activity": await self._get_network_activity(ip),
            "agent_actions": await self._get_agent_actions(alert_id),
            "file_artifacts": await self._get_file_artifacts(ip, hostname),
        }

        # Create forensic case
        case = {
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "alert_id": alert_id,
            "source_ip": ip,
            "hostname": hostname,
            "severity": alert.get("severity", "medium"),
            "status": "open",
            "collected_by": collected_by,
            "evidence": evidence,
            "summary": {
                "total_events": len(evidence["timeline"]),
                "total_threats": len(evidence["related_threats"]),
                "total_alerts": len(evidence["related_alerts"]),
                "total_artifacts": len(evidence["file_artifacts"]),
                "time_span": self._calc_time_span(evidence["timeline"]),
            },
            "notes": [],
            "tags": alert.get("tags", []) + ["forensics"],
        }

        result = await col("forensic_cases").insert_one(case)
        case["id"] = str(result.inserted_id)
        case.pop("_id", None)

        logger.info(f"🔬 Forensic case created for alert {alert_id} ({len(evidence['timeline'])} events)")
        return _serialize(case)

    async def _build_timeline(self, ip: str, hostname: str, hours: int = 48) -> list:
        """Build complete activity timeline for an IP/host"""
        since = datetime.utcnow() - timedelta(hours=hours)
        timeline = []

        # Raw logs
        query = {"timestamp": {"$gte": since}}
        if ip:
            query["$or"] = [{"source_ip": ip}, {"dest_ip": ip}]
        elif hostname:
            query["hostname"] = hostname

        cursor = col("raw_logs").find(query, {"raw": 0}).sort("timestamp", 1).limit(200)
        async for doc in cursor:
            timeline.append({
                "timestamp": doc.get("timestamp"),
                "type": "log",
                "source": doc.get("source", "unknown"),
                "event_id": doc.get("event_id"),
                "message": (doc.get("message", ""))[:200],
                "source_ip": doc.get("source_ip"),
                "dest_ip": doc.get("dest_ip"),
                "log_level": doc.get("log_level"),
            })

        # Threat logs
        if ip:
            cursor = col("threat_logs").find(
                {"source_ip": ip, "timestamp": {"$gte": since}}
            ).sort("timestamp", 1).limit(50)
            async for doc in cursor:
                timeline.append({
                    "timestamp": doc.get("timestamp"),
                    "type": "threat",
                    "threat_type": doc.get("threat_type"),
                    "severity": doc.get("severity"),
                    "description": doc.get("description", "")[:200],
                    "rule_matched": doc.get("rule_matched"),
                })

        # Alerts
        if ip:
            cursor = col("alerts").find(
                {"source_ip": ip, "created_at": {"$gte": since}}
            ).sort("created_at", 1).limit(20)
            async for doc in cursor:
                timeline.append({
                    "timestamp": doc.get("created_at"),
                    "type": "alert",
                    "title": doc.get("title"),
                    "severity": doc.get("severity"),
                    "status": doc.get("status"),
                })

        # Sort by timestamp
        timeline.sort(key=lambda x: x.get("timestamp") or datetime.min)
        return timeline

    async def _get_related_threats(self, ip: str) -> list:
        if not ip:
            return []
        cursor = col("threat_logs").find(
            {"source_ip": ip},
            {"raw": 0}
        ).sort("timestamp", -1).limit(20)
        docs = []
        async for doc in cursor:
            doc["id"] = str(doc.pop("_id"))
            docs.append(doc)
        return docs

    async def _get_related_alerts(self, ip: str) -> list:
        if not ip:
            return []
        cursor = col("alerts").find(
            {"source_ip": ip}
        ).sort("created_at", -1).limit(20)
        docs = []
        async for doc in cursor:
            doc["id"] = str(doc.pop("_id"))
            docs.append(doc)
        return docs

    async def _get_network_activity(self, ip: str) -> Dict:
        if not ip:
            return {}
        since = datetime.utcnow() - timedelta(hours=48)

        # Destination IPs contacted
        dest_agg = [
            {"$match": {"source_ip": ip, "timestamp": {"$gte": since}, "dest_ip": {"$ne": None}}},
            {"$group": {"_id": "$dest_ip", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 10}
        ]
        dest_ips = [{"ip": d["_id"], "count": d["count"]}
                    async for d in col("raw_logs").aggregate(dest_agg)]

        # Ports used
        port_agg = [
            {"$match": {"source_ip": ip, "timestamp": {"$gte": since}, "dest_port": {"$ne": None}}},
            {"$group": {"_id": "$dest_port", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 10}
        ]
        ports = [{"port": d["_id"], "count": d["count"]}
                 async for d in col("raw_logs").aggregate(port_agg)]

        return {
            "destinations": dest_ips,
            "ports": ports,
            "total_connections": await col("raw_logs").count_documents(
                {"source_ip": ip, "timestamp": {"$gte": since}}
            ),
        }

    async def _get_agent_actions(self, alert_id: str) -> list:
        cursor = col("agent_actions").find(
            {"alert_id": alert_id}
        ).sort("timestamp", -1).limit(20)
        docs = []
        async for doc in cursor:
            doc["id"] = str(doc.pop("_id"))
            docs.append(doc)
        return docs

    async def _get_file_artifacts(self, ip: str, hostname: str) -> list:
        """Collect file/process indicators from forensic events"""
        query = {}
        if ip: query["source_ip"] = ip
        if hostname: query["host"] = hostname
        
        # Look for events that specifically have file/process details
        query["$or"] = [
            {"details.file_path": {"$exists": True}},
            {"details.process_name": {"$exists": True}}
        ]
        
        cursor = col("forensics_events").find(query).sort("timestamp", -1).limit(50)
        artifacts = []
        async for doc in cursor:
            details = doc.get("details", {})
            artifacts.append({
                "id": str(doc["_id"]),
                "name": details.get("file_path") or details.get("process_name") or "unknown",
                "type": doc.get("event_type", "file"),
                "size": details.get("bytes_transferred", "—"),
                "hash": details.get("file_hash") or "—",
                "is_threat": doc.get("severity") in ["high", "critical"],
                "timestamp": doc.get("timestamp")
            })
        return artifacts

    def _clean_doc(self, doc: dict) -> dict:
        cleaned = {k: v for k, v in doc.items() if k != "_id"}
        cleaned["id"] = str(doc.get("_id", ""))
        return cleaned

    def _calc_time_span(self, timeline: list) -> str:
        if len(timeline) < 2:
            return "N/A"
        first = timeline[0].get("timestamp")
        last = timeline[-1].get("timestamp")
        if first and last:
            delta = last - first
            hours = delta.total_seconds() / 3600
            if hours < 1:
                return f"{int(delta.total_seconds() / 60)} minutes"
            return f"{hours:.1f} hours"
        return "N/A"

    async def list_cases(self, limit: int = 20) -> list:
        cursor = col("forensic_cases").find(
            {}, {"evidence": 0}
        ).sort("created_at", -1).limit(limit)
        docs = []
        async for doc in cursor:
            doc["id"] = str(doc.pop("_id"))
            docs.append(_serialize(doc))
        return docs

    async def get_case(self, case_id: str) -> Optional[Dict]:
        doc = await col("forensic_cases").find_one({"_id": ObjectId(case_id)})
        if doc:
            doc["id"] = str(doc.pop("_id"))
            return _serialize(doc)
        return None

    async def add_note(self, case_id: str, note: str, author: str):
        await col("forensic_cases").update_one(
            {"_id": ObjectId(case_id)},
            {"$push": {"notes": {
                "text": note,
                "author": author,
                "timestamp": datetime.utcnow()
            }}, "$set": {"updated_at": datetime.utcnow()}}
        )

    async def add_artifact(self, case_id: str, data: dict):
        """Add an artifact to a forensic case"""
        artifact = {
            "name": data.get("name", "unknown"),
            "type": data.get("type", "File"),
            "size": data.get("size", "—"),
            "hash": data.get("hash", "—"),
            "is_threat": data.get("is_threat", False),
            "threat_label": data.get("threat_label"),
            "description": data.get("description", ""),
            "timestamp": datetime.utcnow().isoformat(),
            "added_by": data.get("added_by", "analyst"),
        }
        await col("forensic_cases").update_one(
            {"_id": ObjectId(case_id)},
            {
                "$push": {"artifacts": artifact},
                "$set": {"updated_at": datetime.utcnow()},
                "$inc": {"summary.total_artifacts": 1},
            }
        )
        logger.info(f"📎 Artifact added to case {case_id}: {artifact['name']}")

    async def ip_timeline(self, ip: str, hours: int = 48) -> list:
        return await self._build_timeline(ip, None, hours)


forensics_service = ForensicsService()
