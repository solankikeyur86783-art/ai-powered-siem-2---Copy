"""
Forensics Agent — Real evidence collection from MongoDB, auto-creates forensic cases.
"""
import sys
import os

# Add root and backend to path
root_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
backend_path = os.path.join(root_path, 'backend')
sys.path.insert(0, root_path)
sys.path.insert(0, backend_path)

from datetime import datetime, timedelta
from typing import Dict, Any, List
from loguru import logger
from app.database.db import col  # type: ignore


class ForensicsAgent:
    """
    Digital Forensics & Incident Response (DFIR) Agent.
    Responsibilities:
    - Root cause analysis from REAL database logs
    - Correlating logs across all sources (Honeypot, Alert, Auth, Threat)
    - Timeline reconstruction from actual events
    - Evidence extraction & artifact collection
    - Auto-create forensic cases for investigation
    """

    async def collect_evidence(self, alert: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        alert_id = alert.get("id") or str(alert.get("_id", ""))
        source_ip = alert.get("source_ip")
        hostname = alert.get("hostname", "unknown")
        severity = alert.get("severity", "medium")

        logger.info(f"🔍 Forensics Agent deep-diving alert: {alert_id} | IP: {source_ip} | Host: {hostname}")

        # ── 1. Build real timeline from MongoDB ──
        timeline = await self._build_real_timeline(source_ip, hostname)

        # ── 2. Collect related threat logs ──
        related_threats = await self._get_related_threats(source_ip)

        # ── 3. Collect related alerts ──
        related_alerts = await self._get_related_alerts(source_ip)

        # ── 4. Get network activity profile ──
        network_activity = await self._get_network_activity(source_ip)

        # ── 5. Get previous agent actions on this alert ──
        agent_actions = await self._get_agent_actions(alert_id)

        # ── 6. Extract file/process artifacts ──
        artifacts = await self._get_artifacts(source_ip, hostname)

        # ── 7. Determine root cause from gathered evidence ──
        root_cause = self._determine_root_cause(
            alert, timeline, related_threats, related_alerts
        )

        # ── 8. Auto-create forensic case if severity warrants it ──
        case_id = None
        if severity in ["high", "critical"]:
            case_id = await self._auto_create_forensic_case(
                alert, timeline, related_threats, related_alerts,
                network_activity, artifacts, root_cause
            )

        result = {
            "agent": "forensics_agent",
            "action": "evidence_collection",
            "timestamp": datetime.utcnow().isoformat(),
            "timeline_events": len(timeline),
            "timeline": timeline[:20],  # cap for response size
            "related_threats_count": len(related_threats),
            "related_alerts_count": len(related_alerts),
            "network_activity": network_activity,
            "artifacts_count": len(artifacts),
            "evidence_files": [a.get("name", "unknown") for a in artifacts[:10]],
            "root_cause": root_cause,
            "forensic_case_id": case_id,
            "summary": (
                f"Forensic investigation complete: {len(timeline)} timeline events, "
                f"{len(related_threats)} related threats, {len(related_alerts)} related alerts. "
                f"Root cause: {root_cause}. "
                f"{'Forensic case auto-created: ' + case_id if case_id else 'Case creation skipped (low severity).'}"
            )
        }

        logger.info(f"✅ Forensics: {len(timeline)} events, {len(related_threats)} threats, case={case_id}")
        return result

    # ── Real MongoDB Queries ──────────────────────────────────────

    async def _build_real_timeline(self, ip: str, hostname: str, hours: int = 48) -> List[Dict]:
        """Build complete activity timeline from raw_logs, threat_logs, and alerts."""
        since = datetime.utcnow() - timedelta(hours=hours)
        timeline = []

        # Raw logs from this IP/host
        query = {"timestamp": {"$gte": since}}
        if ip:
            query["$or"] = [{"source_ip": ip}, {"dest_ip": ip}]
        elif hostname:
            query["hostname"] = hostname

        try:
            cursor = col("raw_logs").find(query, {"raw": 0}).sort("timestamp", 1).limit(150)
            async for doc in cursor:
                timeline.append({
                    "timestamp": doc.get("timestamp", datetime.utcnow()).isoformat() if isinstance(doc.get("timestamp"), datetime) else str(doc.get("timestamp", "")),
                    "type": "log",
                    "source": doc.get("source", "unknown"),
                    "event_id": doc.get("event_id"),
                    "message": (doc.get("message", ""))[:200],
                    "source_ip": doc.get("source_ip"),
                    "dest_ip": doc.get("dest_ip"),
                    "log_level": doc.get("log_level"),
                })
        except Exception as e:
            logger.error(f"Forensics timeline raw_logs error: {e}")

        # Threat logs from this IP
        if ip:
            try:
                cursor = col("threat_logs").find(
                    {"source_ip": ip, "timestamp": {"$gte": since}},
                    {"raw": 0}
                ).sort("timestamp", 1).limit(50)
                async for doc in cursor:
                    timeline.append({
                        "timestamp": doc.get("timestamp", datetime.utcnow()).isoformat() if isinstance(doc.get("timestamp"), datetime) else str(doc.get("timestamp", "")),
                        "type": "threat",
                        "threat_type": doc.get("threat_type"),
                        "severity": doc.get("severity"),
                        "description": (doc.get("description", ""))[:200],
                        "rule_matched": doc.get("rule_matched"),
                    })
            except Exception as e:
                logger.error(f"Forensics timeline threat_logs error: {e}")

        # Alerts from this IP
        if ip:
            try:
                cursor = col("alerts").find(
                    {"source_ip": ip, "created_at": {"$gte": since}}
                ).sort("created_at", 1).limit(20)
                async for doc in cursor:
                    timeline.append({
                        "timestamp": doc.get("created_at", datetime.utcnow()).isoformat() if isinstance(doc.get("created_at"), datetime) else str(doc.get("created_at", "")),
                        "type": "alert",
                        "title": doc.get("title"),
                        "severity": doc.get("severity"),
                        "status": doc.get("status"),
                    })
            except Exception as e:
                logger.error(f"Forensics timeline alerts error: {e}")

        # Honeypot captures
        if ip:
            try:
                cursor = col("honeypot_captures").find(
                    {"source_ip": ip, "timestamp": {"$gte": since}}
                ).sort("timestamp", 1).limit(20)
                async for doc in cursor:
                    timeline.append({
                        "timestamp": doc.get("timestamp", datetime.utcnow()).isoformat() if isinstance(doc.get("timestamp"), datetime) else str(doc.get("timestamp", "")),
                        "type": "honeypot",
                        "service": doc.get("service"),
                        "data": (doc.get("data", ""))[:150],
                    })
            except Exception as e:
                logger.debug(f"Forensics honeypot query skipped: {e}")

        # Sort by timestamp string
        timeline.sort(key=lambda x: x.get("timestamp", ""))
        return timeline

    async def _get_related_threats(self, ip: str) -> List[Dict]:
        if not ip:
            return []
        threats = []
        try:
            cursor = col("threat_logs").find(
                {"source_ip": ip}, {"raw": 0}
            ).sort("timestamp", -1).limit(20)
            async for doc in cursor:
                doc["id"] = str(doc.pop("_id", ""))
                # Serialize datetime fields
                for key in ["timestamp", "created_at"]:
                    if isinstance(doc.get(key), datetime):
                        doc[key] = doc[key].isoformat()
                threats.append(doc)
        except Exception as e:
            logger.error(f"Forensics related threats error: {e}")
        return threats

    async def _get_related_alerts(self, ip: str) -> List[Dict]:
        if not ip:
            return []
        alerts = []
        try:
            cursor = col("alerts").find(
                {"source_ip": ip}, {"llm_summary": 0}
            ).sort("created_at", -1).limit(15)
            async for doc in cursor:
                doc["id"] = str(doc.pop("_id", ""))
                for key in ["created_at", "updated_at"]:
                    if isinstance(doc.get(key), datetime):
                        doc[key] = doc[key].isoformat()
                alerts.append(doc)
        except Exception as e:
            logger.error(f"Forensics related alerts error: {e}")
        return alerts

    async def _get_network_activity(self, ip: str) -> Dict:
        if not ip:
            return {"destinations": [], "ports": [], "total_connections": 0}
        since = datetime.utcnow() - timedelta(hours=48)
        result = {"destinations": [], "ports": [], "total_connections": 0}
        try:
            # Destination IPs contacted
            dest_agg = [
                {"$match": {"source_ip": ip, "timestamp": {"$gte": since}, "dest_ip": {"$ne": None}}},
                {"$group": {"_id": "$dest_ip", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
                {"$limit": 10}
            ]
            result["destinations"] = [
                {"ip": d["_id"], "count": d["count"]}
                async for d in col("raw_logs").aggregate(dest_agg)
            ]

            # Ports used
            port_agg = [
                {"$match": {"source_ip": ip, "timestamp": {"$gte": since}, "dest_port": {"$ne": None}}},
                {"$group": {"_id": "$dest_port", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
                {"$limit": 10}
            ]
            result["ports"] = [
                {"port": d["_id"], "count": d["count"]}
                async for d in col("raw_logs").aggregate(port_agg)
            ]

            result["total_connections"] = await col("raw_logs").count_documents(
                {"source_ip": ip, "timestamp": {"$gte": since}}
            )
        except Exception as e:
            logger.error(f"Forensics network activity error: {e}")
        return result

    async def _get_agent_actions(self, alert_id: str) -> List[Dict]:
        actions = []
        try:
            cursor = col("agent_actions").find(
                {"alert_id": alert_id}
            ).sort("timestamp", -1).limit(20)
            async for doc in cursor:
                doc["id"] = str(doc.pop("_id", ""))
                if isinstance(doc.get("timestamp"), datetime):
                    doc["timestamp"] = doc["timestamp"].isoformat()
                actions.append(doc)
        except Exception as e:
            logger.error(f"Forensics agent actions error: {e}")
        return actions

    async def _get_artifacts(self, ip: str, hostname: str) -> List[Dict]:
        """Collect file/process artifacts from threat and raw logs."""
        artifacts = []
        since = datetime.utcnow() - timedelta(hours=48)

        # Look for process-related events
        if ip:
            try:
                cursor = col("threat_logs").find(
                    {"source_ip": ip, "timestamp": {"$gte": since}},
                    {"description": 1, "threat_type": 1, "severity": 1, "rule_matched": 1, "timestamp": 1}
                ).sort("timestamp", -1).limit(20)
                async for doc in cursor:
                    artifacts.append({
                        "name": doc.get("rule_matched") or doc.get("threat_type", "unknown"),
                        "type": doc.get("threat_type", "indicator"),
                        "severity": doc.get("severity", "medium"),
                        "description": (doc.get("description", ""))[:200],
                        "timestamp": doc.get("timestamp", "").isoformat() if isinstance(doc.get("timestamp"), datetime) else str(doc.get("timestamp", "")),
                    })
            except Exception as e:
                logger.debug(f"Forensics artifacts query error: {e}")

        return artifacts

    def _determine_root_cause(self, alert: Dict, timeline: List, threats: List, alerts: List) -> str:
        """Analyze gathered evidence to determine the most likely root cause."""
        threat_types = [t.get("threat_type", "") for t in threats]
        severity = alert.get("severity", "medium")

        if not threats and not timeline:
            return "Insufficient data for root cause analysis — no related events found."

        # Count threat types
        type_counts = {}
        for tt in threat_types:
            type_counts[tt] = type_counts.get(tt, 0) + 1

        dominant_threat = max(type_counts, key=type_counts.get) if type_counts else "unknown"

        root_causes = {
            "brute_force": f"Brute force attack — {type_counts.get('brute_force', 0)} failed login attempts detected from source IP. Likely credential stuffing or password spraying.",
            "port_scan": f"Reconnaissance activity — Port scanning detected with {len(timeline)} related network events. Attacker profiling target services.",
            "malware": f"Malware execution — Malicious indicators detected in {type_counts.get('malware', 0)} events. Check for persistence mechanisms.",
            "privilege_escalation": f"Privilege escalation — {type_counts.get('privilege_escalation', 0)} privilege events detected. Possible exploitation of local vulnerability.",
            "data_exfiltration": f"Data exfiltration — Unusual outbound data transfer detected. {len(timeline)} related network events observed.",
            "lateral_movement": f"Lateral movement — Attacker pivoting through network. {type_counts.get('lateral_movement', 0)} remote access events detected.",
        }

        return root_causes.get(dominant_threat,
            f"Threat type '{dominant_threat}' detected across {len(threats)} threat events and {len(timeline)} timeline entries. "
            f"Severity: {severity}. Investigation recommended.")

    async def _auto_create_forensic_case(self, alert, timeline, threats, alerts,
                                          network, artifacts, root_cause) -> str:
        """Auto-create a forensic case in the database."""
        try:
            alert_id = alert.get("id") or str(alert.get("_id", ""))
            
            # Check if case already exists for this alert
            existing = await col("forensic_cases").find_one({"alert_id": alert_id})
            if existing:
                logger.info(f"Forensic case already exists for alert {alert_id}")
                return str(existing["_id"])

            case = {
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow(),
                "alert_id": alert_id,
                "source_ip": alert.get("source_ip"),
                "hostname": alert.get("hostname", "unknown"),
                "severity": alert.get("severity", "medium"),
                "status": "open",
                "collected_by": "forensics_agent_auto",
                "evidence": {
                    "alert_snapshot": {
                        "id": alert_id,
                        "title": alert.get("title"),
                        "severity": alert.get("severity"),
                        "source_ip": alert.get("source_ip"),
                        "hostname": alert.get("hostname"),
                    },
                    "timeline": timeline[:50],
                    "related_threats": [{"threat_type": t.get("threat_type"), "severity": t.get("severity")} for t in threats[:10]],
                    "related_alerts": [{"title": a.get("title"), "severity": a.get("severity")} for a in alerts[:10]],
                    "network_activity": network,
                    "file_artifacts": artifacts[:20],
                },
                "summary": {
                    "total_events": len(timeline),
                    "total_threats": len(threats),
                    "total_alerts": len(alerts),
                    "total_artifacts": len(artifacts),
                    "root_cause": root_cause,
                },
                "notes": [{
                    "text": f"Auto-created by Forensics Agent. Root cause: {root_cause}",
                    "author": "forensics_agent",
                    "timestamp": datetime.utcnow(),
                }],
                "tags": alert.get("tags", []) + ["auto-forensics", "agent-created"],
            }

            result = await col("forensic_cases").insert_one(case)
            case_id = str(result.inserted_id)
            logger.success(f"📂 Auto-created forensic case {case_id} for alert {alert_id}")
            return case_id
        except Exception as e:
            logger.error(f"Failed to auto-create forensic case: {e}")
            return None
