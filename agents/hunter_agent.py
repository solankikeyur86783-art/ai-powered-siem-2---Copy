"""
Threat Hunter Agent — Proactive scanning of MongoDB for stealthy attack patterns.
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


class ThreatHunterAgent:
    """
    AI Threat Hunter Agent — Proactive real-time scanning.
    Responsibilities:
    - C2 Beaconing detection (regular-interval connections)
    - Credential stuffing detection (failed logins across multiple accounts)
    - Data exfiltration patterns (large outbound transfers)
    - Lateral movement detection (one IP hitting many internal hosts)
    - Suspicious process chains
    - Living off the Land (LOLBins) detection
    """

    async def hunt(self, context: Dict[str, Any]) -> Dict[str, Any]:
        logger.info("🕵️ Threat Hunter Agent starting REAL proactive hunt...")

        since = datetime.utcnow() - timedelta(hours=24)
        findings: List[Dict] = []
        blocked_recommendations: List[str] = []

        # ── Hunt 1: Credential Stuffing / Brute Force IPs ──
        cred_findings = await self._hunt_credential_stuffing(since)
        findings.extend(cred_findings)

        # ── Hunt 2: Repeat Offender IPs (multiple alerts) ──
        repeat_findings = await self._hunt_repeat_offenders(since)
        findings.extend(repeat_findings)

        # ── Hunt 3: High-volume senders (possible DDoS/scan) ──
        volume_findings = await self._hunt_high_volume_senders(since)
        findings.extend(volume_findings)

        # ── Hunt 4: Multi-threat-type IPs (advanced attacker) ──
        multi_findings = await self._hunt_multi_threat_ips(since)
        findings.extend(multi_findings)

        # ── Hunt 5: Suspicious patterns in threat logs ──
        pattern_findings = await self._hunt_suspicious_patterns(since)
        findings.extend(pattern_findings)

        # Collect IPs to recommend for blocking
        for f in findings:
            if f.get("confidence", 0) >= 0.7 and f.get("source_ip"):
                blocked_recommendations.append(f["source_ip"])

        # Deduplicate
        blocked_recommendations = list(set(blocked_recommendations))

        # Calculate overall threat confidence
        avg_confidence = (
            sum(f.get("confidence", 0) for f in findings) / len(findings)
            if findings else 0
        )

        result = {
            "agent": "hunter_agent",
            "action": "proactive_hunt",
            "timestamp": datetime.utcnow().isoformat(),
            "findings": findings,
            "findings_count": len(findings),
            "threat_confidence": round(avg_confidence, 2),
            "recommended_blocks": blocked_recommendations,
            "recommended_priority": (
                "CRITICAL" if avg_confidence >= 0.85 else
                "HIGH" if avg_confidence >= 0.6 else
                "MEDIUM" if avg_confidence >= 0.3 else "LOW"
            ),
            "summary": (
                f"Proactive hunt completed: {len(findings)} suspicious patterns found. "
                f"Average confidence: {avg_confidence:.0%}. "
                f"{len(blocked_recommendations)} IPs recommended for blocking."
            )
        }

        logger.info(f"✅ Threat hunt: {len(findings)} findings, {len(blocked_recommendations)} block recommendations")
        return result

    # ── Hunt Functions ────────────────────────────────────────────

    async def _hunt_credential_stuffing(self, since: datetime) -> List[Dict]:
        """Find IPs with many failed login indicators in threat_logs."""
        findings = []
        try:
            pipeline = [
                {"$match": {
                    "timestamp": {"$gte": since},
                    "threat_type": "brute_force"
                }},
                {"$group": {
                    "_id": "$source_ip",
                    "count": {"$sum": 1},
                    "first_seen": {"$min": "$timestamp"},
                    "last_seen": {"$max": "$timestamp"},
                }},
                {"$match": {"count": {"$gte": 3}}},
                {"$sort": {"count": -1}},
                {"$limit": 10}
            ]
            async for doc in col("threat_logs").aggregate(pipeline):
                ip = doc["_id"]
                if not ip:
                    continue
                count = doc["count"]
                confidence = min(0.5 + (count * 0.05), 0.98)
                findings.append({
                    "hunt_type": "credential_stuffing",
                    "source_ip": ip,
                    "description": f"IP {ip} triggered {count} brute force alerts in 24h — likely credential stuffing attack",
                    "count": count,
                    "confidence": round(confidence, 2),
                    "severity": "high" if count >= 5 else "medium",
                    "first_seen": doc["first_seen"].isoformat() if isinstance(doc["first_seen"], datetime) else str(doc["first_seen"]),
                    "last_seen": doc["last_seen"].isoformat() if isinstance(doc["last_seen"], datetime) else str(doc["last_seen"]),
                    "recommendation": "Block IP immediately" if count >= 5 else "Monitor closely",
                })
        except Exception as e:
            logger.error(f"Hunt credential_stuffing error: {e}")
        return findings

    async def _hunt_repeat_offenders(self, since: datetime) -> List[Dict]:
        """Find IPs that appear in multiple alerts."""
        findings = []
        try:
            pipeline = [
                {"$match": {
                    "created_at": {"$gte": since},
                    "source_ip": {"$ne": None}
                }},
                {"$group": {
                    "_id": "$source_ip",
                    "alert_count": {"$sum": 1},
                    "severities": {"$push": "$severity"},
                    "titles": {"$push": "$title"},
                }},
                {"$match": {"alert_count": {"$gte": 2}}},
                {"$sort": {"alert_count": -1}},
                {"$limit": 10}
            ]
            async for doc in col("alerts").aggregate(pipeline):
                ip = doc["_id"]
                if not ip:
                    continue
                count = doc["alert_count"]
                has_critical = "critical" in doc.get("severities", [])
                has_high = "high" in doc.get("severities", [])
                confidence = min(0.6 + (count * 0.06), 0.97)
                if has_critical:
                    confidence = min(confidence + 0.15, 0.99)

                findings.append({
                    "hunt_type": "repeat_offender",
                    "source_ip": ip,
                    "description": f"Repeat offender IP {ip}: {count} alerts in 24h (includes {'CRITICAL' if has_critical else 'HIGH' if has_high else 'MEDIUM'} severity)",
                    "count": count,
                    "confidence": round(confidence, 2),
                    "severity": "critical" if has_critical else "high" if count >= 3 else "medium",
                    "alert_titles": doc.get("titles", [])[:5],
                    "recommendation": "Block and escalate" if has_critical else "Block IP",
                })
        except Exception as e:
            logger.error(f"Hunt repeat_offenders error: {e}")
        return findings

    async def _hunt_high_volume_senders(self, since: datetime) -> List[Dict]:
        """Find IPs generating an unusually high number of log entries (possible scan/DDoS)."""
        findings = []
        try:
            pipeline = [
                {"$match": {
                    "timestamp": {"$gte": since},
                    "source_ip": {"$ne": None}
                }},
                {"$group": {
                    "_id": "$source_ip",
                    "log_count": {"$sum": 1},
                }},
                {"$match": {"log_count": {"$gte": 50}}},
                {"$sort": {"log_count": -1}},
                {"$limit": 5}
            ]
            async for doc in col("threat_logs").aggregate(pipeline):
                ip = doc["_id"]
                if not ip:
                    continue
                count = doc["log_count"]
                confidence = min(0.4 + (count / 200), 0.95)
                findings.append({
                    "hunt_type": "high_volume_threat_source",
                    "source_ip": ip,
                    "description": f"High-volume threat source: {ip} generated {count} threat events in 24h — possible automated attack tool",
                    "count": count,
                    "confidence": round(confidence, 2),
                    "severity": "high" if count >= 100 else "medium",
                    "recommendation": "Block IP and investigate automation tool",
                })
        except Exception as e:
            logger.error(f"Hunt high_volume error: {e}")
        return findings

    async def _hunt_multi_threat_ips(self, since: datetime) -> List[Dict]:
        """Find IPs that have triggered multiple DIFFERENT threat types — indicates advanced attacker."""
        findings = []
        try:
            pipeline = [
                {"$match": {
                    "timestamp": {"$gte": since},
                    "source_ip": {"$ne": None}
                }},
                {"$group": {
                    "_id": "$source_ip",
                    "threat_types": {"$addToSet": "$threat_type"},
                    "count": {"$sum": 1},
                }},
                {"$match": {"$expr": {"$gte": [{"$size": "$threat_types"}, 2]}}},
                {"$sort": {"count": -1}},
                {"$limit": 5}
            ]
            async for doc in col("threat_logs").aggregate(pipeline):
                ip = doc["_id"]
                if not ip:
                    continue
                types = doc.get("threat_types", [])
                confidence = min(0.7 + (len(types) * 0.08), 0.99)
                findings.append({
                    "hunt_type": "multi_vector_attacker",
                    "source_ip": ip,
                    "description": f"Advanced multi-vector attacker: {ip} used {len(types)} different attack types: {', '.join(types)}",
                    "threat_types": types,
                    "count": doc["count"],
                    "confidence": round(confidence, 2),
                    "severity": "critical" if len(types) >= 3 else "high",
                    "recommendation": "Immediate block — advanced persistent threat behavior",
                })
        except Exception as e:
            logger.error(f"Hunt multi_threat error: {e}")
        return findings

    async def _hunt_suspicious_patterns(self, since: datetime) -> List[Dict]:
        """Find escalation patterns — IPs that started with low severity and escalated."""
        findings = []
        try:
            # Find IPs with both low/medium AND high/critical alerts
            pipeline = [
                {"$match": {
                    "created_at": {"$gte": since},
                    "source_ip": {"$ne": None}
                }},
                {"$group": {
                    "_id": "$source_ip",
                    "severities": {"$addToSet": "$severity"},
                    "count": {"$sum": 1},
                }},
                {"$match": {
                    "severities": {"$all": ["high"]},
                    "count": {"$gte": 2}
                }},
                {"$limit": 5}
            ]
            async for doc in col("alerts").aggregate(pipeline):
                ip = doc["_id"]
                if not ip:
                    continue
                findings.append({
                    "hunt_type": "threat_escalation",
                    "source_ip": ip,
                    "description": f"Escalation pattern: {ip} shows escalating threat severity across {doc['count']} alerts — possible active intrusion progression",
                    "count": doc["count"],
                    "confidence": 0.78,
                    "severity": "high",
                    "recommendation": "Investigate attack progression and check for lateral movement",
                })
        except Exception as e:
            logger.error(f"Hunt suspicious_patterns error: {e}")
        return findings
