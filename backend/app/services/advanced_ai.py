"""
Advanced AI Analysis Service — Deep threat analysis, kill chain mapping, IOC extraction
"""
import json
from datetime import datetime
from typing import Dict, Any, List
from loguru import logger
from app.llm.router import llm_analyze
from app.database.db import col


DEEP_ANALYSIS_SYSTEM = """You are an elite cybersecurity analyst AI. Perform deep threat analysis.
Return ONLY valid JSON with this structure:
{
    "threat_classification": "APT|ransomware|insider_threat|malware|reconnaissance|etc",
    "confidence": 0.0-1.0,
    "kill_chain_phase": "reconnaissance|weaponization|delivery|exploitation|installation|command_control|actions_on_objectives",
    "mitre_attack": {
        "tactic": "string",
        "technique": "T-number",
        "sub_technique": "string or null"
    },
    "iocs": {
        "ips": ["list of IPs"],
        "domains": ["list of domains"],
        "hashes": ["list of file hashes"],
        "emails": ["list of emails"],
        "urls": ["list of URLs"]
    },
    "risk_score": 0-100,
    "attack_narrative": "Detailed story of what happened step by step",
    "recommended_actions": ["action1", "action2"],
    "related_cves": ["CVE-xxxx-xxxx"],
    "severity_assessment": "critical|high|medium|low",
    "false_positive_probability": 0.0-1.0
}"""


class AdvancedAIService:
    """Multi-step AI analysis pipeline"""

    async def deep_analyze(self, alert_id: str) -> Dict[str, Any]:
        """Perform deep AI analysis on an alert"""
        from bson import ObjectId

        # Gather alert + related data
        alert = await col("alerts").find_one({"_id": ObjectId(alert_id)})
        if not alert:
            return {"error": "Alert not found"}

        # Get related threat logs
        threat_logs = []
        if alert.get("source_ip"):
            cursor = col("threat_logs").find(
                {"source_ip": alert["source_ip"]}
            ).sort("timestamp", -1).limit(10)
            async for doc in cursor:
                doc.pop("_id", None)
                doc.pop("raw", None)
                threat_logs.append(doc)

        # Get related raw logs
        raw_logs = []
        if alert.get("source_ip"):
            cursor = col("raw_logs").find(
                {"source_ip": alert["source_ip"]},
                {"raw": 0, "_id": 0}
            ).sort("timestamp", -1).limit(10)
            async for doc in cursor:
                raw_logs.append(doc)

        # Build analysis prompt
        context = {
            "alert": {
                "title": alert.get("title"),
                "description": alert.get("description"),
                "severity": alert.get("severity"),
                "source_ip": alert.get("source_ip"),
                "hostname": alert.get("hostname"),
                "rule_id": alert.get("rule_id"),
                "created_at": str(alert.get("created_at")),
            },
            "related_threats": len(threat_logs),
            "threat_samples": threat_logs[:3],
            "raw_log_samples": raw_logs[:3],
        }

        prompt = f"""Perform deep threat analysis on this security alert and related events:

ALERT: {json.dumps(context['alert'], default=str)}

RELATED THREATS ({context['related_threats']} total):
{json.dumps(context['threat_samples'], default=str, indent=2)}

RAW LOG SAMPLES:
{json.dumps(context['raw_log_samples'], default=str, indent=2)}

Analyze the attack chain, extract IOCs, map to MITRE ATT&CK, and provide a detailed narrative."""

        try:
            analysis = await llm_analyze(DEEP_ANALYSIS_SYSTEM, prompt)
        except Exception as e:
            logger.error(f"Deep analysis LLM failed: {e}")
            analysis = self._fallback_analysis(alert)

        # Enrich with computed risk score
        analysis["computed_risk"] = self._compute_risk_score(alert, threat_logs, analysis)

        # Save analysis
        await col("alerts").update_one(
            {"_id": ObjectId(alert_id)},
            {"$set": {
                "deep_analysis": analysis,
                "analysis_timestamp": datetime.utcnow(),
                "updated_at": datetime.utcnow()
            }}
        )

        return {"alert_id": alert_id, "analysis": analysis}

    def _compute_risk_score(self, alert: dict, threats: list, llm_analysis: dict) -> Dict:
        """Composite risk score from multiple signals"""
        scores = {
            "severity_score": {"critical": 95, "high": 75, "medium": 50, "low": 25}.get(
                alert.get("severity", "low"), 25
            ),
            "frequency_score": min(len(threats) * 10, 100),
            "llm_confidence": int(llm_analysis.get("confidence", 0.5) * 100),
            "llm_risk": llm_analysis.get("risk_score", 50),
        }
        composite = int(
            scores["severity_score"] * 0.3 +
            scores["frequency_score"] * 0.2 +
            scores["llm_confidence"] * 0.2 +
            scores["llm_risk"] * 0.3
        )
        return {
            "composite_score": min(composite, 100),
            "components": scores,
            "risk_level": "critical" if composite >= 80 else "high" if composite >= 60 else "medium" if composite >= 40 else "low",
        }

    def _fallback_analysis(self, alert: dict) -> Dict:
        return {
            "threat_classification": alert.get("rule_id", "unknown"),
            "confidence": 0.5,
            "kill_chain_phase": "unknown",
            "mitre_attack": {"tactic": "Unknown", "technique": "Unknown", "sub_technique": None},
            "iocs": {"ips": [alert.get("source_ip", "")] if alert.get("source_ip") else [],
                     "domains": [], "hashes": [], "emails": [], "urls": []},
            "risk_score": 50,
            "attack_narrative": "LLM analysis unavailable. Manual investigation recommended.",
            "recommended_actions": ["Investigate source IP", "Review related logs", "Check for lateral movement"],
            "related_cves": [],
            "severity_assessment": alert.get("severity", "medium"),
            "false_positive_probability": 0.3,
            "fallback": True,
        }

    async def get_risk_scores(self, hours: int = 24) -> list:
        """Get risk scores for all recent alerts"""
        from datetime import timedelta
        since = datetime.utcnow() - timedelta(hours=hours)
        cursor = col("alerts").find(
            {"created_at": {"$gte": since}},
            {"title": 1, "severity": 1, "source_ip": 1, "deep_analysis": 1, "created_at": 1}
        ).sort("created_at", -1).limit(50)

        results = []
        async for doc in cursor:
            analysis = doc.get("deep_analysis", {})
            risk = analysis.get("computed_risk", {})
            results.append({
                "id": str(doc["_id"]),
                "title": doc.get("title"),
                "severity": doc.get("severity"),
                "source_ip": doc.get("source_ip"),
                "risk_score": risk.get("composite_score", 0),
                "risk_level": risk.get("risk_level", doc.get("severity", "low")),
                "has_analysis": bool(analysis),
                "created_at": doc.get("created_at"),
            })
        return results


advanced_ai = AdvancedAIService()
