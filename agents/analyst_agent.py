"""
Analyst Agent — deep-dives into threats, correlates context, produces reports.
"""
import sys
import os

# Add root and backend to path
root_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
backend_path = os.path.join(root_path, 'backend')
sys.path.insert(0, root_path)
sys.path.insert(0, backend_path)

import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any, List
from loguru import logger
from app.database.db import col  # type: ignore
from app.services.llm_service import llm_service  # type: ignore


class AnalystAgent:
    """
    Security Analyst Agent.
    Responsibilities:
    - Deep investigation of alerts
    - Correlate with historical data
    - MITRE ATT&CK mapping
    - Generate investigation reports
    """

    async def investigate(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        logger.info(f"🟡 Analyst Agent investigating: {alert.get('title')}")

        # Gather context from MongoDB
        context = await self._gather_context(alert)

        # LLM investigation
        investigation = {}
        try:
            investigation = await asyncio.wait_for(
                llm_service.investigate_alert(alert, context["related_logs"]),
                timeout=15.0
            )
        except asyncio.TimeoutError:
            investigation = {"error": "LLM timeout", "attack_narrative": "Manual investigation required"}
        except Exception as e:
            investigation = {"error": str(e)}

        result = {
            "agent": "analyst_agent",
            "action": "investigation",
            "timestamp": datetime.utcnow().isoformat(),
            "context": context,
            "investigation": investigation,
            "mitre_tactic": alert.get("mitre_tactic"),
            "mitre_technique": alert.get("mitre_technique"),
            "summary": investigation.get("attack_narrative", "Investigation complete"),
            "threat_confirmed": investigation.get("threat_confirmed", False),
        }

        logger.info("Analyst investigation complete")
        return result

    async def _gather_context(self, alert: Dict) -> Dict[str, Any]:
        since = datetime.utcnow() - timedelta(hours=24)
        source_ip = alert.get("source_ip")

        # Related logs from same IP
        related_logs = []
        if source_ip:
            cursor = col("threat_logs").find(
                {"source_ip": source_ip, "timestamp": {"$gte": since}},
                {"raw": 0}
            ).sort("timestamp", -1).limit(10)
            async for doc in cursor:
                doc["id"] = str(doc.pop("_id", ""))
                related_logs.append(doc)

        # Historical alerts from same IP
        hist_alerts = []
        if source_ip:
            cursor = col("alerts").find(
                {"source_ip": source_ip},
                {"llm_summary": 0}
            ).sort("created_at", -1).limit(5)
            async for doc in cursor:
                doc["id"] = str(doc.pop("_id", ""))
                hist_alerts.append(doc)

        return {
            "related_logs": related_logs,
            "historical_alerts": hist_alerts,
            "related_log_count": len(related_logs),
            "historical_alert_count": len(hist_alerts),
        }
