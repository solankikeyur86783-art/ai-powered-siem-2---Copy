"""
SOC Agent — first responder, triages alerts and determines priority.
"""
import sys
import os

# Add root and backend to path
root_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
backend_path = os.path.join(root_path, 'backend')
sys.path.insert(0, root_path)
sys.path.insert(0, backend_path)

from datetime import datetime
from typing import Dict, Any
from loguru import logger
from app.services.llm_service import llm_service  # type: ignore
from app.database.db import col  # type: ignore



class SOCAgent:
    """
    SOC (Security Operations Center) Agent.
    Responsibilities:
    - Receive and triage alerts
    - Assign severity and priority
    - Determine if human intervention needed
    - Route to appropriate analyst
    """

    SEVERITY_SCORE = {"critical": 4, "high": 3, "medium": 2, "low": 1}

    async def triage(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        logger.info(f"🔵 SOC Agent triaging alert: {alert.get('title')}")

        severity = alert.get("severity", "low")
        score = self.SEVERITY_SCORE.get(severity, 1)

        # Check for repeat offender IP
        repeat_count = 0
        if alert.get("source_ip"):
            repeat_count = await col("alerts").count_documents({
                "source_ip": alert["source_ip"],
                "id": {"$ne": alert.get("id")}
            })
            if repeat_count > 0:
                score = min(score + 1, 4)

        priority = self._score_to_priority(score)

        result = {
            "agent": "soc_agent",
            "action": "triage",
            "timestamp": datetime.utcnow().isoformat(),
            "priority": priority,
            "severity_score": score,
            "repeat_offender": repeat_count > 0,
            "repeat_count": repeat_count,
            "escalate_to_human": severity in ["high", "critical"],
            "summary": (
                f"Alert triaged as {priority} priority. "
                f"{'⚠️ Repeat offender IP detected. ' if repeat_count > 0 else ''}"
                f"{'🚨 Escalating to human analyst.' if severity in ['high', 'critical'] else 'Auto-handling.'}"
            ),
            "recommended_analyst": "senior_analyst" if severity == "critical" else "analyst"
        }

        logger.info(f"SOC triage complete: {priority} priority")
        return result

    def _score_to_priority(self, score: int) -> str:
        return {4: "P1-CRITICAL", 3: "P2-HIGH", 2: "P3-MEDIUM", 1: "P4-LOW"}.get(score, "P4-LOW")
