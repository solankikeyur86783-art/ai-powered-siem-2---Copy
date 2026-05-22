import json
from typing import Dict, Any, Optional
from loguru import logger
from app.llm.router import llm_analyze
from app.llm.prompt_templates import (
    THREAT_ANALYSIS_SYSTEM,
    THREAT_ANALYSIS_PROMPT,
    ALERT_INVESTIGATION_PROMPT,
    AUTOMATED_RESPONSE_PROMPT,
    DAILY_SUMMARY_PROMPT
)


class LLMService:
    async def analyze_threat(self, log: Dict[str, Any], context: str = "") -> Dict[str, Any]:
        """Analyze a log entry for threats using LLM"""
        try:
            # Sanitize log for LLM (remove huge raw fields)
            log_summary = {
                k: v for k, v in log.items()
                if k not in ["raw", "_id"] and v is not None
            }
            prompt = THREAT_ANALYSIS_PROMPT.format(
                log_data=json.dumps(log_summary, default=str, indent=2),
                context=context or "No additional context"
            )
            result = await llm_analyze(THREAT_ANALYSIS_SYSTEM, prompt)
            logger.debug(f"LLM analysis: {result.get('threat_type')} / {result.get('severity')}")
            return result
        except Exception as e:
            logger.error(f"LLM threat analysis failed: {e}")
            return self._fallback_response()

    async def investigate_alert(self, alert: Dict, related_events: list) -> Dict[str, Any]:
        """Deep investigation of an alert"""
        try:
            prompt = ALERT_INVESTIGATION_PROMPT.format(
                alert_title=alert.get("title", "Unknown"),
                severity=alert.get("severity", "unknown"),
                description=alert.get("description", ""),
                source_ip=alert.get("source_ip", "unknown"),
                hostname=alert.get("hostname", "unknown"),
                related_events=json.dumps(related_events[:5], default=str)
            )
            return await llm_analyze(THREAT_ANALYSIS_SYSTEM, prompt)
        except Exception as e:
            logger.error(f"Alert investigation failed: {e}")
            return {"error": str(e)}

    async def recommend_response(self, threat: Dict[str, Any]) -> Dict[str, Any]:
        """Get automated response recommendations"""
        try:
            prompt = AUTOMATED_RESPONSE_PROMPT.format(
                threat_type=threat.get("threat_type", "unknown"),
                severity=threat.get("severity", "low"),
                source_ip=threat.get("source_ip", "unknown"),
                hostname=threat.get("hostname", "unknown")
            )
            return await llm_analyze(THREAT_ANALYSIS_SYSTEM, prompt)
        except Exception as e:
            logger.error(f"Response recommendation failed: {e}")
            return {"error": str(e)}

    async def daily_summary(self, stats: Dict[str, Any]) -> Dict[str, Any]:
        """Generate daily security summary"""
        try:
            prompt = DAILY_SUMMARY_PROMPT.format(
                total_logs=stats.get("total_logs", 0),
                threats=stats.get("threats", 0),
                critical=stats.get("critical", 0),
                high=stats.get("high", 0),
                top_ips=json.dumps(stats.get("top_ips", [])[:5]),
                threat_types=json.dumps(stats.get("threat_types", []))
            )
            return await llm_analyze(THREAT_ANALYSIS_SYSTEM, prompt)
        except Exception as e:
            logger.error(f"Daily summary failed: {e}")
            return {"error": str(e), "summary": None}

    def _fallback_response(self) -> Dict[str, Any]:
        return {
            "threat_detected": False,
            "severity": "low",
            "threat_type": "unknown",
            "summary": "LLM analysis unavailable",
            "recommended_actions": [],
            "confidence": 0.0
        }


llm_service = LLMService()
