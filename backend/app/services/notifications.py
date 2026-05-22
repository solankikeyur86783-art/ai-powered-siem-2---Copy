"""
Notification Service — Slack alerts with demo/mock mode
"""
from datetime import datetime
from typing import Dict, Any, List
from loguru import logger
from app.config import get_settings
from app.database.db import col

settings = get_settings()


class SlackNotifier:
    """Send alerts to Slack via webhook (mock mode if no URL configured)"""

    def __init__(self):
        self.webhook_url = getattr(settings, 'slack_webhook_url', None) or ""
        self.enabled = bool(self.webhook_url and self.webhook_url.startswith("http"))

    async def send(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        sev = alert.get("severity", "low")
        colors = {"critical": "#ff3366", "high": "#ff7a35", "medium": "#ffcc00", "low": "#00e676"}

        payload = {
            "attachments": [{
                "color": colors.get(sev, "#4f8fff"),
                "title": f"🚨 [{sev.upper()}] {alert.get('title', 'Security Alert')}",
                "text": alert.get("description", ""),
                "fields": [
                    {"title": "Source IP", "value": alert.get("source_ip", "N/A"), "short": True},
                    {"title": "Hostname", "value": alert.get("hostname", "N/A"), "short": True},
                    {"title": "Rule", "value": alert.get("rule_id", "N/A"), "short": True},
                    {"title": "Time", "value": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"), "short": True},
                ],
                "footer": "CortexSIEM Alert System"
            }]
        }

        if self.enabled:
            try:
                import httpx
                async with httpx.AsyncClient() as client:
                    resp = await client.post(self.webhook_url, json=payload, timeout=5)
                    return {"sent": True, "channel": "slack", "status": resp.status_code}
            except Exception as e:
                logger.error(f"Slack send failed: {e}")
                return {"sent": False, "channel": "slack", "error": str(e)}
        else:
            logger.info(f"[MOCK SLACK] Alert: {alert.get('title')} ({sev})")
            return {"sent": True, "channel": "slack", "mock": True, "payload": payload}


class NotificationManager:
    """Routes alerts to Slack based on severity settings"""

    def __init__(self):
        self.slack = SlackNotifier()
        # Default: notify on high+critical via Slack
        self.thresholds = {
            "slack": ["critical", "high"],
        }

    async def notify(self, alert: Dict[str, Any]) -> List[Dict]:
        """Send Slack notifications based on alert severity"""
        sev = alert.get("severity", "low")
        results = []

        # Load custom settings from DB
        try:
            db_settings = await col("notification_settings").find_one({"_id": "global"})
            if db_settings:
                self.thresholds = db_settings.get("thresholds", self.thresholds)
        except Exception:
            pass

        if sev in self.thresholds.get("slack", []):
            result = await self.slack.send(alert)
            results.append(result)

        # Log notification
        if results:
            await col("notification_log").insert_one({
                "timestamp": datetime.utcnow(),
                "alert_title": alert.get("title"),
                "severity": sev,
                "channels": [r.get("channel") for r in results],
                "results": results,
            })

        return results

    async def get_settings(self) -> Dict:
        db_settings = await col("notification_settings").find_one({"_id": "global"})
        return {
            "slack": {
                "enabled": self.slack.enabled,
                "webhook_configured": bool(self.slack.webhook_url),
            },
            "thresholds": db_settings.get("thresholds", self.thresholds) if db_settings else self.thresholds,
        }

    async def update_settings(self, new_settings: Dict) -> Dict:
        await col("notification_settings").update_one(
            {"_id": "global"},
            {"$set": {**new_settings, "updated_at": datetime.utcnow()}},
            upsert=True
        )
        return {"success": True}


notification_manager = NotificationManager()

