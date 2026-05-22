from loguru import logger
from app.database.db import get_db


async def create_indices():
    db = get_db()
    try:
        # Raw logs indices
        await db.raw_logs.create_index([("timestamp", -1)])
        await db.raw_logs.create_index([("source_ip", 1)])
        await db.raw_logs.create_index([("event_id", 1)])
        await db.raw_logs.create_index([("hostname", 1)])
        await db.raw_logs.create_index([("log_level", 1)])

        # Threat logs indices
        await db.threat_logs.create_index([("timestamp", -1)])
        await db.threat_logs.create_index([("severity", 1)])
        await db.threat_logs.create_index([("threat_type", 1)])
        await db.threat_logs.create_index([("source_ip", 1)])
        await db.threat_logs.create_index([("status", 1)])
        await db.threat_logs.create_index([("ml_score", -1)])

        # Alerts indices
        await db.alerts.create_index([("created_at", -1)])
        await db.alerts.create_index([("severity", 1)])
        await db.alerts.create_index([("status", 1)])
        await db.alerts.create_index([("rule_id", 1)])

        # Agent actions indices
        await db.agent_actions.create_index([("timestamp", -1)])
        await db.agent_actions.create_index([("agent_type", 1)])
        await db.agent_actions.create_index([("alert_id", 1)])

        # System stats
        await db.system_stats.create_index([("timestamp", -1)])

        # v3.0 — New indices
        # Users
        await db.users.create_index([("username", 1)], unique=True)
        await db.users.create_index([("email", 1)], unique=True)

        # IP intel cache (TTL)
        await db.ip_intel_cache.create_index([("ip", 1), ("source", 1)])
        await db.ip_intel_cache.create_index([("cached_at", 1)], expireAfterSeconds=86400)

        # Custom rules
        await db.custom_rules.create_index([("name", 1)])
        await db.custom_rules.create_index([("enabled", 1)])

        # Reports
        await db.reports.create_index([("created_at", -1)])

        # Anomalies
        await db.anomalies.create_index([("detected_at", -1)])
        await db.anomalies.create_index([("resolved", 1)])

        # Honeypot captures
        await db.honeypot_captures.create_index([("timestamp", -1)])
        await db.honeypot_captures.create_index([("source_ip", 1)])

        # Forensic cases
        await db.forensic_cases.create_index([("created_at", -1)])
        await db.forensic_cases.create_index([("source_ip", 1)])

        # Saved queries
        await db.saved_queries.create_index([("created_at", -1)])

        # Notification log
        await db.notification_log.create_index([("timestamp", -1)])

        # Model versions
        await db.model_versions.create_index([("trained_at", -1)])

        logger.success("✅ MongoDB indices created (v3.0)")
    except Exception as e:
        logger.error(f"Index creation error: {e}")
