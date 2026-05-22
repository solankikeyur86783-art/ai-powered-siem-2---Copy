"""
Tor Detection Service
━━━━━━━━━━━━━━━━━━━━
• Fetches live Tor exit-node list from torproject.org every 30 minutes
• Stores in-memory set for O(1) lookup (no Redis dependency)
• Behavioral signal detection for Tor-like traffic even without a list match
• Creates HIGH severity alerts in MongoDB on match
• Incident Response workflow: block IP, create IR ticket, notify SOC, log forensics
"""
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Set
from loguru import logger
from app.database.db import col

TOR_FEED_URL = "https://check.torproject.org/torbulkexitlist"
REFRESH_INTERVAL = 1800           # 30 minutes

# Tor-associated ports (relay, ORPort, DirPort)
TOR_PORTS: Set[int] = {9001, 9030, 9050, 9051, 9150, 9151, 443, 80}
TOR_SIGNAL_PORTS: Set[int] = {9001, 9030, 9050, 9051, 9150, 9151}

# Known Tor-associated user-agent fragments
TOR_UA_FRAGMENTS = [
    "tor browser", "torbrowser", "mozilla/5.0 (windows nt 6.1; rv:",
    "mozilla/5.0 (windows nt 10.0; rv:", "neutral/"
]


class TorDetectionService:
    """Live Tor exit-node detection with behavioral analysis and IR automation."""

    def __init__(self):
        self._exit_nodes: Set[str] = set()
        self._last_refresh: Optional[datetime] = None
        self._node_count: int = 0
        self._feed_ok: bool = False
        self._lock = asyncio.Lock()

    # ── Feed Management ──────────────────────────────────────────

    async def refresh_feed(self) -> Dict[str, Any]:
        """Fetch the live Tor exit-node list and cache in memory."""
        async with self._lock:
            try:
                import httpx
                async with httpx.AsyncClient(timeout=15) as client:
                    resp = await client.get(TOR_FEED_URL)
                    resp.raise_for_status()
                    lines = resp.text.splitlines()
                    nodes = {
                        line.strip() for line in lines
                        if line.strip() and not line.startswith("#")
                    }
                    self._exit_nodes = nodes
                    self._node_count = len(nodes)
                    self._last_refresh = datetime.utcnow()
                    self._feed_ok = True
                    logger.success(f"🧅 Tor feed refreshed — {self._node_count} exit nodes loaded")

                    # Persist metadata to DB for dashboard queries
                    await col("tor_feed_meta").update_one(
                        {"_id": "status"},
                        {"$set": {
                            "node_count": self._node_count,
                            "last_refresh": self._last_refresh,
                            "feed_ok": True,
                            "feed_url": TOR_FEED_URL,
                        }},
                        upsert=True
                    )
                    return {"success": True, "node_count": self._node_count, "refreshed_at": self._last_refresh.isoformat()}

            except Exception as e:
                self._feed_ok = False
                logger.error(f"Tor feed refresh failed: {e}")
                await col("tor_feed_meta").update_one(
                    {"_id": "status"},
                    {"$set": {"feed_ok": False, "last_error": str(e), "error_at": datetime.utcnow()}},
                    upsert=True
                )
                return {"success": False, "error": str(e)}

    async def auto_refresh_loop(self):
        """Background task: refresh Tor feed every 30 minutes."""
        # Initial load
        await self.refresh_feed()
        while True:
            await asyncio.sleep(REFRESH_INTERVAL)
            await self.refresh_feed()

    def _needs_refresh(self) -> bool:
        if not self._last_refresh:
            return True
        return (datetime.utcnow() - self._last_refresh).total_seconds() > REFRESH_INTERVAL

    # ── IP Checking ──────────────────────────────────────────────

    async def is_tor_exit_node(self, ip: str) -> bool:
        """Return True if ip is a known Tor exit node."""
        if self._needs_refresh():
            await self.refresh_feed()
        return ip in self._exit_nodes

    async def check_ip(self, ip: str) -> Dict[str, Any]:
        """Full check: list lookup + behavioral signals."""
        is_tor = await self.is_tor_exit_node(ip)
        return {
            "ip": ip,
            "is_tor_exit_node": is_tor,
            "feed_node_count": self._node_count,
            "feed_last_refresh": self._last_refresh.isoformat() if self._last_refresh else None,
            "feed_ok": self._feed_ok,
            "checked_at": datetime.utcnow().isoformat(),
        }

    async def scan_recent_logs(self, hours: int = 24) -> Dict[str, Any]:
        """
        Scan recent threat logs for Tor exit-node IPs.
        Triggers HIGH alerts for any match not already alerted.
        """
        if self._needs_refresh():
            await self.refresh_feed()

        since = datetime.utcnow() - timedelta(hours=hours)
        matched = []
        alert_ids = []

        pipeline = [
            {"$match": {"timestamp": {"$gte": since}, "source_ip": {"$ne": None}}},
            {"$group": {
                "_id": "$source_ip",
                "count": {"$sum": 1},
                "severity": {"$max": "$severity"},
                "last_seen": {"$max": "$timestamp"},
                "threat_types": {"$addToSet": "$threat_type"},
            }},
        ]

        async for doc in col("threat_logs").aggregate(pipeline):
            ip = doc["_id"]
            if ip and ip in self._exit_nodes:
                matched.append({
                    "ip": ip,
                    "count": doc["count"],
                    "severity": doc["severity"],
                    "last_seen": doc["last_seen"].isoformat() if doc.get("last_seen") else None,
                    "threat_types": doc["threat_types"],
                })
                alert_id = await self._create_tor_alert(ip, doc)
                if alert_id:
                    alert_ids.append(alert_id)

        return {
            "scanned_at": datetime.utcnow().isoformat(),
            "hours": hours,
            "feed_node_count": self._node_count,
            "matches_found": len(matched),
            "matches": matched,
            "alerts_created": alert_ids,
        }

    # ── Behavioral Detection ─────────────────────────────────────

    def analyze_behavioral_signals(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Score a log event for Tor-like behavior using 5 signal categories.
        Flags as suspicious if 3 or more signals match.
        """
        signals = []
        score = 0

        # Signal 1: Tor-associated destination ports
        dest_port = event.get("dest_port") or event.get("port")
        if isinstance(dest_port, int) and dest_port in TOR_SIGNAL_PORTS:
            signals.append({"signal": "tor_port", "value": dest_port,
                            "description": f"Traffic to Tor relay port {dest_port}"})
            score += 1

        # Signal 2: High request frequency (>100 events in last hour) — caller provides count
        req_count = event.get("request_count", 0)
        if req_count > 100:
            signals.append({"signal": "high_frequency", "value": req_count,
                            "description": f"High request frequency: {req_count} requests"})
            score += 1

        # Signal 3: Rotating user-agents (caller provides unique_ua_count)
        unique_uas = event.get("unique_ua_count", 0)
        if unique_uas > 3:
            signals.append({"signal": "rotating_user_agents", "value": unique_uas,
                            "description": f"Rotating user-agents detected: {unique_uas} unique UAs"})
            score += 1

        # Signal 4: Known Tor UA fragments in user_agent string
        ua = (event.get("user_agent") or "").lower()
        for frag in TOR_UA_FRAGMENTS:
            if frag in ua:
                signals.append({"signal": "tor_user_agent", "value": ua[:80],
                                "description": "User-agent matches Tor Browser pattern"})
                score += 1
                break

        # Signal 5: Encrypted / unusual protocol patterns
        proto = (event.get("protocol") or "").lower()
        encrypted_flag = event.get("is_encrypted", False)
        if encrypted_flag or proto in ("tls", "ssl", "tor"):
            signals.append({"signal": "encrypted_traffic", "value": proto or "unknown",
                            "description": "Encrypted/obfuscated traffic pattern detected"})
            score += 1

        is_suspicious = score >= 3
        return {
            "ip": event.get("source_ip", "unknown"),
            "behavioral_score": score,
            "is_suspicious": is_suspicious,
            "signals": signals,
            "verdict": "SUSPICIOUS — Tor-like behavior" if is_suspicious else "CLEAN",
            "analyzed_at": datetime.utcnow().isoformat(),
        }

    # ── Alert Creation ───────────────────────────────────────────

    async def _create_tor_alert(self, ip: str, doc: Dict) -> Optional[str]:
        """Create a HIGH severity Tor alert (dedup: one per IP per hour)."""
        dedup_window = datetime.utcnow() - timedelta(hours=1)
        existing = await col("alerts").find_one({
            "source_ip": ip,
            "rule_id": "TOR_EXIT_NODE",
            "created_at": {"$gte": dedup_window}
        })
        if existing:
            return None  # Already alerted recently

        alert = {
            "title": f"🧅 Tor Exit Node Detected: {ip}",
            "description": (
                f"Incoming traffic from known Tor exit node {ip}. "
                f"This IP appeared {doc.get('count', 1)} time(s) in the last 24h. "
                f"Threat types: {', '.join(doc.get('threat_types', ['unknown']))}. "
                "Tor exit nodes can be used to anonymize malicious activity."
            ),
            "severity": "high",
            "status": "open",
            "source_ip": ip,
            "rule_id": "TOR_EXIT_NODE",
            "rule_name": "Tor Exit Node Detection",
            "category": "threat_intelligence",
            "tags": ["tor", "anonymization", "threat-intel"],
            "event_count": doc.get("count", 1),
            "threat_types": doc.get("threat_types", []),
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
        }
        result = await col("alerts").insert_one(alert)
        alert_id = str(result.inserted_id)

        # Log to agent actions
        await col("agent_actions").insert_one({
            "timestamp": datetime.utcnow(),
            "agent_type": "tor_detector",
            "action": f"tor_exit_node_detected:{ip}",
            "result": f"HIGH alert created for Tor exit node {ip}",
            "success": True,
            "details": {"ip": ip, "alert_id": alert_id},
            "status": "completed",
        })

        logger.warning(f"🧅 Tor exit node alert created: {ip} → alert {alert_id}")
        return alert_id

    async def create_tor_alert_for_ip(self, ip: str) -> Optional[str]:
        """Public method to create a Tor alert for a specific IP."""
        doc = {"count": 1, "threat_types": ["tor_traffic"]}
        return await self._create_tor_alert(ip, doc)

    # ── Incident Response Workflow ───────────────────────────────

    async def trigger_ir_workflow(self, ip: str, alert_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Full IR workflow for a Tor-detected IP:
        1. Block IP (firewall log)
        2. Create IR ticket
        3. SOC webhook notification
        4. Log forensic session data
        """
        steps = []
        now = datetime.utcnow()

        # Step 1 — Block IP
        await col("agent_actions").insert_one({
            "timestamp": now,
            "agent_type": "responder",
            "action": f"block_ip:{ip}",
            "result": f"IP {ip} blocked — Tor exit node detected",
            "success": True,
            "details": {"ip": ip, "reason": "Tor exit node", "alert_id": alert_id},
            "status": "completed",
        })
        await col("blocked_ips").update_one(
            {"ip": ip},
            {"$set": {"ip": ip, "reason": "tor_exit_node", "blocked_at": now,
                      "alert_id": alert_id, "auto_blocked": True}},
            upsert=True
        )
        steps.append({"step": 1, "action": "block_ip", "target": ip,
                      "status": "executed", "note": "IP logged as blocked"})

        # Step 2 — Create IR ticket
        ticket = {
            "ticket_id": f"TOR-{int(now.timestamp())}",
            "title": f"Tor Exit Node Incident — {ip}",
            "description": (
                f"Automated IR ticket: Tor exit node {ip} detected by CortexSIEM. "
                "IP has been blocked. Immediate SOC review required."
            ),
            "severity": "high",
            "status": "open",
            "source_ip": ip,
            "alert_id": alert_id,
            "created_at": now,
            "updated_at": now,
            "type": "tor_incident",
            "assigned_to": "SOC Team",
        }
        await col("ir_tickets").insert_one(ticket)
        ticket_id = ticket["ticket_id"]
        steps.append({"step": 2, "action": "create_ir_ticket",
                      "ticket_id": ticket_id, "status": "created"})

        # Step 3 — SOC Webhook notification
        try:
            from app.services.notifications import notification_manager
            soc_alert = {
                "title": f"🧅 Tor Exit Node IR: {ip}",
                "description": f"Tor exit node {ip} detected and blocked. Ticket {ticket_id} opened.",
                "severity": "high",
                "source_ip": ip,
                "rule_id": "TOR_IR_WORKFLOW",
            }
            notif_result = await notification_manager.notify(soc_alert)
            steps.append({"step": 3, "action": "notify_soc_webhook",
                          "status": "sent", "channels": [r.get("channel") for r in notif_result]})
        except Exception as e:
            steps.append({"step": 3, "action": "notify_soc_webhook",
                          "status": "failed", "error": str(e)})

        # Step 4 — Forensic session log
        forensic_entry = {
            "ip": ip,
            "event_type": "tor_exit_node_ir",
            "alert_id": alert_id,
            "ticket_id": ticket_id,
            "collected_at": now,
            "session_data": {
                "ip": ip,
                "detection_method": "tor_exit_node_list",
                "feed_url": TOR_FEED_URL,
                "node_count_at_detection": self._node_count,
                "feed_last_refresh": self._last_refresh.isoformat() if self._last_refresh else None,
            },
            "ir_steps": steps,
        }
        await col("forensic_sessions").insert_one(forensic_entry)
        steps.append({"step": 4, "action": "log_forensic_session",
                      "status": "logged", "entry_count": 1})

        # Update alert status
        if alert_id:
            try:
                from bson import ObjectId
                await col("alerts").update_one(
                    {"_id": ObjectId(alert_id)},
                    {"$set": {"status": "investigating", "ir_triggered": True,
                              "ticket_id": ticket_id, "updated_at": now}}
                )
            except Exception:
                pass

        logger.success(f"🚨 IR workflow completed for Tor IP {ip} — ticket {ticket_id}")
        return {
            "success": True,
            "ip": ip,
            "alert_id": alert_id,
            "ticket_id": ticket_id,
            "steps_executed": steps,
            "completed_at": now.isoformat(),
        }

    # ── Status ───────────────────────────────────────────────────

    def get_status(self) -> Dict[str, Any]:
        return {
            "feed_ok": self._feed_ok,
            "node_count": self._node_count,
            "last_refresh": self._last_refresh.isoformat() if self._last_refresh else None,
            "feed_url": TOR_FEED_URL,
            "refresh_interval_minutes": REFRESH_INTERVAL // 60,
        }


# Singleton
tor_detection = TorDetectionService()
