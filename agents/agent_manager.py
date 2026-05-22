"""
Agent Manager — Orchestrates all 5 AI agents with auto-block, auto-forensics, and WebSocket broadcasting.
Runs ALL agents on EVERY alert for comprehensive threat detection.
"""
from __future__ import annotations

import sys
import os

# Add root and backend to path so we can import app modules
root_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
backend_path = os.path.join(root_path, 'backend')
sys.path.insert(0, root_path)
sys.path.insert(0, backend_path)

import asyncio
import subprocess
import platform
from datetime import datetime
from typing import Dict, Any, List
from loguru import logger
from app.database.db import col  # type: ignore


class AgentManager:
    def __init__(self):
        self._initialized = False
        self._blocked_ips: set = set()

    async def handle_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run ALL 5 agents on EVERY alert for comprehensive threat detection.
        Pipeline: SOC Triage + Analyst → Auto-Block + Forensics + Hunter (all parallel)
        """
        from agents.soc_agent import SOCAgent
        from agents.analyst_agent import AnalystAgent
        from agents.responder_agent import ResponderAgent
        from agents.hunter_agent import ThreatHunterAgent
        from agents.forensics_agent import ForensicsAgent

        results = {}
        alert_id = alert.get("id") or str(alert.get("_id", ""))
        severity = alert.get("severity", "low").lower()
        source_ip = alert.get("source_ip")

        start_time = datetime.utcnow()
        logger.info(f"🚀 Agent pipeline starting for alert {alert_id} [{severity.upper()}]")

        # ── Phase 1: Core Analysis (SOC + Analyst in parallel) ──
        await self._broadcast_agent_event("pipeline_start", alert_id, {
            "message": f"Agent pipeline triggered for alert: {alert.get('title', 'Unknown')}",
            "severity": severity,
        })

        async def run_soc():
            try:
                soc = SOCAgent()
                res = await soc.triage(alert)
                await self._log_action("soc_agent", alert_id, "triage", res)
                await self._broadcast_agent_event("soc_complete", alert_id, {
                    "priority": res.get("priority"),
                    "summary": res.get("summary"),
                })
                return res
            except Exception as e:
                logger.error(f"SOC agent error: {e}")
                return {"error": str(e)}

        async def run_analyst():
            try:
                analyst = AnalystAgent()
                res = await analyst.investigate(alert)
                await self._log_action("analyst_agent", alert_id, "investigate", res)
                await self._broadcast_agent_event("analyst_complete", alert_id, {
                    "threat_confirmed": res.get("threat_confirmed"),
                    "summary": res.get("summary"),
                })
                return res
            except Exception as e:
                logger.error(f"Analyst agent error: {e}")
                return {"error": str(e)}

        core_results = await asyncio.gather(run_soc(), run_analyst())
        results["soc"] = core_results[0]
        results["analyst"] = core_results[1]

        # Auto-publish analyst summary to alert
        analyst_summary = results["analyst"].get("summary")
        if analyst_summary and alert_id:
            try:
                from bson import ObjectId
                query = {"_id": ObjectId(alert_id)} if len(alert_id) == 24 else {"id": alert_id}
                await col("alerts").update_one(
                    query,
                    {"$set": {
                        "llm_summary": analyst_summary,
                        "status": "investigating",
                        "updated_at": datetime.utcnow()
                    }}
                )
                logger.info(f"💾 Auto-published analyst summary to alert {alert_id}")
            except Exception as e:
                logger.error(f"Failed to auto-publish summary: {e}")

        # ── Phase 2: ALL Specialized Agents (Responder + Forensics + Hunter in parallel) ──
        # Run for ALL severity levels, not just high/critical
        logger.info(f"🔥 Triggering specialized responders for {severity} severity alert")

        threat_confirmed = results["analyst"].get("threat_confirmed", False)
        soc_priority = results["soc"].get("severity_score", 1)

        async def run_responder():
            try:
                responder = ResponderAgent()
                res = await responder.respond(alert)
                await self._log_action("responder_agent", alert_id, "respond", res)
                await self._broadcast_agent_event("responder_complete", alert_id, {
                    "actions_taken": len(res.get("actions_taken", [])),
                    "summary": res.get("summary"),
                })
                return res
            except Exception as e:
                logger.error(f"Responder agent error: {e}")
                return {"error": str(e)}

        async def run_forensics():
            try:
                forensics = ForensicsAgent()
                res = await forensics.collect_evidence(alert, {})
                await self._log_action("forensics_agent", alert_id, "evidence_collection", res)
                await self._broadcast_agent_event("forensics_complete", alert_id, {
                    "timeline_events": res.get("timeline_events", 0),
                    "forensic_case_id": res.get("forensic_case_id"),
                    "summary": res.get("summary"),
                })
                return res
            except Exception as e:
                logger.error(f"Forensics agent error: {e}")
                return {"error": str(e)}

        async def run_hunter():
            try:
                hunter = ThreatHunterAgent()
                res = await hunter.hunt({"alert": alert, "source_ip": source_ip})
                await self._log_action("hunter_agent", alert_id, "proactive_hunt", res)
                await self._broadcast_agent_event("hunter_complete", alert_id, {
                    "findings_count": res.get("findings_count", 0),
                    "recommended_blocks": res.get("recommended_blocks", []),
                    "summary": res.get("summary"),
                })
                return res
            except Exception as e:
                logger.error(f"Hunter agent error: {e}")
                return {"error": str(e)}

        spec_results = await asyncio.gather(run_responder(), run_forensics(), run_hunter())
        results["responder"] = spec_results[0]
        results["forensics"] = spec_results[1]
        results["hunter"] = spec_results[2]

        # ── Phase 3: Auto-Block Decision ──
        should_block = self._should_auto_block(alert, results)
        if should_block and source_ip:
            block_result = await self._auto_block_ip(source_ip, alert, results)
            results["auto_block"] = block_result
            await self._broadcast_agent_event("ip_blocked", alert_id, {
                "ip": source_ip,
                "reason": block_result.get("reason"),
                "success": block_result.get("success"),
            })
        else:
            results["auto_block"] = {"blocked": False, "reason": "Threat level below auto-block threshold"}

        # ── Phase 4: Update Alert Status ──
        try:
            from bson import ObjectId
            query = {"_id": ObjectId(alert_id)} if len(alert_id) == 24 else {"id": alert_id}
            new_status = "blocked" if should_block else "investigating" if severity in ["high", "critical"] else "triaged"
            await col("alerts").update_one(
                query,
                {"$set": {
                    "status": new_status,
                    "agent_processed": True,
                    "agent_processed_at": datetime.utcnow(),
                    "auto_blocked": should_block,
                    "updated_at": datetime.utcnow(),
                }}
            )
        except Exception as e:
            logger.error(f"Failed to update alert status: {e}")

        elapsed = (datetime.utcnow() - start_time).total_seconds()
        logger.success(f"✅ Agent pipeline complete for {alert_id} in {elapsed:.1f}s — blocked={should_block}")

        await self._broadcast_agent_event("pipeline_complete", alert_id, {
            "elapsed_seconds": round(elapsed, 1),
            "auto_blocked": should_block,
            "forensic_case_created": results.get("forensics", {}).get("forensic_case_id") is not None,
            "hunt_findings": results.get("hunter", {}).get("findings_count", 0),
        })

        return results

    def _should_auto_block(self, alert: Dict, results: Dict) -> bool:
        """Decide whether to auto-block based on agent consensus."""
        severity = alert.get("severity", "low").lower()
        source_ip = alert.get("source_ip")

        if not source_ip:
            return False

        # Always block critical
        if severity == "critical":
            return True

        # Block high if analyst confirmed threat
        analyst_confirmed = results.get("analyst", {}).get("threat_confirmed", False)
        if severity == "high" and analyst_confirmed:
            return True

        # Block if SOC escalated AND severity is at least high
        soc_escalate = results.get("soc", {}).get("escalate_to_human", False)
        if soc_escalate and severity in ["high", "critical"]:
            return True

        # Block if repeat offender (SOC detected)
        repeat_offender = results.get("soc", {}).get("repeat_offender", False)
        if repeat_offender and severity in ["medium", "high", "critical"]:
            return True

        # Block if hunter found high-confidence match for this IP
        hunter_blocks = results.get("hunter", {}).get("recommended_blocks", [])
        if source_ip in hunter_blocks:
            return True

        # Block if responder's LLM recommendation says to block
        responder_actions = results.get("responder", {}).get("actions_taken", [])
        for action in responder_actions:
            if action.get("action") == "block_ip" and action.get("status") == "success":
                return True  # Already blocked by responder

        return False

    async def _auto_block_ip(self, ip: str, alert: Dict, results: Dict) -> Dict:
        """Block a malicious IP and log the action."""
        reason = (
            f"Auto-blocked: Alert '{alert.get('title', 'Unknown')}' "
            f"[{alert.get('severity', 'unknown').upper()}] — "
            f"Confirmed by {sum(1 for k in ['soc', 'analyst'] if 'error' not in results.get(k, {}))} agents"
        )

        # Record in blocked_ips collection
        try:
            await col("blocked_ips").update_one(
                {"ip": ip},
                {"$set": {
                    "ip": ip,
                    "blocked_at": datetime.utcnow(),
                    "reason": reason,
                    "alert_id": alert.get("id") or str(alert.get("_id", "")),
                    "alert_title": alert.get("title"),
                    "severity": alert.get("severity"),
                    "blocked_by": "agent_manager_auto",
                    "active": True,
                }},
                upsert=True
            )
        except Exception as e:
            logger.error(f"Failed to record blocked IP: {e}")

        # Attempt OS-level firewall block
        fw_success = False
        fw_message = ""
        try:
            if platform.system() == "Windows":
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name=SIEM_AUTOBLOCK_{ip}",
                    "dir=in", "action=block",
                    f"remoteip={ip}",
                    "enable=yes"
                ]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                fw_success = result.returncode == 0
                fw_message = "Windows Firewall rule added" if fw_success else f"Firewall error: {result.stderr}"
            else:
                result = subprocess.run(
                    ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                    capture_output=True, text=True, timeout=10
                )
                fw_success = result.returncode == 0
                fw_message = "iptables rule added" if fw_success else f"iptables error: {result.stderr}"
        except PermissionError:
            fw_message = "Permission denied — run as administrator for OS-level blocking"
        except Exception as e:
            fw_message = f"Firewall block exception: {e}"

        self._blocked_ips.add(ip)

        block_result = {
            "blocked": True,
            "ip": ip,
            "reason": reason,
            "firewall_success": fw_success,
            "firewall_message": fw_message,
            "success": True,  # DB record always succeeds
            "timestamp": datetime.utcnow().isoformat(),
        }

        # Log the block action
        await self._log_action("auto_blocker", alert.get("id", ""), "auto_block_ip", block_result)

        if fw_success:
            logger.success(f"🛡️ AUTO-BLOCKED IP {ip}: {reason}")
        else:
            logger.warning(f"⚠️ IP {ip} blocked in DB but firewall block failed: {fw_message}")

        return block_result

    async def _log_action(self, agent: str, alert_id: str, action: str, result: Dict):
        try:
            await col("agent_actions").insert_one({
                "timestamp": datetime.utcnow(),
                "agent_type": agent,
                "alert_id": alert_id,
                "action": action,
                "result": str(result.get("summary") or result.get("action") or "completed"),
                "success": "error" not in result,
                "details": result
            })
        except Exception as e:
            logger.error(f"Agent action log error: {e}")

    async def _broadcast_agent_event(self, event_type: str, alert_id: str, data: Dict):
        """Broadcast agent activity to frontend via WebSocket."""
        try:
            from app.main import ws_manager  # type: ignore
            await ws_manager.broadcast({
                "type": "agent_activity",
                "event": event_type,
                "alert_id": alert_id,
                "data": data,
                "timestamp": datetime.utcnow().isoformat(),
            })
        except ImportError:
            pass  # ws_manager not available (e.g., running standalone)
        except Exception as e:
            logger.debug(f"WS broadcast error (non-critical): {e}")

    async def get_blocked_ips(self) -> List[Dict]:
        """Get all currently blocked IPs."""
        blocked = []
        try:
            cursor = col("blocked_ips").find({"active": True}).sort("blocked_at", -1)
            async for doc in cursor:
                doc["id"] = str(doc.pop("_id", ""))
                if isinstance(doc.get("blocked_at"), datetime):
                    doc["blocked_at"] = doc["blocked_at"].isoformat()
                blocked.append(doc)
        except Exception as e:
            logger.error(f"Get blocked IPs error: {e}")
        return blocked

    async def unblock_ip(self, ip: str) -> Dict:
        """Unblock an IP address."""
        try:
            # Update DB
            await col("blocked_ips").update_one(
                {"ip": ip},
                {"$set": {"active": False, "unblocked_at": datetime.utcnow()}}
            )

            # Remove firewall rule
            fw_success = False
            try:
                if platform.system() == "Windows":
                    cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name=SIEM_AUTOBLOCK_{ip}"]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    fw_success = result.returncode == 0
                else:
                    result = subprocess.run(
                        ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                        capture_output=True, text=True, timeout=10
                    )
                    fw_success = result.returncode == 0
            except Exception:
                pass

            self._blocked_ips.discard(ip)
            logger.info(f"🔓 IP {ip} unblocked (firewall: {'success' if fw_success else 'manual needed'})")
            return {"success": True, "ip": ip, "firewall_removed": fw_success}
        except Exception as e:
            logger.error(f"Unblock IP error: {e}")
            return {"success": False, "error": str(e)}


agent_manager = AgentManager()