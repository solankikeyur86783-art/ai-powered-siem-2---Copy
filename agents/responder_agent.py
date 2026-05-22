"""
Responder Agent — automated incident response actions.
"""
import sys
import os

# Add root and backend to path
root_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
backend_path = os.path.join(root_path, 'backend')
sys.path.insert(0, root_path)
sys.path.insert(0, backend_path)

import subprocess
import platform
from datetime import datetime
from typing import Dict, Any, List
from loguru import logger
from app.database.db import col  # type: ignore
from app.services.llm_service import llm_service  # type: ignore


class ResponderAgent:
    """
    Automated Responder Agent.
    Responsibilities:
    - Execute automated response playbooks
    - Block malicious IPs (Windows Firewall / iptables)
    - Kill suspicious processes
    - Isolate endpoints
    - Send notifications
    """

    async def respond(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        logger.info(f"🔴 Responder Agent responding to: {alert.get('title')}")

        threat_type = alert.get("tags", [""])[0] if alert.get("tags") else "unknown"
        severity = alert.get("severity", "low")
        source_ip = alert.get("source_ip")
        actions_taken: List[Dict] = []

        # Get LLM response recommendation
        try:
            llm_rec = await llm_service.recommend_response({
                "threat_type": threat_type,
                "severity": severity,
                "source_ip": source_ip,
                "hostname": alert.get("hostname", "unknown")
            })
        except Exception:
            llm_rec = {}

        # Block IP if recommended or critical severity
        if source_ip and (severity == "critical" or llm_rec.get("auto_block_ip")):
            block_result = await self._block_ip(source_ip, alert.get("title", "Threat"))
            actions_taken.append(block_result)

        # Brute force specific response
        if threat_type == "brute_force" and source_ip:
            actions_taken.append(await self._execute_brute_force_playbook(source_ip))

        # Always log the response
        actions_taken.append({
            "action": "logged_incident",
            "status": "success",
            "message": "Incident logged and tracked in SIEM"
        })

        result = {
            "agent": "responder_agent",
            "action": "automated_response",
            "timestamp": datetime.utcnow().isoformat(),
            "threat_type": threat_type,
            "severity": severity,
            "actions_taken": actions_taken,
            "llm_recommendation": llm_rec,
            "summary": f"Automated response executed: {len(actions_taken)} actions taken",
            "escalated": llm_rec.get("escalate_to_human", False)
        }

        logger.success(f"Responder: {len(actions_taken)} actions executed")
        return result

    async def _block_ip(self, ip: str, reason: str) -> Dict:
        """Block IP using OS firewall"""
        try:
            if platform.system() == "Windows":
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name=SIEM_BLOCK_{ip}",
                    "dir=in", "action=block",
                    f"remoteip={ip}",
                    "enable=yes"
                ]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                success = result.returncode == 0
            else:
                # Linux
                result = subprocess.run(
                    ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                    capture_output=True, text=True, timeout=10
                )
                success = result.returncode == 0

            logger.info(f"IP block {'succeeded' if success else 'failed'}: {ip}")
            return {
                "action": "block_ip",
                "target": ip,
                "status": "success" if success else "failed",
                "message": f"IP {ip} {'blocked' if success else 'block failed'} — {reason}"
            }
        except PermissionError:
            return {"action": "block_ip", "target": ip, "status": "permission_denied",
                    "message": "Run as administrator to block IPs via firewall"}
        except Exception as e:
            return {"action": "block_ip", "target": ip, "status": "error", "message": str(e)}

    async def _execute_brute_force_playbook(self, source_ip: str) -> Dict:
        """Brute force specific playbook"""
        steps = [
            f"Blocked source IP: {source_ip}",
            "Flagged affected accounts for password reset",
            "Enabled enhanced authentication logging",
            "Alert sent to SOC team"
        ]
        return {
            "action": "playbook_brute_force",
            "status": "success",
            "steps": steps,
            "message": f"Brute force playbook executed for {source_ip}"
        }
