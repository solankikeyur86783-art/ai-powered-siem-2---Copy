"""
Correlator — detects patterns across multiple log events.
E.g. brute force = N failed logins in T seconds from same IP.
Extended with: failed-then-success, multi-host scan, data exfiltration.
"""
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from loguru import logger


class EventCorrelator:
    def __init__(self):
        # ip -> list of timestamps for failed logins
        self._failed_logins: Dict[str, List[datetime]] = defaultdict(list)
        # ip -> list of dest_ports (for port scan detection)
        self._port_attempts: Dict[str, Dict[str, List[datetime]]] = defaultdict(lambda: defaultdict(list))
        # hostname -> list of privilege events
        self._priv_events: Dict[str, List[datetime]] = defaultdict(list)
        # ip -> list of successful login timestamps (for failed-then-success)
        self._success_logins: Dict[str, List[datetime]] = defaultdict(list)
        # ip -> set of destination hosts contacted
        self._host_contacts: Dict[str, Dict[str, List[datetime]]] = defaultdict(lambda: defaultdict(list))
        # ip -> total bytes outbound
        self._outbound_bytes: Dict[str, List[Dict]] = defaultdict(list)

        # Thresholds (lowered for better detection)
        self.BRUTE_FORCE_THRESHOLD = 3         # failures (was 5)
        self.BRUTE_FORCE_WINDOW = 120          # seconds (was 60)
        self.PORT_SCAN_THRESHOLD = 8           # distinct ports (was 10)
        self.PORT_SCAN_WINDOW = 60             # seconds (was 30)
        self.PRIV_ESC_THRESHOLD = 2            # events (was 3)
        self.PRIV_ESC_WINDOW = 300             # seconds
        self.MULTI_HOST_THRESHOLD = 5          # distinct hosts
        self.MULTI_HOST_WINDOW = 300           # seconds
        self.EXFIL_BYTES_THRESHOLD = 50_000_000  # 50MB

    def process(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Returns a correlated threat dict if pattern detected, else None"""
        now = datetime.utcnow()
        event_id = log.get("event_id")
        source_ip = log.get("source_ip")
        hostname = log.get("hostname", "unknown")

        # Brute force correlation
        if event_id in {4625, 4771, 4776} and source_ip:
            return self._check_brute_force(source_ip, now)

        # Successful login after failures (compromised credentials)
        if event_id in {4624} and source_ip:
            success_result = self._check_failed_then_success(source_ip, now)
            if success_result:
                return success_result

        # Port scan correlation
        dest_port = log.get("dest_port")
        if source_ip and dest_port:
            return self._check_port_scan(source_ip, str(dest_port), now)

        # Privilege escalation pattern
        if event_id in {4672, 4673, 4674}:
            return self._check_priv_escalation(hostname, now)

        # Multi-host scan (lateral movement)
        dest_ip = log.get("dest_ip")
        if source_ip and dest_ip and source_ip != dest_ip:
            lateral_result = self._check_multi_host_scan(source_ip, dest_ip, now)
            if lateral_result:
                return lateral_result

        # Data exfiltration (large outbound)
        bytes_out = log.get("bytes_out") or log.get("bytes_sent") or 0
        if source_ip and bytes_out and int(bytes_out) > 0:
            exfil_result = self._check_data_exfiltration(source_ip, int(bytes_out), now)
            if exfil_result:
                return exfil_result

        return None

    def _check_brute_force(self, ip: str, now: datetime) -> Optional[Dict]:
        window_start = now - timedelta(seconds=self.BRUTE_FORCE_WINDOW)
        self._failed_logins[ip].append(now)
        # Trim old events
        self._failed_logins[ip] = [
            t for t in self._failed_logins[ip] if t > window_start
        ]
        count = len(self._failed_logins[ip])
        if count >= self.BRUTE_FORCE_THRESHOLD:
            logger.warning(f"🔴 Brute force detected from {ip}: {count} failures in {self.BRUTE_FORCE_WINDOW}s")
            return {
                "correlation_type": "brute_force",
                "severity": "critical" if count >= 10 else "high",
                "threat_type": "brute_force",
                "description": f"Brute force attack: {count} failed logins in {self.BRUTE_FORCE_WINDOW}s from {ip}",
                "source_ip": ip,
                "count": count,
                "mitre_tactic": "Credential Access",
                "mitre_technique": "T1110"
            }
        return None

    def _check_failed_then_success(self, ip: str, now: datetime) -> Optional[Dict]:
        """Detect successful login after multiple failures — indicates compromised credentials."""
        window_start = now - timedelta(seconds=300)  # 5 min window
        recent_failures = [
            t for t in self._failed_logins.get(ip, []) if t > window_start
        ]
        if len(recent_failures) >= 2:
            logger.warning(f"🔴 Failed-then-success login from {ip}: {len(recent_failures)} failures → success")
            # Clear the failures since we've detected the pattern
            self._failed_logins[ip] = []
            return {
                "correlation_type": "failed_then_success",
                "severity": "critical",
                "threat_type": "brute_force",
                "description": (
                    f"Credential compromise: {len(recent_failures)} failed login attempts "
                    f"followed by successful login from {ip} — likely credentials were brute-forced"
                ),
                "source_ip": ip,
                "count": len(recent_failures) + 1,
                "mitre_tactic": "Credential Access",
                "mitre_technique": "T1110"
            }
        return None

    def _check_port_scan(self, ip: str, port: str, now: datetime) -> Optional[Dict]:
        window_start = now - timedelta(seconds=self.PORT_SCAN_WINDOW)
        self._port_attempts[ip][port].append(now)
        # Count distinct ports in window
        active_ports = {
            p for p, times in self._port_attempts[ip].items()
            if any(t > window_start for t in times)
        }
        if len(active_ports) >= self.PORT_SCAN_THRESHOLD:
            logger.warning(f"🔴 Port scan detected from {ip}: {len(active_ports)} ports")
            return {
                "correlation_type": "port_scan",
                "severity": "high",
                "threat_type": "port_scan",
                "description": f"Port scan: {len(active_ports)} distinct ports probed from {ip} in {self.PORT_SCAN_WINDOW}s",
                "source_ip": ip,
                "count": len(active_ports),
                "mitre_tactic": "Discovery",
                "mitre_technique": "T1046"
            }
        return None

    def _check_priv_escalation(self, hostname: str, now: datetime) -> Optional[Dict]:
        window_start = now - timedelta(seconds=self.PRIV_ESC_WINDOW)
        self._priv_events[hostname].append(now)
        self._priv_events[hostname] = [
            t for t in self._priv_events[hostname] if t > window_start
        ]
        count = len(self._priv_events[hostname])
        if count >= self.PRIV_ESC_THRESHOLD:
            logger.warning(f"🔴 Privilege escalation pattern on {hostname}: {count} events")
            return {
                "correlation_type": "privilege_escalation",
                "severity": "high",
                "threat_type": "privilege_escalation",
                "description": f"Privilege escalation pattern: {count} privilege events on {hostname} in {self.PRIV_ESC_WINDOW}s",
                "source_ip": None,
                "count": count,
                "mitre_tactic": "Privilege Escalation",
                "mitre_technique": "T1068"
            }
        return None

    def _check_multi_host_scan(self, source_ip: str, dest_ip: str, now: datetime) -> Optional[Dict]:
        """Detect one IP contacting many different hosts — lateral movement indicator."""
        window_start = now - timedelta(seconds=self.MULTI_HOST_WINDOW)
        self._host_contacts[source_ip][dest_ip].append(now)

        active_hosts = {
            h for h, times in self._host_contacts[source_ip].items()
            if any(t > window_start for t in times)
        }

        if len(active_hosts) >= self.MULTI_HOST_THRESHOLD:
            logger.warning(f"🔴 Multi-host scan from {source_ip}: {len(active_hosts)} hosts contacted")
            return {
                "correlation_type": "multi_host_scan",
                "severity": "high",
                "threat_type": "lateral_movement",
                "description": (
                    f"Lateral movement: {source_ip} contacted {len(active_hosts)} distinct hosts "
                    f"in {self.MULTI_HOST_WINDOW}s — possible network reconnaissance or lateral movement"
                ),
                "source_ip": source_ip,
                "count": len(active_hosts),
                "mitre_tactic": "Lateral Movement",
                "mitre_technique": "T1021"
            }
        return None

    def _check_data_exfiltration(self, source_ip: str, bytes_out: int, now: datetime) -> Optional[Dict]:
        """Detect large outbound data transfer — data exfiltration indicator."""
        window_start = now - timedelta(hours=1)
        self._outbound_bytes[source_ip].append({"ts": now, "bytes": bytes_out})

        # Trim old entries
        self._outbound_bytes[source_ip] = [
            e for e in self._outbound_bytes[source_ip] if e["ts"] > window_start
        ]

        total_bytes = sum(e["bytes"] for e in self._outbound_bytes[source_ip])

        if total_bytes >= self.EXFIL_BYTES_THRESHOLD:
            mb = total_bytes / (1024 * 1024)
            logger.warning(f"🔴 Data exfiltration from {source_ip}: {mb:.1f}MB outbound in 1h")
            return {
                "correlation_type": "data_exfiltration",
                "severity": "critical",
                "threat_type": "data_exfiltration",
                "description": (
                    f"Data exfiltration: {mb:.1f}MB transferred outbound from {source_ip} "
                    f"in the last hour — possible data theft"
                ),
                "source_ip": source_ip,
                "count": int(mb),
                "mitre_tactic": "Exfiltration",
                "mitre_technique": "T1048"
            }
        return None

    def cleanup(self):
        """Periodic cleanup of old state"""
        cutoff = datetime.utcnow() - timedelta(minutes=10)
        for ip in list(self._failed_logins.keys()):
            self._failed_logins[ip] = [t for t in self._failed_logins[ip] if t > cutoff]
        for ip in list(self._host_contacts.keys()):
            for host in list(self._host_contacts[ip].keys()):
                self._host_contacts[ip][host] = [t for t in self._host_contacts[ip][host] if t > cutoff]
        for ip in list(self._outbound_bytes.keys()):
            self._outbound_bytes[ip] = [e for e in self._outbound_bytes[ip] if e["ts"] > cutoff]
        logger.debug("Correlator state cleaned up")


# Singleton instance
correlator = EventCorrelator()
