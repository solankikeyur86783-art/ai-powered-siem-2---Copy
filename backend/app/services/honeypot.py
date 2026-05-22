"""
Honeypot Service — Lightweight network honeypots for threat detection
"""
import asyncio
import json
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from loguru import logger
from app.database.db import col


class HoneypotService:
    """Manage lightweight honeypot listeners"""

    def __init__(self):
        self._servers = {}
        self._running = False
        self._stats = {"total_captures": 0, "unique_ips": set()}

    async def start_honeypot(self, service: str = "ssh", port: int = None):
        """Start a honeypot listener"""
        defaults = {"ssh": 2222, "http": 8888, "ftp": 2121, "telnet": 2323, "smb": 4455}
        port = port or defaults.get(service, 9999)

        if service in self._servers:
            return {"status": "already_running", "service": service, "port": port}

        try:
            if service == "http":
                server = await asyncio.start_server(
                    self._handle_http, "0.0.0.0", port
                )
            else:
                server = await asyncio.start_server(
                    self._handle_generic, "0.0.0.0", port
                )

            self._servers[service] = {"server": server, "port": port, "started_at": datetime.utcnow()}
            self._running = True
            logger.success(f"🍯 Honeypot [{service}] started on port {port}")

            return {"status": "started", "service": service, "port": port}
        except OSError as e:
            logger.error(f"Honeypot [{service}] failed to start on port {port}: {e}")
            return {"status": "error", "service": service, "port": port, "error": str(e)}

    async def stop_honeypot(self, service: str):
        """Stop a honeypot listener"""
        if service in self._servers:
            self._servers[service]["server"].close()
            await self._servers[service]["server"].wait_closed()
            del self._servers[service]
            logger.info(f"Honeypot [{service}] stopped")
            return {"status": "stopped", "service": service}
        return {"status": "not_running", "service": service}

    async def stop_all(self):
        for svc in list(self._servers.keys()):
            await self.stop_honeypot(svc)
        self._running = False

    async def _handle_generic(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle generic TCP honeypot connections"""
        peer = writer.get_extra_info("peername")
        ip = peer[0] if peer else "unknown"
        port = peer[1] if peer else 0

        try:
            # Send fake banner
            writer.write(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
            await writer.drain()

            # Read what attacker sends
            data = b""
            try:
                data = await asyncio.wait_for(reader.read(4096), timeout=10)
            except asyncio.TimeoutError:
                pass

            await self._record_capture(ip, port, "ssh", data)

        except Exception as e:
            logger.debug(f"Honeypot connection error: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _handle_http(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle HTTP honeypot connections"""
        peer = writer.get_extra_info("peername")
        ip = peer[0] if peer else "unknown"
        port = peer[1] if peer else 0

        try:
            data = b""
            try:
                data = await asyncio.wait_for(reader.read(8192), timeout=10)
            except asyncio.TimeoutError:
                pass

            # Send fake HTTP response
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Server: Apache/2.4.52 (Ubuntu)\r\n"
                "Content-Type: text/html\r\n\r\n"
                "<html><head><title>Welcome</title></head>"
                "<body><h1>It works!</h1></body></html>"
            )
            writer.write(response.encode())
            await writer.drain()

            await self._record_capture(ip, port, "http", data)

        except Exception as e:
            logger.debug(f"HTTP honeypot error: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _record_capture(self, ip: str, port: int, service: str, data: bytes):
        """Record a honeypot interaction"""
        decoded = ""
        try:
            decoded = data.decode("utf-8", errors="replace")[:2000]
        except Exception:
            decoded = data.hex()[:2000] if data else ""

        # Extract credentials if present
        creds = self._extract_credentials(decoded, service)

        capture = {
            "timestamp": datetime.utcnow(),
            "source_ip": ip,
            "source_port": port,
            "service": service,
            "payload_preview": decoded[:500],
            "payload_size": len(data) if data else 0,
            "credentials": creds,
            "risk_indicators": self._analyze_payload(decoded),
        }

        await col("honeypot_captures").insert_one(capture)
        self._stats["total_captures"] += 1
        self._stats["unique_ips"].add(ip)

        logger.warning(f"🍯 Honeypot [{service}] capture from {ip}:{port} ({len(data or b'')} bytes)")

        # Auto-create alert for honeypot hits
        alert = {
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "title": f"Honeypot [{service.upper()}] — Connection from {ip}",
            "description": f"Honeypot on port {self._servers.get(service, {}).get('port', '?')} received connection from {ip}. Payload: {decoded[:200]}",
            "severity": "high" if creds else "medium",
            "status": "open",
            "rule_id": f"honeypot_{service}",
            "source_ip": ip,
            "hostname": "honeypot",
            "tags": ["honeypot", service, "deception"],
        }
        await col("alerts").insert_one(alert)

    def _extract_credentials(self, payload: str, service: str) -> Dict:
        """Try to extract credentials from payload"""
        creds = {}
        if service == "ssh":
            # Look for username/password patterns
            lines = payload.split("\n")
            for line in lines:
                if "user" in line.lower():
                    creds["username_attempt"] = line.strip()[:100]
                if "pass" in line.lower():
                    creds["password_attempt"] = line.strip()[:100]
        elif service == "http":
            if "authorization:" in payload.lower():
                creds["auth_header"] = True
            if "password" in payload.lower() or "passwd" in payload.lower():
                creds["password_in_request"] = True
        return creds

    def _analyze_payload(self, payload: str) -> list:
        """Identify risk indicators in payload"""
        indicators = []
        suspicious = {
            "shell_command": ["/bin/sh", "/bin/bash", "cmd.exe", "powershell"],
            "exploit_attempt": ["exploit", "shellcode", "buffer", "overflow", "../", "..\\"],
            "credential_brute": ["admin", "root", "password", "123456"],
            "scanner": ["nmap", "masscan", "nikto", "dirbuster", "sqlmap"],
            "malware": ["wget ", "curl ", "chmod ", "base64"],
        }
        for category, keywords in suspicious.items():
            for kw in keywords:
                if kw.lower() in payload.lower():
                    indicators.append({"type": category, "keyword": kw})
                    break
        return indicators

    def get_status(self) -> Dict:
        supported = [
            {"service": "ssh", "name": "SSH Decoy", "port": 2222, "ip": "0.0.0.0"},
            {"service": "http", "name": "Web Admin Trap", "port": 8888, "ip": "0.0.0.0"},
            {"service": "ftp", "name": "FTP Honeypot", "port": 2121, "ip": "0.0.0.0"},
            {"service": "telnet", "name": "Legacy Telnet Trap", "port": 2323, "ip": "0.0.0.0"},
            {"service": "smb", "name": "SMB File Share", "port": 4455, "ip": "0.0.0.0"},
        ]

        honeypots_array = []
        for s in supported:
            svc = s["service"]
            is_active = svc in self._servers
            honeypots_array.append({
                "service": svc,
                "name": s["name"],
                "port": self._servers[svc]["port"] if is_active else s["port"],
                "ip": s["ip"],
                "active": is_active,
                "uptime_minutes": int((datetime.utcnow() - self._servers[svc]["started_at"]).total_seconds() / 60) if is_active else 0
            })
            
        return {
            "running": self._running,
            "honeypots": honeypots_array,
            "services": {
                svc: {
                    "port": info["port"],
                    "started_at": info["started_at"].isoformat(),
                    "uptime_minutes": int((datetime.utcnow() - info["started_at"]).total_seconds() / 60),
                }
                for svc, info in self._servers.items()
            },
            "total_captures": self._stats.get("total_captures", 0),
            "unique_attackers": len(self._stats.get("unique_ips", [])),
        }

    async def get_captures(self, hours: int = 24, limit: int = 100) -> list:
        since = datetime.utcnow() - timedelta(hours=hours)
        cursor = col("honeypot_captures").find(
            {"timestamp": {"$gte": since}}
        ).sort("timestamp", -1).limit(limit)
        docs = []
        async for doc in cursor:
            doc["id"] = str(doc.pop("_id"))
            docs.append(doc)
        return docs

    async def get_stats(self, hours: int = 24) -> Dict:
        since = datetime.utcnow() - timedelta(hours=hours)

        total = await col("honeypot_captures").count_documents({"timestamp": {"$gte": since}})
        
        # Unique IPs
        unique_ips = len(await col("honeypot_captures").distinct("source_ip", {"timestamp": {"$gte": since}}))
        
        # Credential attempts (any capture that has something in credentials field)
        creds = await col("honeypot_captures").count_documents({
            "timestamp": {"$gte": since},
            "credentials": {"$ne": {}}
        })

        # Top attacker IPs
        ip_agg = [
            {"$match": {"timestamp": {"$gte": since}}},
            {"$group": {"_id": "$source_ip", "count": {"$sum": 1},
                        "services": {"$addToSet": "$service"}}},
            {"$sort": {"count": -1}},
            {"$limit": 10}
        ]
        top_ips = [{"ip": d["_id"], "count": d["count"], "services": d["services"]}
                   async for d in col("honeypot_captures").aggregate(ip_agg)]

        # By service
        svc_agg = [
            {"$match": {"timestamp": {"$gte": since}}},
            {"$group": {"_id": "$service", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ]
        by_service = [{"service": d["_id"], "count": d["count"]}
                      async for d in col("honeypot_captures").aggregate(svc_agg)]

        status = self.get_status()
        svc_counts = {item["service"]: item["count"] for item in by_service}
        for node in status.get("honeypots", []):
            node["captures"] = svc_counts.get(node["service"], 0)
        
        return {
            **status,
            "total_captures": total,
            "unique_ips": unique_ips,
            "credential_attempts": creds,
            "top_attackers": top_ips,
            "by_service": by_service,
        }


honeypot_service = HoneypotService()
