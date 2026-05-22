"""
Log Parser — normalizes logs from various sources into a unified format.
Supports: Winlogbeat, Syslog, CEF, manual
"""
import re
from datetime import datetime
from typing import Dict, Any, Optional
from loguru import logger


def parse_winlogbeat(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Parse Winlogbeat event format"""
    try:
        winlog = raw.get("winlog", {})
        channel = winlog.get("channel")
        
        # User requested not to use Security logs
        if channel == "Security":
            return None
            
        event_data = winlog.get("event_data", {})
        host = raw.get("host", {})
        event = raw.get("event", {})

        source_ip = (
            event_data.get("IpAddress")
            or event_data.get("SourceAddress")
            or event_data.get("ClientAddress")
            or event_data.get("IpAddress")
            or raw.get("source", {}).get("ip")
            or raw.get("source_ip")
            or raw.get("ip")
        )

        # Clean up "-" values
        if source_ip in ["-", "::1", "127.0.0.1"]:
            source_ip = None

        return {
            "timestamp": _parse_timestamp(raw.get("@timestamp") or raw.get("timestamp")),
            "source": channel or "winlogbeat",
            "hostname": host.get("name") or host.get("hostname") or "unknown",
            "source_ip": source_ip,
            "dest_ip": event_data.get("DestAddress"),
            "source_port": _safe_int(event_data.get("SourcePort")),
            "dest_port": _safe_int(event_data.get("DestPort")),
            "event_id": _safe_int(winlog.get("event_id") or event.get("code")),
            "log_level": _map_severity(event.get("severity") or winlog.get("level") or "information"),
            "message": raw.get("message") or event_data.get("SubjectUserName") or "",
            "raw": raw
        }
    except Exception as e:
        logger.error(f"Winlogbeat parse error: {e}")
        return _default_log(raw)


def parse_syslog(line: str) -> Dict[str, Any]:
    """Parse standard syslog format"""
    try:
        # RFC 3164 format: <PRI>MMM DD HH:MM:SS hostname process[pid]: message
        pattern = r'^<(\d+)>(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(.+)$'
        m = re.match(pattern, line)
        if m:
            priority = int(m.group(1))
            severity_code = priority & 7
            return {
                "timestamp": datetime.utcnow(),
                "source": "syslog",
                "hostname": m.group(3),
                "source_ip": _extract_ip(m.group(4)),
                "log_level": _syslog_severity(severity_code),
                "message": m.group(4),
                "raw": {"raw_line": line}
            }
    except Exception as e:
        logger.error(f"Syslog parse error: {e}")

    return {"timestamp": datetime.utcnow(), "source": "syslog", "message": line, "raw": {"raw_line": line}}


def parse_generic(data: Dict[str, Any]) -> Dict[str, Any]:
    """Parse a generic/manual log dict"""
    return {
        "timestamp": _parse_timestamp(data.get("timestamp")),
        "source": data.get("source", "manual"),
        "hostname": data.get("hostname", "unknown"),
        "source_ip": data.get("source_ip"),
        "dest_ip": data.get("dest_ip"),
        "source_port": _safe_int(data.get("source_port")),
        "dest_port": _safe_int(data.get("dest_port")),
        "event_id": _safe_int(data.get("event_id")),
        "log_level": data.get("log_level", "INFO"),
        "message": data.get("message", ""),
        "raw": data
    }


def auto_parse(data: Dict[str, Any]) -> Dict[str, Any]:
    """Auto-detect and parse log format"""
    if "winlog" in data or ("@timestamp" in data and "host" in data):
        parsed = parse_winlogbeat(data)
        if parsed is None:  # Filtered out (e.g. Security logs)
            return None
        return parsed
    return parse_generic(data)


# ── Helpers ─────────────────────────────────────────────
def _parse_timestamp(ts) -> datetime:
    if ts is None:
        return datetime.utcnow()
    if isinstance(ts, datetime):
        return ts
    try:
        # ISO 8601
        ts_str = str(ts).replace("Z", "+00:00")
        return datetime.fromisoformat(ts_str).replace(tzinfo=None)
    except Exception:
        return datetime.utcnow()


def _safe_int(val) -> Optional[int]:
    try:
        return int(val) if val is not None else None
    except (ValueError, TypeError):
        return None


def _map_severity(level: str) -> str:
    level = str(level).lower()
    mapping = {
        "critical": "CRITICAL", "error": "ERROR", "warning": "WARNING",
        "warn": "WARNING", "information": "INFO", "info": "INFO",
        "verbose": "DEBUG", "debug": "DEBUG", "audit": "INFO"
    }
    return mapping.get(level, "INFO")


def _syslog_severity(code: int) -> str:
    mapping = {0: "CRITICAL", 1: "CRITICAL", 2: "CRITICAL",
               3: "ERROR", 4: "WARNING", 5: "INFO", 6: "INFO", 7: "DEBUG"}
    return mapping.get(code, "INFO")


def _extract_ip(text: str) -> Optional[str]:
    pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    m = re.search(pattern, text)
    return m.group(0) if m else None


def _default_log(raw: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "timestamp": datetime.utcnow(),
        "source": "unknown",
        "hostname": "unknown",
        "source_ip": None,
        "dest_ip": None,
        "source_port": None,
        "dest_port": None,
        "event_id": None,
        "log_level": "INFO",
        "message": str(raw.get("message", "")),
        "raw": raw
    }
