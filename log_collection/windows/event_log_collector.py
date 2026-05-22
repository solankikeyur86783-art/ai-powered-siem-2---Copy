"""
Windows Event Log Collector — collects live logs using pywin32.
Run as Administrator on Windows.
Usage: python log_collection/windows/event_log_collector.py
"""
import sys
import json
import time
import threading
import requests
from datetime import datetime
from loguru import logger

SIEM_URL = "http://localhost:8000/api/logs/ingest/raw"

# Windows event logs to monitor
MONITORED_LOGS = ["System", "Application"]

# Critical Windows Security Event IDs
CRITICAL_EVENT_IDS = {
    4624, 4625, 4634, 4648, 4657, 4663, 4672, 4673, 4674,
    4688, 4697, 4720, 4722, 4724, 4728, 4732, 4756, 4719,
    4771, 4776, 5156, 5157, 7045
}


def check_windows():
    if sys.platform != "win32":
        logger.error("This collector requires Windows. Use Winlogbeat on other platforms.")
        sys.exit(1)


def send_to_siem(event_data: dict):
    try:
        requests.post(SIEM_URL, json=event_data, timeout=3)
    except Exception as e:
        logger.debug(f"Send error: {e}")


def collect_with_pywin32(log_name: str):
    """Collect Windows events using pywin32"""
    try:
        import win32evtlog
        import win32evtlogutil
        import win32con
        import pywintypes
    except ImportError:
        logger.error("pywin32 not installed. Run: pip install pywin32")
        return

    logger.info(f"📋 Collecting from: {log_name}")
    hand = win32evtlog.OpenEventLog(None, log_name)

    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    last_record = 0

    while True:
        try:
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            if not events:
                time.sleep(2)
                continue

            for event in events:
                record_num = event.RecordNumber
                if record_num <= last_record:
                    continue
                last_record = record_num

                event_id = event.EventID & 0xFFFF

                # Filter to critical events only (to reduce noise)
                if log_name == "Security" and event_id not in CRITICAL_EVENT_IDS:
                    continue

                try:
                    message = win32evtlogutil.SafeFormatMessage(event, log_name)
                except Exception:
                    message = str(event.StringInserts) if event.StringInserts else ""

                data = {
                    "source": "windows_event_log",
                    "hostname": event.ComputerName,
                    "event_id": event_id,
                    "log_level": _map_event_type(event.EventType),
                    "message": message[:2000],  # Truncate long messages
                    "timestamp": event.TimeGenerated.Format() if event.TimeGenerated else datetime.utcnow().isoformat(),
                    "raw": {
                        "record_number": record_num,
                        "source_name": event.SourceName,
                        "log_name": log_name,
                        "string_inserts": list(event.StringInserts) if event.StringInserts else []
                    }
                }
                send_to_siem(data)
                logger.debug(f"[{log_name}] Event {event_id}: {message[:80]}")

        except Exception as e:
            logger.error(f"Event log read error ({log_name}): {e}")
            time.sleep(5)


def _map_event_type(event_type: int) -> str:
    mapping = {
        1: "ERROR",
        2: "WARNING",
        4: "INFO",
        8: "INFO",
        16: "ERROR"
    }
    return mapping.get(event_type, "INFO")


def start_collection():
    check_windows()
    logger.info("🚀 Windows Event Log Collector starting...")
    logger.info(f"📡 Sending to: {SIEM_URL}")

    # Startup heartbeat
    send_to_siem({
        "source": "windows_event_log",
        "hostname": "local",
        "event_id": 0,
        "log_level": "INFO",
        "message": "Collector service started successfully.",
        "timestamp": datetime.utcnow().isoformat(),
        "raw": {"status": "heartbeat"}
    })

    threads = []
    for log_name in MONITORED_LOGS:
        t = threading.Thread(target=collect_with_pywin32, args=(log_name,), daemon=True)
        t.start()
        threads.append(t)
        logger.info(f"✅ Started collector for: {log_name}")

    logger.success("🟢 All collectors running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        logger.info("Stopping collectors...")


if __name__ == "__main__":
    start_collection()
