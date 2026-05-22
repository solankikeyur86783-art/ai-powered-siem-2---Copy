"""
Rule Engine — Sigma-style rules for threat detection.
Each rule returns a match dict or None.
"""
import re
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from loguru import logger

# Windows Event IDs of interest
BRUTE_FORCE_EVENT_IDS = {4625, 4771, 4776}  # Failed logon
SUCCESS_LOGON_IDS = {4624}
PRIVILEGE_USE_IDS = {4672, 4673, 4674}
PROCESS_CREATE_IDS = {4688, 1}
NETWORK_IDS = {5156, 5157, 3}
USER_CHANGE_IDS = {4720, 4722, 4724, 4728, 4732, 4756}
AUDIT_CHANGE_IDS = {4719, 4906}
SUSPICIOUS_PROCESS_NAMES = {
    "mimikatz", "meterpreter", "empire", "powersploit",
    "cobalt", "psexec", "wce.exe", "fgdump", "pwdump",
    "procdump", "lsass", "nmap", "masscan"
}

RULES = []


def rule(name: str, severity: str, threat_type: str, mitre_tactic: str = None, mitre_technique: str = None):
    """Decorator to register detection rules"""
    def decorator(func):
        RULES.append({
            "name": name,
            "severity": severity,
            "threat_type": threat_type,
            "mitre_tactic": mitre_tactic,
            "mitre_technique": mitre_technique,
            "func": func
        })
        return func
    return decorator


@rule("Brute Force - Multiple Failed Logins",
      severity="high", threat_type="brute_force",
      mitre_tactic="Credential Access", mitre_technique="T1110")
def detect_brute_force(log: Dict[str, Any]) -> Optional[str]:
    event_id = log.get("event_id")
    if event_id in BRUTE_FORCE_EVENT_IDS:
        return f"Failed authentication attempt detected (Event ID: {event_id})"
    return None


@rule("Privilege Escalation - Special Privileges Assigned",
      severity="high", threat_type="privilege_escalation",
      mitre_tactic="Privilege Escalation", mitre_technique="T1068")
def detect_privilege_escalation(log: Dict[str, Any]) -> Optional[str]:
    event_id = log.get("event_id")
    if event_id in PRIVILEGE_USE_IDS:
        return f"Privileged operation detected (Event ID: {event_id})"
    return None


@rule("Suspicious Process Creation",
      severity="high", threat_type="malware",
      mitre_tactic="Execution", mitre_technique="T1059")
def detect_suspicious_process(log: Dict[str, Any]) -> Optional[str]:
    event_id = log.get("event_id")
    message = (log.get("message") or "").lower()
    raw = log.get("raw") or {}

    if event_id in PROCESS_CREATE_IDS:
        process_name = str(raw.get("process", {}).get("name", "")).lower()
        cmd_line = str(raw.get("process", {}).get("command_line", "")).lower()

        for suspicious in SUSPICIOUS_PROCESS_NAMES:
            if suspicious in process_name or suspicious in cmd_line or suspicious in message:
                return f"Suspicious process detected: {suspicious}"

        # PowerShell encoded commands
        if "powershell" in process_name and ("-enc" in cmd_line or "-encodedcommand" in cmd_line):
            return "Encoded PowerShell command — possible obfuscation"

    return None


@rule("User Account Created",
      severity="medium", threat_type="privilege_escalation",
      mitre_tactic="Persistence", mitre_technique="T1136")
def detect_user_creation(log: Dict[str, Any]) -> Optional[str]:
    event_id = log.get("event_id")
    if event_id == 4720:
        return "New user account created"
    return None


@rule("Audit Policy Changed",
      severity="medium", threat_type="privilege_escalation",
      mitre_tactic="Defense Evasion", mitre_technique="T1562")
def detect_audit_change(log: Dict[str, Any]) -> Optional[str]:
    event_id = log.get("event_id")
    if event_id in AUDIT_CHANGE_IDS:
        return f"Audit policy modification detected (Event ID: {event_id})"
    return None


@rule("Port Scan Detected",
      severity="medium", threat_type="port_scan",
      mitre_tactic="Discovery", mitre_technique="T1046")
def detect_port_scan(log: Dict[str, Any]) -> Optional[str]:
    message = (log.get("message") or "").lower()
    if any(kw in message for kw in ["port scan", "nmap", "masscan", "portscan"]):
        return "Port scanning activity detected"
    return None


@rule("Lateral Movement - Remote Service",
      severity="high", threat_type="lateral_movement",
      mitre_tactic="Lateral Movement", mitre_technique="T1021")
def detect_lateral_movement(log: Dict[str, Any]) -> Optional[str]:
    event_id = log.get("event_id")
    raw = log.get("raw") or {}
    if event_id == 4624:
        logon_type = raw.get("winlog", {}).get("event_data", {}).get("LogonType")
        if logon_type in ["3", "10", 3, 10]:
            return f"Remote network/interactive logon (Type {logon_type}) — possible lateral movement"
    return None


@rule("Data Exfiltration - Large Outbound Transfer",
      severity="high", threat_type="data_exfiltration",
      mitre_tactic="Exfiltration", mitre_technique="T1048")
def detect_exfiltration(log: Dict[str, Any]) -> Optional[str]:
    message = (log.get("message") or "").lower()
    if any(kw in message for kw in ["exfil", "large transfer", "unusual upload", "data transfer"]):
        return "Potential data exfiltration activity"
    return None


@rule("Malware Indicator in Log",
      severity="critical", threat_type="malware",
      mitre_tactic="Execution", mitre_technique="T1204")
def detect_malware_keywords(log: Dict[str, Any]) -> Optional[str]:
    message = (log.get("message") or "").lower()
    malware_keywords = [
        "ransomware", "trojan", "rootkit", "keylogger", "backdoor",
        "c2", "command and control", "beacon", "shellcode", "exploit"
    ]
    for kw in malware_keywords:
        if kw in message:
            return f"Malware indicator found: '{kw}'"
    return None


@rule("DNS Tunneling Detected",
      severity="high", threat_type="data_exfiltration",
      mitre_tactic="Exfiltration", mitre_technique="T1071.004")
def detect_dns_tunneling(log: Dict[str, Any]) -> Optional[str]:
    message = (log.get("message") or "").lower()
    raw = log.get("raw") or {}
    dns_query = str(raw.get("dns", {}).get("query", "")).lower() or ""

    # Suspiciously long DNS queries (possible data exfiltration)
    if dns_query and len(dns_query) > 80:
        return f"Suspiciously long DNS query ({len(dns_query)} chars) — possible DNS tunneling"

    # Known DNS tunneling indicators
    if any(kw in message for kw in ["dns tunnel", "iodine", "dnscat", "dns exfil"]):
        return "DNS tunneling indicator detected in log message"

    # High entropy subdomain (base64/hex encoded data in subdomain)
    if dns_query:
        subdomain = dns_query.split('.')[0]
        if len(subdomain) > 30 and sum(c.isdigit() for c in subdomain) > len(subdomain) * 0.3:
            return f"High-entropy DNS subdomain detected — possible DNS data exfiltration"
    return None


@rule("Credential Dumping Detected",
      severity="critical", threat_type="privilege_escalation",
      mitre_tactic="Credential Access", mitre_technique="T1003")
def detect_credential_dumping(log: Dict[str, Any]) -> Optional[str]:
    message = (log.get("message") or "").lower()
    raw = log.get("raw") or {}
    process_name = str(raw.get("process", {}).get("name", "")).lower()
    cmd_line = str(raw.get("process", {}).get("command_line", "")).lower()

    # LSASS access
    if "lsass" in message or "lsass" in process_name:
        if any(kw in message for kw in ["access", "dump", "memory", "sekurlsa"]):
            return "LSASS memory access detected — credential dumping attempt"

    # SAM/SYSTEM hive access
    if any(kw in message for kw in ["sam hive", "system hive", "security hive",
                                      "reg save", "ntds.dit", "secretsdump"]):
        return "Registry hive / NTDS.dit access — credential extraction attempt"

    # Shadow file access (Linux)
    if "/etc/shadow" in message or "passwd" in message and "cat" in message:
        return "Password file access detected — possible credential harvesting"

    # Mimikatz patterns
    if any(kw in (cmd_line + " " + message) for kw in [
        "sekurlsa", "kerberos::list", "crypto::certificates",
        "privilege::debug", "token::elevate", "lsadump"
    ]):
        return "Mimikatz-style credential extraction detected"

    return None


@rule("Reverse Shell Detected",
      severity="critical", threat_type="malware",
      mitre_tactic="Execution", mitre_technique="T1059")
def detect_reverse_shell(log: Dict[str, Any]) -> Optional[str]:
    message = (log.get("message") or "").lower()
    raw = log.get("raw") or {}
    cmd_line = str(raw.get("process", {}).get("command_line", "")).lower()

    reverse_shell_patterns = [
        "bash -i >& /dev/tcp", "nc -e /bin/sh", "nc -e /bin/bash",
        "python -c 'import socket", "php -r '$sock=fsockopen",
        "ruby -rsocket", "perl -e 'use Socket", "ncat -e",
        "/dev/tcp/", "mkfifo /tmp", "powershell -nop -c \"$client",
        "invoke-powershellTcp", "reverse_tcp", "meterpreter"
    ]

    combined = cmd_line + " " + message
    for pattern in reverse_shell_patterns:
        if pattern in combined:
            return f"Reverse shell pattern detected: '{pattern}'"
    return None


@rule("Web Shell Activity",
      severity="critical", threat_type="malware",
      mitre_tactic="Persistence", mitre_technique="T1505.003")
def detect_web_shell(log: Dict[str, Any]) -> Optional[str]:
    message = (log.get("message") or "").lower()

    web_shell_indicators = [
        "c99", "r57", "b374k", "wso", "web shell", "webshell",
        "cmd.php", "cmd.asp", "cmd.jsp", "eval(base64",
        "system(", "passthru(", "shell_exec(", "exec(",
        "<?php @eval", "<?php system"
    ]

    for indicator in web_shell_indicators:
        if indicator in message:
            return f"Web shell indicator detected: '{indicator}'"
    return None


@rule("Ransomware Behavior Detected",
      severity="critical", threat_type="malware",
      mitre_tactic="Impact", mitre_technique="T1486")
def detect_ransomware_behavior(log: Dict[str, Any]) -> Optional[str]:
    message = (log.get("message") or "").lower()

    ransom_indicators = [
        "your files have been encrypted", "bitcoin", "ransom",
        "decrypt your", "pay to recover", ".encrypted", ".locked",
        "vssadmin delete shadows", "bcdedit /set", "wbadmin delete",
        "cipher /w:", "readme.txt created in multiple",
        "mass file rename", "mass file encryption"
    ]

    for indicator in ransom_indicators:
        if indicator in message:
            return f"Ransomware behavior indicator: '{indicator}'"
    return None


@rule("C2 Beaconing Communication",
      severity="high", threat_type="malware",
      mitre_tactic="Command and Control", mitre_technique="T1071")
def detect_c2_beaconing(log: Dict[str, Any]) -> Optional[str]:
    message = (log.get("message") or "").lower()

    c2_indicators = [
        "beacon", "callback", "c2 server", "command and control",
        "heartbeat", "checkin", "cobalt strike", "empire",
        "metasploit", "cobaltstrike", "sliver", "havoc",
        "brute ratel", "nighthawk"
    ]

    for indicator in c2_indicators:
        if indicator in message:
            return f"C2 framework indicator detected: '{indicator}'"
    return None


def run_rules(log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Run all rules against a log entry. Return first match (highest severity prioritized)."""
    matches = []
    for rule_def in RULES:
        try:
            result = rule_def["func"](log)
            if result:
                matches.append({
                    "rule_name": rule_def["name"],
                    "severity": rule_def["severity"],
                    "threat_type": rule_def["threat_type"],
                    "description": result,
                    "mitre_tactic": rule_def["mitre_tactic"],
                    "mitre_technique": rule_def["mitre_technique"],
                })
        except Exception as e:
            logger.error(f"Rule '{rule_def['name']}' error: {e}")

    if not matches:
        return None

    # Return highest severity match
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    matches.sort(key=lambda m: severity_order.get(m["severity"], 0), reverse=True)
    return matches[0]
