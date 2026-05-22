"""
Log Generator — generates realistic Windows event logs for SIEM testing.
Sends a continuous stream of normal + occasional threat traffic.
Usage: python scripts/log_generator.py --rate 10 --threat-rate 0.05
"""
import sys, time, random, argparse, requests
from datetime import datetime
sys.path.insert(0, '.')

API = "http://localhost:8000/api/logs/ingest/raw"

NORMAL_EVENTS = [
    (4624, "INFO",    "Successful logon: {user}"),
    (4634, "INFO",    "Account logoff: {user}"),
    (4648, "INFO",    "Logon attempt with explicit credentials"),
    (4688, "INFO",    "New process: explorer.exe"),
    (5156, "INFO",    "Network connection allowed: port {port}"),
    (4663, "INFO",    "File access: C:\\Users\\{user}\\Documents\\report.docx"),
]

HOSTS = ["WORKSTATION-01","WORKSTATION-02","SERVER-DC01","LAPTOP-HR-05","SERVER-WEB01"]
USERS = ["jsmith","mjohnson","admin","bwilson","system"]
PORTS = [80,443,8080,3389,445,22,53]

def gen_normal():
    event_id, level, msg_tpl = random.choice(NORMAL_EVENTS)
    return {
        "source":    "winlogbeat",
        "hostname":  random.choice(HOSTS),
        "event_id":  event_id,
        "log_level": level,
        "message":   msg_tpl.format(user=random.choice(USERS), port=random.choice(PORTS)),
        "source_ip": f"192.168.1.{random.randint(1,50)}",
    }

def gen_threat():
    threats = [
        {"event_id":4625,"log_level":"WARNING","message":"Failed logon attempt","source_ip":f"185.220.{random.randint(1,255)}.{random.randint(1,255)}","hostname":random.choice(HOSTS)},
        {"event_id":4688,"log_level":"CRITICAL","message":"New process: mimikatz.exe","hostname":random.choice(HOSTS)},
        {"event_id":4672,"log_level":"WARNING","message":"Special privileges assigned","hostname":"SERVER-DC01"},
        {"event_id":5157,"log_level":"INFO","message":"Connection blocked","source_ip":f"10.0.{random.randint(0,255)}.{random.randint(1,255)}","dest_port":random.randint(1,1024),"hostname":random.choice(HOSTS)},
    ]
    return {**random.choice(threats), "source": "winlogbeat"}

def run(rate, threat_rate):
    print(f"🚀 Log generator: {rate}/s, {threat_rate*100:.0f}% threat rate → {API}")
    sent = threats = 0
    while True:
        try:
            log = gen_threat() if random.random() < threat_rate else gen_normal()
            r = requests.post(API, json=log, timeout=3)
            sent += 1
            if log.get("log_level") in ["WARNING","CRITICAL","ERROR"]:
                threats += 1
                print(f"  🔴 [{log['log_level']}] EV:{log.get('event_id')} — {log['message'][:60]}")
            if sent % 50 == 0:
                print(f"  📊 Sent: {sent} | Threats: {threats} | Rate: {rate}/s")
        except Exception as e:
            print(f"  ⚠ Send error: {e}")
        time.sleep(1.0 / max(rate, 1))

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--rate", type=int, default=5, help="Logs per second")
    p.add_argument("--threat-rate", type=float, default=0.05, help="0.0-1.0 threat ratio")
    args = p.parse_args()
    run(args.rate, args.threat_rate)
