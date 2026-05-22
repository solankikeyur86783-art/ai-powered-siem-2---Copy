"""
Honeypot Attack Simulator — sends REAL TCP connections to active honeypots
so they register as actual captures in the SIEM dashboard.
"""
import socket
import time
import random
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

HONEYPOTS = [
    ("Web Admin Trap",       "127.0.0.1", 8888, "http"),
    ("FTP Honeypot",         "127.0.0.1", 2121, "ftp"),
    ("Legacy Telnet Trap",   "127.0.0.1", 2323, "telnet"),
    ("SMB File Share",       "127.0.0.1", 4455, "smb"),
    ("SSH Decoy",            "127.0.0.1", 2222, "ssh"),
]

HTTP_PAYLOADS = [
    b"GET /admin HTTP/1.1\r\nHost: target\r\nUser-Agent: Nikto/2.1.6\r\n\r\n",
    b"GET /wp-login.php HTTP/1.1\r\nHost: target\r\nUser-Agent: sqlmap/1.7\r\n\r\n",
    b"POST /login HTTP/1.1\r\nHost: target\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=admin&password=123456",
    b"GET /../../etc/passwd HTTP/1.1\r\nHost: target\r\n\r\n",
    b"GET /shell.php?cmd=whoami HTTP/1.1\r\nHost: target\r\nUser-Agent: dirbuster\r\n\r\n",
]

SSH_PAYLOADS = [
    b"SSH-2.0-PuTTY_Release_0.78\r\nuser root\npassword admin123\n",
    b"SSH-2.0-libssh2_1.10.0\r\nuser admin\npassword password\n",
    b"SSH-2.0-nmap\r\nuser ubuntu\npassword letmein\n",
]

FTP_PAYLOADS = [
    b"USER admin\r\nPASS password123\r\nLIST\r\n",
    b"USER root\r\nPASS toor\r\nSTOR malware.exe\r\n",
    b"USER anonymous\r\nPASS guest@evil.com\r\nRETR /etc/shadow\r\n",
]

GENERIC_PAYLOADS = [
    b"admin\r\npassword\r\nls -la\r\nwhoami\r\ncat /etc/passwd\r\n",
    b"root\r\n123456\r\npowershell -enc JABjACAAPQ...\r\n",
    b"test\r\ntest\r\nnmap -sV 192.168.1.0/24\r\n",
]


def log(msg, color=Fore.WHITE):
    print(f"{color}[{datetime.now().strftime('%H:%M:%S')}] {msg}{Style.RESET_ALL}")


def attack_honeypot(name, host, port, service, payload):
    """Send a real TCP connection to a honeypot port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))

        # Read banner if any
        try:
            banner = sock.recv(1024)
        except socket.timeout:
            banner = b""

        # Send attack payload
        sock.sendall(payload)
        time.sleep(0.3)

        # Try to read response
        try:
            response = sock.recv(4096)
        except socket.timeout:
            response = b""

        sock.close()
        return True
    except ConnectionRefusedError:
        return None  # Honeypot not running
    except Exception as e:
        return False


def main():
    print("=" * 65)
    print(f"  🍯 Honeypot Attack Simulator")
    print(f"  📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 65)

    total_sent = 0
    total_failed = 0
    total_offline = 0

    for name, host, port, service in HONEYPOTS:
        print(f"\n  🎯 Targeting: {name} ({service}:{port})")
        print("-" * 50)

        if service == "http":
            payloads = HTTP_PAYLOADS
        elif service == "ssh":
            payloads = SSH_PAYLOADS
        elif service == "ftp":
            payloads = FTP_PAYLOADS
        else:
            payloads = GENERIC_PAYLOADS

        # Send 3-5 attack attempts per honeypot
        attack_count = random.randint(3, 5)
        for i in range(attack_count):
            payload = random.choice(payloads)
            result = attack_honeypot(name, host, port, service, payload)

            if result is True:
                log(f"    [{i+1}/{attack_count}] Hit! Payload sent ({len(payload)} bytes) ✓", Fore.GREEN)
                total_sent += 1
            elif result is None:
                log(f"    [{i+1}/{attack_count}] Honeypot OFFLINE — skipping", Fore.RED)
                total_offline += 1
                break
            else:
                log(f"    [{i+1}/{attack_count}] Connection error ✗", Fore.YELLOW)
                total_failed += 1

            time.sleep(0.5)

    print("\n" + "=" * 65)
    print(f"  📊 ATTACK SUMMARY")
    print(f"  ✅ Successful hits : {total_sent}")
    print(f"  ❌ Failed          : {total_failed}")
    print(f"  ⚫ Offline         : {total_offline}")
    print("=" * 65)
    print(f"\n  Check your SIEM Honeypot dashboard now!")


if __name__ == "__main__":
    main()
