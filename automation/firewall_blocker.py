"""
Firewall Blocker — blocks IPs via Windows Firewall or iptables.
Called by the Responder Agent automatically.
"""
import subprocess
import platform
import sys
from loguru import logger

def block_ip(ip: str, reason: str = "SIEM Auto-Block") -> bool:
    try:
        if platform.system() == "Windows":
            result = subprocess.run([
                "netsh","advfirewall","firewall","add","rule",
                f"name=SIEM_BLOCK_{ip}","dir=in","action=block",
                f"remoteip={ip}","enable=yes"
            ], capture_output=True, text=True, timeout=10)
            success = result.returncode == 0
        else:
            result = subprocess.run(
                ["iptables","-A","INPUT","-s",ip,"-j","DROP"],
                capture_output=True, text=True, timeout=10
            )
            success = result.returncode == 0
        logger.info(f"Block IP {ip}: {'SUCCESS' if success else 'FAILED'} — {reason}")
        return success
    except PermissionError:
        logger.error("Need admin/root privileges to block IPs")
        return False
    except Exception as e:
        logger.error(f"Block IP error: {e}")
        return False

def unblock_ip(ip: str) -> bool:
    try:
        if platform.system() == "Windows":
            result = subprocess.run([
                "netsh","advfirewall","firewall","delete","rule",
                f"name=SIEM_BLOCK_{ip}"
            ], capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        else:
            result = subprocess.run(
                ["iptables","-D","INPUT","-s",ip,"-j","DROP"],
                capture_output=True, text=True, timeout=10
            )
            return result.returncode == 0
    except Exception as e:
        logger.error(f"Unblock IP error: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python firewall_blocker.py <ip> [reason]")
        sys.exit(1)
    ip = sys.argv[1]
    reason = sys.argv[2] if len(sys.argv) > 2 else "Manual block"
    success = block_ip(ip, reason)
    print(f"{'✅ Blocked' if success else '❌ Failed'}: {ip}")
