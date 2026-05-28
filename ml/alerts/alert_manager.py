import json
import time
from collections import defaultdict

import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ALERT_FILE = os.path.join(BASE_DIR, "scripts", "alerts.json")
# Track attacks per IP
ip_counter = defaultdict(int)
last_alert_time = {}
COOLDOWN_SECONDS = 30  # Don't log the same attack from the same IP more than once every 30 seconds

def get_severity(attack_type, count):
    attack_type_upper = str(attack_type).upper()
    if "INFILTRATION" in attack_type_upper or "BOT" in attack_type_upper:
        return "CRITICAL"
    elif "DDOS" in attack_type_upper or "DOS" in attack_type_upper or "BRUTE" in attack_type_upper:
        return "HIGH"
    elif count > 5:
        return "MEDIUM"
    else:
        return "LOW"

import subprocess
import threading

# Keep track of blocked IPs to avoid redundant firewall rules
blocked_ips = set()

# Whitelist: Safe IPs that will never be blocked or flagged
WHITELIST_IPS = {"127.0.0.1", "localhost", "192.168.1.1", "192.168.0.1"}

BLOCK_DURATION_SECONDS = 60

def take_action(src_ip, severity):
    if severity == "LOW":
        # Log only (handled by default)
        pass
    elif severity == "MEDIUM":
        print(f"  [ACTION] Flagged IP {src_ip} for suspicious activity.")
    elif severity == "HIGH":
        print(f"  [ACTION] Flagged IP {src_ip} and marked for Rate Limiting (Future Feature).")
    elif severity == "CRITICAL":
        if src_ip not in blocked_ips:
            print(f"  [ACTION] CRITICAL THREAT! Blocking IP {src_ip} via Windows Firewall for {BLOCK_DURATION_SECONDS}s...")
            blocked_ips.add(src_ip)
            # Threading prevents blocking the main alert/sniffing pipeline
            threading.Thread(target=block_ip_windows, args=(src_ip,), daemon=True).start()

def block_ip_windows(ip):
    try:
        rule_name = f"SOC_BLOCK_{ip}"
        cmd = ["netsh", "advfirewall", "firewall", "add", "rule", 
               f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip}"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"  [SUCCESS] Firewall Rule Added: Blocked {ip}. Auto-unblock in {BLOCK_DURATION_SECONDS}s.")
            # Schedule auto unblock
            threading.Timer(BLOCK_DURATION_SECONDS, unblock_ip_windows, args=(ip, rule_name)).start()
        else:
            print(f"  [WARNING] Firewall Block Failed (Run as Admin?): {result.stderr.strip() or result.stdout.strip()}")
            blocked_ips.discard(ip) # Remove from blocked tracking if it failed
    except Exception as e:
        print(f"  [ERROR] Failed to execute firewall command for {ip}: {e}")
        blocked_ips.discard(ip)

def unblock_ip_windows(ip, rule_name):
    try:
        cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"\n  [INFO] Auto-Unblocked IP {ip} (Timeout Reached)")
        else:
            print(f"\n  [WARNING] Failed to auto-unblock IP {ip}")
    except Exception as e:
        print(f"\n  [ERROR] Exception during auto-unblock for {ip}: {e}")
    finally:
        if ip in blocked_ips:
            blocked_ips.remove(ip)

def save_alert(src_ip, dst_ip, attack_type):
    if src_ip in WHITELIST_IPS:
        # Ignore traffic from safe whitelisted IPs entirely
        return

    current_time = time.time()
    alert_key = f"{src_ip}_{attack_type}"
    
    # Check cooldown to prevent alert spam
    if alert_key in last_alert_time and (current_time - last_alert_time[alert_key]) < COOLDOWN_SECONDS:
        return  # Skip duplicate
    
    last_alert_time[alert_key] = current_time

    ip_counter[src_ip] += 1
    count = ip_counter[src_ip]

    severity = get_severity(attack_type, count)

    alert = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "attack_type": attack_type,
        "count": count,
        "severity": severity,
        "action_taken": "Blocked" if severity == "CRITICAL" else ("Flagged" if severity in ["MEDIUM", "HIGH"] else "Logged")
    }

    # Save to file
    with open(ALERT_FILE, "a") as f:
        f.write(json.dumps(alert) + "\n")

    print(f"\n[ALERT] [{severity}] {attack_type} | {src_ip} (count={count})")
    take_action(src_ip, severity)