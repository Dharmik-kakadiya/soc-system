import time
import os
import sys

# Setup paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

from ml.alerts.alert_manager import save_alert

print("[*] Starting Attack Simulation...")
time.sleep(1)

attacks = [
    ("10.0.0.50", "192.168.1.100", "DDoS"),
    ("10.0.0.50", "192.168.1.100", "DDoS"),
    ("10.0.0.50", "192.168.1.100", "DDoS"),
    ("45.33.12.9", "192.168.1.50", "BruteForce"),
    ("45.33.12.9", "192.168.1.50", "BruteForce"),
    ("188.166.45.1", "192.168.1.10", "Infiltration"),
]

for src, dst, atype in attacks:
    print(f"[ATTACK] Injecting: {atype} from {src} -> {dst}")
    save_alert(src, dst, atype)
    time.sleep(1)

print("[DONE] Simulation complete! Check your Dashboard now!")
