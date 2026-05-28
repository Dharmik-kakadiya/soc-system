import time
import requests
import logging
import json
import os

from scapy.all import sniff, IP, TCP, UDP
import threading

# Suppress scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# =========================
# CONFIG
# =========================
API_URL = "http://127.0.0.1:8001/predict"
ALERT_FILE = "alerts.json"

print("\n" + "="*60)
print("[SOC] LIVE PACKET SNIFFER STARTED")
print("="*60)
print("Listening for network traffic...\n")

# =========================
# Helpers
# =========================

import sys
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

from ml.alerts.alert_manager import save_alert
def send_to_api(payload, src_ip, dst_ip, src_port, dst_port):
    try:
        response = requests.post(API_URL, json=payload, timeout=2)
        if response.status_code == 200:
            result = response.json()
            if result.get("attack", False):
                attack_type = result.get("attack_type", "BENIGN")
                print(f"[ATTACK] {attack_type} | {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                save_alert(src_ip, dst_ip, attack_type)
            else:
                print(f"[SAFE] {src_ip} -> {dst_ip}")
    except requests.exceptions.RequestException as e:
        # Catching all requests errors including timeouts
        pass # To avoid spamming terminal when API is slow or offline


# Protocol mapping (IMPORTANT FIX)
PROTO_MAP = {
    6: "tcp",
    17: "udp",
    1: "icmp"
}

# =========================
# Flow storage
# =========================
active_flows = {}
last_cleanup_time = time.time()
FLOW_TIMEOUT = 120

# =========================
# Packet processing
# =========================

def process_packet(packet):

    if IP not in packet:
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    protocol = packet[IP].proto

    protocol_name = PROTO_MAP.get(protocol, "tcp")

    src_port = 0
    dst_port = 0
    flags = ""
    win_bytes = -1
    has_payload = False

    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        flags = str(packet[TCP].flags)
        win_bytes = packet[TCP].window
        if len(packet[TCP].payload) > 0: has_payload = True
    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        if len(packet[UDP].payload) > 0: has_payload = True

    flow_id_1 = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
    flow_id_2 = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
    
    current_time = time.time()

    global last_cleanup_time
    if current_time - last_cleanup_time > 60:
        stale = [k for k, v in active_flows.items() if current_time - v["start_time"] > FLOW_TIMEOUT]
        for k in stale:
            del active_flows[k]
        last_cleanup_time = current_time

    # Identify direction and flow ID
    if flow_id_1 in active_flows:
        flow_id = flow_id_1
        direction = "fwd"
    elif flow_id_2 in active_flows:
        flow_id = flow_id_2
        direction = "bwd"
    else:
        # New flow, this packet is the initiator (forward)
        flow_id = flow_id_1
        direction = "fwd"
        active_flows[flow_id] = {
            "start_time": current_time,
            "last_time": current_time,
            "protocol": protocol_name,
            "dst port": dst_port,
            "tot fwd pkts": 0, "tot bwd pkts": 0,
            "totlen fwd pkts": 0, "totlen bwd pkts": 0,
            "fwd pkt len max": 0, "fwd pkt len min": 999999,
            "bwd pkt len max": 0, "bwd pkt len min": 999999,
            "fwd header len": 0, "bwd header len": 0,
            "fin flag cnt": 0, "syn flag cnt": 0, "rst flag cnt": 0,
            "psh flag cnt": 0, "ack flag cnt": 0, "urg flag cnt": 0,
            "init fwd win byts": -1, "init bwd win byts": -1,
            "fwd act data pkts": 0, "fwd seg size min": 0,
            "flow iat tot": 0, "flow iat max": 0, "flow iat min": 999999,
            "fwd iat tot": 0, "fwd iat max": 0, "fwd iat min": 999999,
            "bwd iat tot": 0, "bwd iat max": 0, "bwd iat min": 999999,
            "last_fwd_time": 0, "last_bwd_time": 0
        }

    flow = active_flows[flow_id]
    pkt_len = len(packet)
    
    header_len = 20 # Basic IP header
    if TCP in packet: header_len += 20
    elif UDP in packet: header_len += 8

    # IAT Updates
    iat = (current_time - flow["last_time"]) * 1e6
    if flow["tot fwd pkts"] + flow["tot bwd pkts"] > 0:
        flow["flow iat tot"] += iat
        flow["flow iat max"] = max(flow["flow iat max"], iat)
        flow["flow iat min"] = min(flow["flow iat min"], iat)
    flow["last_time"] = current_time

    # Directional updates
    if direction == "fwd":
        if flow["tot fwd pkts"] > 0:
            fwd_iat = (current_time - flow["last_fwd_time"]) * 1e6
            flow["fwd iat tot"] += fwd_iat
            flow["fwd iat max"] = max(flow["fwd iat max"], fwd_iat)
            flow["fwd iat min"] = min(flow["fwd iat min"], fwd_iat)
        flow["last_fwd_time"] = current_time
        
        flow["tot fwd pkts"] += 1
        flow["totlen fwd pkts"] += pkt_len
        flow["fwd pkt len max"] = max(flow["fwd pkt len max"], pkt_len)
        flow["fwd pkt len min"] = min(flow["fwd pkt len min"], pkt_len)
        flow["fwd header len"] += header_len
        if win_bytes != -1 and flow["init fwd win byts"] == -1: flow["init fwd win byts"] = win_bytes
        if has_payload: flow["fwd act data pkts"] += 1
        flow["fwd seg size min"] = header_len
    else:
        if flow["tot bwd pkts"] > 0:
            bwd_iat = (current_time - flow["last_bwd_time"]) * 1e6
            flow["bwd iat tot"] += bwd_iat
            flow["bwd iat max"] = max(flow["bwd iat max"], bwd_iat)
            flow["bwd iat min"] = min(flow["bwd iat min"], bwd_iat)
        flow["last_bwd_time"] = current_time
        
        flow["tot bwd pkts"] += 1
        flow["totlen bwd pkts"] += pkt_len
        flow["bwd pkt len max"] = max(flow["bwd pkt len max"], pkt_len)
        flow["bwd pkt len min"] = min(flow["bwd pkt len min"], pkt_len)
        flow["bwd header len"] += header_len
        if win_bytes != -1 and flow["init bwd win byts"] == -1: flow["init bwd win byts"] = win_bytes

    # Flag updates
    if flags:
        if "F" in flags: flow["fin flag cnt"] += 1
        if "S" in flags: flow["syn flag cnt"] += 1
        if "R" in flags: flow["rst flag cnt"] += 1
        if "P" in flags: flow["psh flag cnt"] += 1
        if "A" in flags: flow["ack flag cnt"] += 1
        if "U" in flags: flow["urg flag cnt"] += 1

    # Trigger detection logic
    tot_pkts = flow["tot fwd pkts"] + flow["tot bwd pkts"]
    if tot_pkts % 15 == 0 or ("F" in flags or "R" in flags):
        
        flow_duration_sec = current_time - flow["start_time"]
        flow_duration_us = int(flow_duration_sec * 1e6)
        
        f_mean = flow["totlen fwd pkts"] / flow["tot fwd pkts"] if flow["tot fwd pkts"] > 0 else 0
        b_mean = flow["totlen bwd pkts"] / flow["tot bwd pkts"] if flow["tot bwd pkts"] > 0 else 0
        p_mean = (flow["totlen fwd pkts"] + flow["totlen bwd pkts"]) / tot_pkts if tot_pkts > 0 else 0
        
        payload = {
            "dst port": flow["dst port"],
            "protocol": flow["protocol"],
            "flow duration": flow_duration_us,
            "tot fwd pkts": flow["tot fwd pkts"],
            "tot bwd pkts": flow["tot bwd pkts"],
            "totlen fwd pkts": flow["totlen fwd pkts"],
            "totlen bwd pkts": flow["totlen bwd pkts"],
            "fwd pkt len max": flow["fwd pkt len max"],
            "fwd pkt len min": flow["fwd pkt len min"] if flow["fwd pkt len min"] != 999999 else 0,
            "fwd pkt len mean": f_mean,
            "bwd pkt len max": flow["bwd pkt len max"],
            "bwd pkt len min": flow["bwd pkt len min"] if flow["bwd pkt len min"] != 999999 else 0,
            "bwd pkt len mean": b_mean,
            "flow byts/s": (flow["totlen fwd pkts"] + flow["totlen bwd pkts"]) / flow_duration_sec if flow_duration_sec > 0 else 0,
            "flow pkts/s": tot_pkts / flow_duration_sec if flow_duration_sec > 0 else 0,
            "flow iat tot": flow["flow iat tot"],
            "flow iat max": flow["flow iat max"],
            "flow iat min": flow["flow iat min"] if flow["flow iat min"] != 999999 else 0,
            "flow iat mean": flow["flow iat tot"] / (tot_pkts - 1) if tot_pkts > 1 else 0,
            "fwd iat tot": flow["fwd iat tot"],
            "fwd iat max": flow["fwd iat max"],
            "fwd iat min": flow["fwd iat min"] if flow["fwd iat min"] != 999999 else 0,
            "fwd iat mean": flow["fwd iat tot"] / (flow["tot fwd pkts"] - 1) if flow["tot fwd pkts"] > 1 else 0,
            "bwd iat tot": flow["bwd iat tot"],
            "bwd iat max": flow["bwd iat max"],
            "bwd iat min": flow["bwd iat min"] if flow["bwd iat min"] != 999999 else 0,
            "bwd iat mean": flow["bwd iat tot"] / (flow["tot bwd pkts"] - 1) if flow["tot bwd pkts"] > 1 else 0,
            "fwd header len": flow["fwd header len"],
            "bwd header len": flow["bwd header len"],
            "fwd pkts/s": flow["tot fwd pkts"] / flow_duration_sec if flow_duration_sec > 0 else 0,
            "bwd pkts/s": flow["tot bwd pkts"] / flow_duration_sec if flow_duration_sec > 0 else 0,
            "pkt len min": min(flow["fwd pkt len min"] if flow["fwd pkt len min"] != 999999 else 0, 
                               flow["bwd pkt len min"] if flow["bwd pkt len min"] != 999999 else 0),
            "pkt len max": max(flow["fwd pkt len max"], flow["bwd pkt len max"]),
            "pkt len mean": p_mean,
            "fin flag cnt": flow["fin flag cnt"],
            "syn flag cnt": flow["syn flag cnt"],
            "rst flag cnt": flow["rst flag cnt"],
            "psh flag cnt": flow["psh flag cnt"],
            "ack flag cnt": flow["ack flag cnt"],
            "urg flag cnt": flow["urg flag cnt"],
            "down/up ratio": flow["totlen bwd pkts"] / flow["totlen fwd pkts"] if flow["totlen fwd pkts"] > 0 else 0,
            "init fwd win byts": flow["init fwd win byts"] if flow["init fwd win byts"] != -1 else 0,
            "init bwd win byts": flow["init bwd win byts"] if flow["init bwd win byts"] != -1 else 0,
            "fwd act data pkts": flow["fwd act data pkts"],
            "fwd seg size min": flow["fwd seg size min"],
            "subflow fwd pkts": flow["tot fwd pkts"],
            "subflow fwd byts": flow["totlen fwd pkts"],
            "subflow bwd pkts": flow["tot bwd pkts"],
            "subflow bwd byts": flow["totlen bwd pkts"],
            "fwd seg size avg": f_mean,
            "bwd seg size avg": b_mean,
            "pkt size avg": p_mean
        }

        # Threading call to avoid blocking sniffer
        threading.Thread(target=send_to_api, args=(payload, src_ip, dst_ip, src_port, dst_port)).start()

        # Clean flow if closed
        if ("F" in flags or "R" in flags) and flow_id in active_flows:
            del active_flows[flow_id]

# =========================
# Start sniffing
# =========================

import socket
from scapy.all import get_working_ifaces

def get_active_interface():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # connect() for UDP doesn't send packets, just resolves routing
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = None
    finally:
        s.close()
        
    if ip:
        for iface in get_working_ifaces():
            if hasattr(iface, 'ip') and iface.ip == ip:
                return iface.name
    return None

try:
    active_iface = get_active_interface()
    if active_iface:
        print(f"[*] Auto-detected active interface: {active_iface}")
        sniff(iface=active_iface, prn=process_packet, store=False)
    else:
        print("[*] Could not auto-detect interface. Using default.")
        sniff(prn=process_packet, store=False)
except KeyboardInterrupt:
    print("\nSniffer stopped.")