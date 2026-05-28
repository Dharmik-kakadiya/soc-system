import streamlit as st
import json
import os
import time
from collections import Counter

# =========================
# File Path Fix (Absolute Path)
# =========================
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALERT_FILE_ROOT = os.path.join(BASE_DIR, "alerts.json")
ALERT_FILE_SCRIPTS = os.path.join(BASE_DIR, "scripts", "alerts.json")

st.set_page_config(page_title="SOC Dashboard", layout="wide", page_icon="shield")

# =========================
# Load alerts (Pure Python, no pandas needed for basic ops)
# =========================
def load_alerts():
    file_path = ALERT_FILE_ROOT if os.path.exists(ALERT_FILE_ROOT) else ALERT_FILE_SCRIPTS
    try:
        with open(file_path, "r") as f:
            data = [json.loads(line) for line in f if line.strip()]
            
        # Deduplicate: Keep only the most recent alert for each (src_ip, attack_type)
        unique_alerts = {}
        for row in data:
            key = f"{row.get('src_ip', '')}_{row.get('attack_type', '')}"
            # Because the file is append-only, the latest occurrences appear last.
            unique_alerts[key] = row
            
        deduplicated_data = list(unique_alerts.values())
        
        # Sort by timestamp descending
        deduplicated_data.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        return deduplicated_data
    except Exception:
        return []

# =========================
# Pure Python chart generator (SVG bar chart - no dependencies!)
# =========================
def make_bar_chart_html(counts: dict, color: str, title: str) -> str:
    if not counts:
        return f"<p style='color:#aaa'>No data yet</p>"
    
    max_val = max(counts.values())
    bars_html = ""
    bar_width = max(30, 300 // len(counts))

    for label, val in list(counts.items())[:10]:
        pct = int((val / max_val) * 150)
        short_label = str(label)[:12] + "..." if len(str(label)) > 12 else str(label)
        bars_html += f"<div style='display:flex; align-items:center; margin:4px 0; gap:8px;'><div style='width:110px; text-align:right; font-size:12px; color:#ccc; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;'>{short_label}</div><div style='background:{color}; width:{pct}px; height:22px; border-radius:4px; transition:width 0.3s;'></div><div style='font-size:12px; color:#fff; font-weight:bold;'>{val}</div></div>"

    return f"<div style='background:#1e1e2e; padding:16px; border-radius:12px; border:1px solid #333;'><div style='color:#fff; font-weight:bold; font-size:15px; margin-bottom:12px;'>{title}</div>{bars_html}</div>"

# =========================
# Render alerts table as HTML
# =========================
def make_table_html(data: list) -> str:
    if not data:
        return "<p style='color:#aaa'>No alerts to display.</p>"

    severity_colors = {"HIGH": "#ff4b4b", "MEDIUM": "#ffa500", "LOW": "#ffd700", "CRITICAL": "#ff0000"}
    rows = ""
    for row in data[:20]:
        sev = row.get("severity", "")
        sev_color = severity_colors.get(sev, "#aaa")
        sev_badge = f"<span style='background:{sev_color}; color:#000; padding:2px 8px; border-radius:10px; font-size:11px; font-weight:bold;'>{sev}</span>" if sev else "-"
        
        action = row.get("action_taken", "Logged")
        action_color = "#ff4b4b" if action == "Blocked" else ("#ffa500" if action == "Flagged" else "#a0a8c0")
        action_badge = f"<span style='color:{action_color}; font-weight:bold; font-size:12px;'>{action}</span>"
        
        rows += f"""
        <tr style='border-bottom:1px solid #2a2a3e;'>
            <td style='padding:8px 12px; color:#a0a8c0; font-size:12px;'>{row.get('timestamp','N/A')[:19]}</td>
            <td style='padding:8px 12px; color:#e06c75; font-weight:bold; font-family:monospace;'>{row.get('src_ip','?')}</td>
            <td style='padding:8px 12px; color:#61afef; font-family:monospace;'>{row.get('dst_ip','?')}</td>
            <td style='padding:8px 12px; color:#c678dd; font-weight:bold;'>{row.get('attack_type','?')}</td>
            <td style='padding:8px 12px;'>{sev_badge}</td>
            <td style='padding:8px 12px;'>{action_badge}</td>
        </tr>"""

    return f"<div style='overflow-x:auto; border-radius:12px; border:1px solid #333;'><table style='width:100%; border-collapse:collapse; background:#1e1e2e;'><thead><tr style='background:#12121f; color:#7d8ec0; font-size:13px;'><th style='padding:10px 12px; text-align:left;'>Timestamp</th><th style='padding:10px 12px; text-align:left;'>Source IP</th><th style='padding:10px 12px; text-align:left;'>Dest IP</th><th style='padding:10px 12px; text-align:left;'>Attack Type</th><th style='padding:10px 12px; text-align:left;'>Severity</th><th style='padding:10px 12px; text-align:left;'>Action Taken</th></tr></thead><tbody>{rows}</tbody></table></div>"

# =========================
# Main App
# =========================

st.markdown("""
<style>
    body { background-color: #0d0d1a; }
    .block-container { padding-top: 1rem; }
    h1 { color: #7d8ec0 !important; }
    div[data-testid="metric-container"] {
        background: #1e1e2e;
        border: 1px solid #2a2a3e;
        border-radius: 12px;
        padding: 12px 16px;
    }
</style>
""", unsafe_allow_html=True)

st.title("SOC Dashboard - Intrusion Detection System")
st.caption("Live network threat monitoring | Auto-refreshes every 3 seconds")

alerts = load_alerts()

if not alerts:
    st.warning("No alerts yet... Waiting for network traffic.")
else:
    # =========================
    # Metrics Row
    # =========================
    total = len(alerts)
    unique_ips = len(set(a.get("src_ip", "") for a in alerts))
    attack_types = len(set(a.get("attack_type", "") for a in alerts))
    high_sev = sum(1 for a in alerts if a.get("severity") == "HIGH")

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Alerts", total)
    col2.metric("Unique Attacker IPs", unique_ips)
    col3.metric("Attack Types Seen", attack_types)
    col4.metric("High Severity Threats", high_sev)

    st.markdown("---")

    # =========================
    # Charts (Pure HTML, zero dependencies)
    # =========================
    attack_counts = dict(Counter(a.get("attack_type", "UNKNOWN") for a in alerts).most_common(8))
    ip_counts = dict(Counter(a.get("src_ip", "?") for a in alerts).most_common(8))

    chart_col1, chart_col2 = st.columns(2)
    with chart_col1:
        st.markdown(make_bar_chart_html(attack_counts, "#e06c75", "Attack Type Distribution"), unsafe_allow_html=True)
    with chart_col2:
        st.markdown(make_bar_chart_html(ip_counts, "#61afef", "Top Attacker IPs"), unsafe_allow_html=True)

    st.markdown("---")

    # =========================
    # Live Alerts Table
    # =========================
    st.subheader("Live Alerts Feed")
    st.markdown(make_table_html(alerts), unsafe_allow_html=True)

# =========================
# Native Auto Refresh (every 3 seconds)
# =========================
time.sleep(3)
st.rerun()