# -*- coding: utf-8 -*-
"""
SOC SYSTEM - FULL BENCHMARK TEST (All 15 Attack Types)
Dataset: CICIDS-2018 (CSE-CIC-IDS2018)

Yeh script saare 15 attack types ka real CSV data se test karta hai.
Output: Console report + HTML report (benchmark_report.html)
"""
import sys
import os
import io

# Force UTF-8 stdout on Windows to avoid codec errors
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

import time
import glob
import warnings
import numpy as np
import pandas as pd
from collections import defaultdict
from datetime import datetime

warnings.filterwarnings("ignore")

# Fix imports
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from ml.pipeline.predict import predict

# =============================================================================
# CICIDS-2018 - 15 Raw Attack Labels -> Model Class Mapping
# Model predicts: Bot, BruteForce, DDoS, DoS, Infiltration, WebAttack, BENIGN
# =============================================================================
ATTACK_MAP = {
    # DoS group (4 attacks)
    "DoS attacks-Hulk":         "DoS",
    "DoS attacks-GoldenEye":    "DoS",
    "DoS attacks-Slowloris":    "DoS",
    "DoS attacks-SlowHTTPTest": "DoS",
    # DDoS group (3 attacks)
    "DDOS attack-HOIC":         "DDoS",
    "DDOS attack-LOIC-UDP":     "DDoS",
    "DDoS attacks-LOIC-HTTP":   "DDoS",
    # BruteForce group (4 attacks)
    "Brute Force -Web":         "BruteForce",
    "Brute Force -XSS":         "BruteForce",
    "SSH-Bruteforce":           "BruteForce",
    "FTP-BruteForce":           "BruteForce",
    # Web / Injection (1 attack)
    "SQL Injection":            "WebAttack",
    # Infiltration (1 attack)
    "Infilteration":            "Infiltration",
    # Bot (1 attack)
    "Bot":                      "Bot",
    # Additional alias
    "Infiltration":             "Infiltration",
}

# Best-effort: which files likely contain which labels
FILE_ATTACK_HINTS = {
    "02-14-2018.csv": ["Bot", "FTP-BruteForce", "SSH-Bruteforce"],
    "02-15-2018.csv": ["DoS attacks-Hulk", "DoS attacks-GoldenEye",
                       "DoS attacks-Slowloris", "DoS attacks-SlowHTTPTest"],
    "02-16-2018.csv": ["DoS attacks-Hulk", "DoS attacks-GoldenEye"],
    "02-20-2018.csv": ["DDOS attack-HOIC", "DDOS attack-LOIC-UDP",
                       "DDoS attacks-LOIC-HTTP"],
    "02-21-2018.csv": ["DDOS attack-HOIC", "DDOS attack-LOIC-UDP"],
    "02-22-2018.csv": ["Brute Force -Web", "Brute Force -XSS", "SQL Injection"],
    "02-23-2018.csv": ["Brute Force -Web", "Brute Force -XSS", "SQL Injection"],
    "02-28-2018.csv": ["Infilteration"],
    "03-01-2018.csv": ["Infilteration"],
    "03-02-2018.csv": ["Bot"],
}

SAMPLES_PER_ATTACK = 200

# =============================================================================
print("\n" + "="*70)
print("  SOC SYSTEM BENCHMARK - ALL 15 ATTACK TYPES")
print("  Started: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
print("="*70)

DATA_DIR = os.path.join(BASE_DIR, "data")
csv_files = sorted(glob.glob(os.path.join(DATA_DIR, "*.csv")))

if not csv_files:
    print("[!] No CSV files found in data/ - aborting.")
    sys.exit(1)

print("\n[*] Found {} CSV file(s) in data/".format(len(csv_files)))
print("[*] Scanning CSV files for attack samples...")

# =============================================================================
# Phase 2 - Collect samples
# =============================================================================
samples = defaultdict(list)

for csv_path in csv_files:
    fname = os.path.basename(csv_path)
    hints = FILE_ATTACK_HINTS.get(fname, [])

    needed = [h for h in hints if len(samples[h]) < SAMPLES_PER_ATTACK]
    if hints and not needed:
        print("    {}: already have enough samples - skipping".format(fname))
        continue

    print("    Reading {} ...".format(fname), end=" ", flush=True)
    t0 = time.time()

    try:
        # Detect encoding
        enc = "utf-8"
        try:
            pd.read_csv(csv_path, nrows=1, encoding="utf-8")
        except UnicodeDecodeError:
            enc = "latin-1"

        chunk_size = 50_000
        found_in_file = set()

        for chunk in pd.read_csv(
            csv_path,
            chunksize=chunk_size,
            low_memory=False,
            on_bad_lines="skip",
            encoding=enc,
        ):
            chunk.columns = chunk.columns.str.strip()

            # Find label column
            label_col = None
            for col in chunk.columns:
                if col.strip().lower() == "label":
                    label_col = col
                    break
            if label_col is None:
                break

            chunk[label_col] = chunk[label_col].astype(str).str.strip()

            for raw_label in ATTACK_MAP:
                if len(samples[raw_label]) >= SAMPLES_PER_ATTACK:
                    continue
                mask = chunk[label_col] == raw_label
                rows = chunk[mask]
                if len(rows) > 0:
                    found_in_file.add(raw_label)
                    need = SAMPLES_PER_ATTACK - len(samples[raw_label])
                    taken = rows.head(need)
                    for _, row in taken.iterrows():
                        samples[raw_label].append(row.to_dict())

            # Stop early if all labels collected
            if all(len(samples[r]) >= SAMPLES_PER_ATTACK for r in ATTACK_MAP):
                break

        elapsed = time.time() - t0
        found_labels = list(found_in_file)
        print("Done {:.1f}s | Labels found: {}".format(
            elapsed, found_labels if found_labels else "none"))

    except Exception as e:
        print("ERROR: {}".format(e))
        continue

# =============================================================================
# Phase 3 - Run predictions
# =============================================================================
print("\n" + "="*70)
print("  RUNNING PREDICTIONS")
print("="*70)

raw_labels_found   = [r for r in ATTACK_MAP if samples[r]]
raw_labels_missing = [r for r in ATTACK_MAP if not samples[r]]

if raw_labels_missing:
    print("\n[!] No samples found for: {}".format(raw_labels_missing))

results = {}

for raw_label in raw_labels_found:
    model_class = ATTACK_MAP[raw_label]
    rows = samples[raw_label]
    correct = 0
    wrong = 0
    pred_counts = defaultdict(int)
    latencies = []

    print("\n  [{}]  =>  expected: {}".format(raw_label, model_class))
    print("  Testing {} samples ...".format(len(rows)), end=" ", flush=True)

    for row_dict in rows:
        clean = {}
        for k, v in row_dict.items():
            try:
                clean[str(k).strip().lower()] = float(v)
            except (ValueError, TypeError):
                clean[str(k).strip().lower()] = 0.0

        t0 = time.time()
        try:
            res = predict(clean)
            latencies.append((time.time() - t0) * 1000)
            predicted = res.get("attack_type", "BENIGN")
            pred_counts[predicted] += 1
            if predicted == model_class:
                correct += 1
            else:
                wrong += 1
        except Exception as e:
            wrong += 1
            pred_counts["ERROR"] += 1

    total = correct + wrong
    acc = (correct / total * 100) if total > 0 else 0
    avg_lat = float(np.mean(latencies)) if latencies else 0.0

    results[raw_label] = {
        "model_class":    model_class,
        "total":          total,
        "correct":        correct,
        "wrong":          wrong,
        "accuracy":       acc,
        "predictions":    dict(pred_counts),
        "avg_latency_ms": avg_lat,
    }

    status = "PASS" if acc >= 70 else ("FAIR" if acc >= 40 else "FAIL")
    top_pred = max(pred_counts, key=pred_counts.get, default="N/A")
    print("{} | Acc: {:.1f}% | Lat: {:.1f}ms | Top: {} ({}/{})".format(
        status, acc, avg_lat, top_pred, pred_counts.get(top_pred, 0), total))

# =============================================================================
# Phase 4 - Aggregate by model class
# =============================================================================
class_stats = defaultdict(lambda: {"correct": 0, "total": 0})
for raw_label, r in results.items():
    mc = r["model_class"]
    class_stats[mc]["correct"] += r["correct"]
    class_stats[mc]["total"]   += r["total"]

# =============================================================================
# Phase 5 - Console Summary
# =============================================================================
print("\n\n" + "="*70)
print("  FINAL BENCHMARK REPORT")
print("="*70)
print("\n  {:<32} {:<15} {:>6} {:>8} {:>10} {:>10}".format(
    "Attack Type (Raw)", "Model Class", "Total", "Correct", "Accuracy", "Avg Lat"))
print("  " + "-"*75)

for raw_label in raw_labels_found:
    r = results[raw_label]
    print("  {:<32} {:<15} {:>6} {:>8} {:>9.1f}%  {:>7.1f}ms".format(
        raw_label, r["model_class"], r["total"],
        r["correct"], r["accuracy"], r["avg_latency_ms"]))

for ml in raw_labels_missing:
    print("  {:<32} {:<15} {:>6}".format(ml, ATTACK_MAP[ml], "NO DATA"))

total_all   = sum(r["total"]   for r in results.values())
correct_all = sum(r["correct"] for r in results.values())
overall_acc = (correct_all / total_all * 100) if total_all > 0 else 0

print("\n  AGGREGATED BY MODEL CLASS:")
print("  " + "-"*50)
print("  {:<22} {:>8} {:>8} {:>10}".format("Model Class", "Total", "Correct", "Accuracy"))
print("  " + "-"*50)
for mc, s in sorted(class_stats.items()):
    acc = (s["correct"] / s["total"] * 100) if s["total"] > 0 else 0
    print("  {:<22} {:>8} {:>8} {:>9.1f}%".format(mc, s["total"], s["correct"], acc))

print("\n  " + "="*70)
print("  OVERALL ACCURACY: {}/{} = {:.2f}%".format(correct_all, total_all, overall_acc))
print("  " + "="*70)

# =============================================================================
# Phase 6 - Generate HTML Report
# =============================================================================
REPORT_PATH = os.path.join(BASE_DIR, "scripts", "benchmark_report.html")

def get_color(acc):
    if acc >= 80:   return "#00e676"
    elif acc >= 60: return "#ffeb3b"
    elif acc >= 40: return "#ff9800"
    else:           return "#f44336"

def get_badge(acc):
    if acc >= 80:   return "PASS", "#00e676"
    elif acc >= 60: return "FAIR", "#ffeb3b"
    elif acc >= 40: return "WEAK", "#ff9800"
    else:           return "FAIL", "#f44336"

rows_html = ""
for raw_label in raw_labels_found:
    r = results[raw_label]
    acc = r["accuracy"]
    color = get_color(acc)
    badge_text, badge_bg = get_badge(acc)
    bar_w = int(acc)
    pred_str = ", ".join(
        "{}: {}".format(k, v)
        for k, v in sorted(r["predictions"].items(), key=lambda x: -x[1])
    )
    rows_html += """
        <tr>
            <td class="attack-name">{raw_label}</td>
            <td><span class="class-badge">{model_class}</span></td>
            <td>{total}</td>
            <td>{correct}</td>
            <td>
                <div class="bar-container">
                    <div class="bar" style="width:{bar_w}%; background:{color};"></div>
                    <span class="bar-label">{acc:.1f}%</span>
                </div>
            </td>
            <td><span class="badge" style="background:{badge_bg}; color:#000;">{badge_text}</span></td>
            <td class="pred-cell">{pred_str}</td>
            <td>{lat:.1f}ms</td>
        </tr>
    """.format(
        raw_label=raw_label, model_class=r["model_class"],
        total=r["total"], correct=r["correct"], bar_w=bar_w,
        color=color, acc=acc, badge_bg=badge_bg, badge_text=badge_text,
        pred_str=pred_str, lat=r["avg_latency_ms"]
    )

for ml_label in raw_labels_missing:
    rows_html += """
        <tr style="opacity:0.5;">
            <td class="attack-name">{}</td>
            <td><span class="class-badge">{}</span></td>
            <td colspan="6" style="text-align:center; color:#888;">No samples found in data/</td>
        </tr>
    """.format(ml_label, ATTACK_MAP[ml_label])

class_cards_html = ""
for mc, s in sorted(class_stats.items()):
    acc = (s["correct"] / s["total"] * 100) if s["total"] > 0 else 0
    color = get_color(acc)
    badge_text, badge_bg = get_badge(acc)
    circumference = 2 * 3.14159 * 34
    dash = circumference * acc / 100
    offset = circumference * 0.25
    class_cards_html += """
        <div class="class-card">
            <div class="class-name">{mc}</div>
            <div class="class-acc" style="color:{color};">{acc:.1f}%</div>
            <div class="class-detail">{correct}/{total} correct</div>
            <div class="progress-ring">
                <svg viewBox="0 0 80 80">
                    <circle cx="40" cy="40" r="34" fill="none" stroke="#222" stroke-width="8"/>
                    <circle cx="40" cy="40" r="34" fill="none" stroke="{color}" stroke-width="8"
                        stroke-dasharray="{dash:.1f} {circ:.1f}"
                        stroke-dashoffset="{offset:.1f}"
                        stroke-linecap="round"/>
                </svg>
            </div>
        </div>
    """.format(mc=mc, color=color, acc=acc,
               correct=s["correct"], total=s["total"],
               dash=dash, circ=circumference, offset=offset)

html = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SOC System Benchmark Report</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;900&family=JetBrains+Mono:wght@400;600&display=swap');
  :root {{
    --bg: #0a0a0f; --surface: #12121a; --surface2: #1a1a26;
    --border: #2a2a40; --accent: #6c63ff; --accent2: #00e5ff;
    --text: #e0e0f0; --text-muted: #888899;
    --green: #00e676; --yellow: #ffeb3b; --orange: #ff9800; --red: #f44336;
  }}
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ font-family:'Inter',sans-serif; background:var(--bg); color:var(--text); min-height:100vh; padding:2rem; }}

  .header {{ text-align:center; margin-bottom:3rem; position:relative; }}
  .header::before {{ content:''; position:absolute; inset:-2rem;
    background:radial-gradient(ellipse at 50% 0%, rgba(108,99,255,0.18) 0%, transparent 70%);
    pointer-events:none; }}
  .header h1 {{ font-size:2.4rem; font-weight:900;
    background:linear-gradient(135deg,#6c63ff,#00e5ff,#00e676);
    -webkit-background-clip:text; -webkit-text-fill-color:transparent; letter-spacing:-0.5px; }}
  .header .subtitle {{ color:var(--text-muted); margin-top:0.5rem; font-size:0.95rem;
    font-family:'JetBrains Mono',monospace; }}

  .summary-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr));
    gap:1rem; margin-bottom:2.5rem; }}
  .summary-card {{ background:var(--surface); border:1px solid var(--border); border-radius:16px;
    padding:1.4rem 1.2rem; text-align:center; position:relative; overflow:hidden;
    transition:transform 0.2s, border-color 0.2s; }}
  .summary-card:hover {{ transform:translateY(-3px); border-color:var(--accent); }}
  .summary-card::after {{ content:''; position:absolute; bottom:0; left:0; right:0; height:3px;
    background:linear-gradient(90deg,var(--accent),var(--accent2)); }}
  .summary-card .val {{ font-size:2.2rem; font-weight:700;
    background:linear-gradient(135deg,#6c63ff,#00e5ff);
    -webkit-background-clip:text; -webkit-text-fill-color:transparent; }}
  .summary-card .lbl {{ color:var(--text-muted); font-size:0.8rem; margin-top:0.3rem;
    text-transform:uppercase; letter-spacing:1px; }}

  .section-title {{ font-size:1.1rem; font-weight:600; color:var(--accent2);
    margin-bottom:1rem; text-transform:uppercase; letter-spacing:2px; }}
  .class-cards-grid {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(150px,1fr));
    gap:1rem; margin-bottom:3rem; }}
  .class-card {{ background:var(--surface); border:1px solid var(--border); border-radius:14px;
    padding:1.2rem; text-align:center; transition:transform 0.2s; }}
  .class-card:hover {{ transform:translateY(-4px); border-color:var(--accent); }}
  .class-name {{ font-size:0.85rem; font-weight:600; color:var(--accent2); margin-bottom:0.4rem;
    text-transform:uppercase; letter-spacing:1px; }}
  .class-acc {{ font-size:1.6rem; font-weight:700; line-height:1; }}
  .class-detail {{ font-size:0.75rem; color:var(--text-muted); margin-top:0.3rem; }}
  .progress-ring {{ width:56px; height:56px; margin:0.8rem auto 0; }}
  .progress-ring svg {{ transform:rotate(-90deg); }}

  .table-container {{ background:var(--surface); border:1px solid var(--border);
    border-radius:16px; overflow:hidden; margin-bottom:2rem; }}
  table {{ width:100%; border-collapse:collapse; }}
  thead tr {{ background:linear-gradient(90deg,rgba(108,99,255,0.15),rgba(0,229,255,0.08));
    border-bottom:1px solid var(--border); }}
  th {{ padding:1rem 1.2rem; text-align:left; font-size:0.75rem; font-weight:600;
    text-transform:uppercase; letter-spacing:1.5px; color:var(--text-muted); }}
  td {{ padding:0.85rem 1.2rem; font-size:0.88rem;
    border-bottom:1px solid rgba(255,255,255,0.04); vertical-align:middle; }}
  tr:last-child td {{ border-bottom:none; }}
  tr:hover td {{ background:rgba(108,99,255,0.05); }}
  .attack-name {{ font-family:'JetBrains Mono',monospace; font-size:0.82rem; color:var(--accent2); }}
  .class-badge {{ background:rgba(108,99,255,0.15); border:1px solid rgba(108,99,255,0.35);
    color:#a09bff; border-radius:6px; padding:0.2rem 0.6rem;
    font-size:0.75rem; font-weight:600; white-space:nowrap; }}
  .badge {{ border-radius:6px; padding:0.2rem 0.7rem; font-size:0.72rem;
    font-weight:700; letter-spacing:1px; }}
  .bar-container {{ position:relative; background:#1e1e2e; border-radius:6px;
    height:22px; min-width:120px; overflow:hidden; }}
  .bar {{ height:100%; border-radius:6px; opacity:0.85; }}
  .bar-label {{ position:absolute; right:8px; top:50%; transform:translateY(-50%);
    font-size:0.75rem; font-weight:600; color:#fff; text-shadow:0 1px 3px rgba(0,0,0,0.8); }}
  .pred-cell {{ font-family:'JetBrains Mono',monospace; font-size:0.72rem;
    color:var(--text-muted); max-width:200px; word-break:break-all; }}
  .footer {{ text-align:center; color:var(--text-muted); font-size:0.8rem;
    margin-top:3rem; padding-top:1.5rem; border-top:1px solid var(--border); }}
  .footer strong {{ color:var(--accent); }}
</style>
</head>
<body>
<div class="header">
  <h1>SOC SYSTEM - BENCHMARK REPORT</h1>
  <p class="subtitle">Generated: {ts} &nbsp;|&nbsp; Dataset: CICIDS-2018 &nbsp;|&nbsp; Samples/Attack: {spa}</p>
</div>

<div class="summary-grid">
  <div class="summary-card"><div class="val">{n_found}</div><div class="lbl">Attack Types Tested</div></div>
  <div class="summary-card"><div class="val">{total_all:,}</div><div class="lbl">Total Samples</div></div>
  <div class="summary-card"><div class="val">{correct_all:,}</div><div class="lbl">Correct Predictions</div></div>
  <div class="summary-card"><div class="val">{overall_acc:.1f}%</div><div class="lbl">Overall Accuracy</div></div>
  <div class="summary-card"><div class="val">{n_classes}</div><div class="lbl">Model Classes</div></div>
  <div class="summary-card"><div class="val">{n_miss}</div><div class="lbl">Missing Labels</div></div>
</div>

<p class="section-title">Accuracy by Model Class</p>
<div class="class-cards-grid">
{class_cards_html}
</div>

<p class="section-title">Detailed Attack-Level Results</p>
<div class="table-container">
  <table>
    <thead>
      <tr>
        <th>Raw Attack Label</th>
        <th>Model Class</th>
        <th>Samples</th>
        <th>Correct</th>
        <th>Accuracy</th>
        <th>Status</th>
        <th>Prediction Breakdown</th>
        <th>Avg Latency</th>
      </tr>
    </thead>
    <tbody>
      {rows_html}
    </tbody>
  </table>
</div>

<div class="footer">
  Generated by <strong>SOC System Benchmark</strong> &nbsp;|&nbsp;
  Model: RandomForest (2-stage: IDS + Attack Classifier) &nbsp;|&nbsp;
  Dataset: CSE-CIC-IDS2018
</div>
</body>
</html>""".format(
    ts=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    spa=SAMPLES_PER_ATTACK,
    n_found=len(raw_labels_found),
    total_all=total_all, correct_all=correct_all,
    overall_acc=overall_acc,
    n_classes=len(class_stats),
    n_miss=len(raw_labels_missing),
    class_cards_html=class_cards_html,
    rows_html=rows_html,
)

with open(REPORT_PATH, "w", encoding="utf-8") as f:
    f.write(html)

print("\n[OK] HTML report saved: {}".format(REPORT_PATH))
print("[OK] Benchmark complete at {}".format(datetime.now().strftime("%H:%M:%S")))
print("="*70 + "\n")
