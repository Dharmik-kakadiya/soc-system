# -*- coding: utf-8 -*-
"""
Quick check: What dst_port and flow_pkts_s do SlowHTTPTest samples have?
Also compare with Web-BruteForce and SSH-BruteForce.
"""
import sys, os, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

import pandas as pd
import numpy as np
import warnings
warnings.filterwarnings("ignore")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def show_stats(fpath, label_val, n=200):
    enc = "utf-8"
    try:
        pd.read_csv(fpath, nrows=1, encoding="utf-8")
    except UnicodeDecodeError:
        enc = "latin-1"

    rows = []
    for chunk in pd.read_csv(fpath, chunksize=50000, low_memory=False,
                              on_bad_lines="skip", encoding=enc):
        chunk.columns = chunk.columns.str.strip()
        lbl_col = next((c for c in chunk.columns if c.lower().strip() == "label"), None)
        if not lbl_col:
            continue
        chunk[lbl_col] = chunk[lbl_col].astype(str).str.strip()
        match = chunk[chunk[lbl_col] == label_val]
        rows.append(match.head(n - len(rows)))
        if sum(len(r) for r in rows) >= n:
            break

    if not rows:
        print(f"  No rows found for: {label_val}")
        return

    df = pd.concat(rows, ignore_index=True).head(n)
    df.columns = df.columns.str.strip()

    # Normalize column names
    col_map = {c.lower().strip(): c for c in df.columns}

    def get_col(name):
        return col_map.get(name, None)

    dst_col       = get_col("dst port")
    pkts_col      = get_col("flow pkts/s")
    fwd_pkts_col  = get_col("fwd pkts/s")
    ids_score_col = get_col("ids score")

    print(f"\n  [{label_val}]  ({len(df)} samples)")

    if dst_col:
        top_ports = df[dst_col].value_counts().head(5)
        print(f"  Top dst_ports: {dict(top_ports)}")
    if pkts_col:
        vals = pd.to_numeric(df[pkts_col], errors="coerce").dropna()
        print(f"  flow_pkts/s  : min={vals.min():.0f}  max={vals.max():.0f}  mean={vals.mean():.0f}  median={vals.median():.0f}")
    if fwd_pkts_col:
        vals = pd.to_numeric(df[fwd_pkts_col], errors="coerce").dropna()
        print(f"  fwd_pkts/s   : min={vals.min():.0f}  max={vals.max():.0f}  mean={vals.mean():.0f}")

CHECKS = [
    (os.path.join(BASE_DIR, "data", "02-16-2018.csv"), "DoS attacks-SlowHTTPTest"),
    (os.path.join(BASE_DIR, "data", "02-14-2018.csv"), "FTP-BruteForce"),
    (os.path.join(BASE_DIR, "data", "02-14-2018.csv"), "SSH-Bruteforce"),
    (os.path.join(BASE_DIR, "data", "02-22-2018.csv"), "Brute Force -Web"),
    (os.path.join(BASE_DIR, "data", "02-22-2018.csv"), "Brute Force -XSS"),
]

print("="*60)
print("PORT + PACKET RATE ANALYSIS")
print("="*60)

for fpath, label in CHECKS:
    if os.path.exists(fpath):
        show_stats(fpath, label, n=200)
    else:
        print(f"\n[!] File not found: {fpath}")

print("\n[DONE]")
