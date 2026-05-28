# -*- coding: utf-8 -*-
import sys, os
sys.stdout = open(sys.stdout.fileno(), mode='w', encoding='utf8', buffering=1)

import pandas as pd
import numpy as np

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def load_samples(fpath, label, n=2000):
    enc = "utf-8"
    try:
        pd.read_csv(fpath, nrows=1, encoding="utf-8")
    except UnicodeDecodeError:
        enc = "latin-1"
        
    rows = []
    for chunk in pd.read_csv(fpath, chunksize=50000, low_memory=False, on_bad_lines="skip", encoding=enc):
        chunk.columns = chunk.columns.str.strip().str.lower()
        lbl_col = next((c for c in chunk.columns if "label" in c), None)
        if not lbl_col: continue
        
        chunk[lbl_col] = chunk[lbl_col].astype(str).str.strip()
        match = chunk[chunk[lbl_col] == label]
        rows.append(match)
        if sum(len(r) for r in rows) >= n: break
            
    df = pd.concat(rows, ignore_index=True).head(n)
    return df.select_dtypes(include=[np.number])

print("[*] Loading SlowHTTPTest samples...")
slow_df = load_samples(os.path.join(BASE_DIR, "data", "02-16-2018.csv"), "DoS attacks-SlowHTTPTest")

print("[*] Loading FTP-BruteForce samples...")
ftp_df = load_samples(os.path.join(BASE_DIR, "data", "02-14-2018.csv"), "FTP-BruteForce")

print("\n" + "="*80)
print("ZERO OVERLAP FEATURES")
print("="*80)

found = False
for col in slow_df.columns:
    if col not in ftp_df.columns: continue
    
    s_min, s_max = slow_df[col].min(), slow_df[col].max()
    f_min, f_max = ftp_df[col].min(), ftp_df[col].max()
    
    # Check if there is absolutely zero overlap
    if s_max < f_min or f_max < s_min:
        print(f"\n{col.upper()}:")
        print(f"  SlowHTTPTest  : [{s_min:.2f}, {s_max:.2f}]")
        print(f"  FTP-BruteForce: [{f_min:.2f}, {f_max:.2f}]")
        found = True

if not found:
    print("\n[!] No feature has zero overlap! They are practically identical in ranges.")

    print("\n" + "="*80)
    print("LEAST OVERLAPPING FEATURES (by difference in means)")
    print("="*80)
    diffs = []
    for col in slow_df.columns:
        if col not in ftp_df.columns: continue
        s_mean, f_mean = slow_df[col].mean(), ftp_df[col].mean()
        if pd.isna(s_mean) or pd.isna(f_mean): continue
        if s_mean == 0 and f_mean == 0: continue
        
        max_val = max(abs(s_mean), abs(f_mean))
        min_val = min(abs(s_mean), abs(f_mean))
        if min_val > 0:
            diffs.append((col, s_mean, f_mean, max_val/min_val))
            
    diffs.sort(key=lambda x: x[3], reverse=True)
    for col, s_mean, f_mean, ratio in diffs[:10]:
        print(f"{col:<30} | Slow: {s_mean:<15.2f} | FTP: {f_mean:<15.2f} | Ratio: {ratio:.2f}x")

print("\n[DONE]")
