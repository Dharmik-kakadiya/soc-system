# -*- coding: utf-8 -*-
import sys, os, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

import pandas as pd
import numpy as np

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def load_samples(fpath, label, n=500):
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
        rows.append(match.head(n - sum(len(r) for r in rows)))
        if sum(len(r) for r in rows) >= n: break
            
    df = pd.concat(rows, ignore_index=True)
    
    # Exclude non-numeric columns except label
    numeric_df = df.select_dtypes(include=[np.number])
    return numeric_df

print("[*] Loading SlowHTTPTest samples...")
slow_df = load_samples(os.path.join(BASE_DIR, "data", "02-16-2018.csv"), "DoS attacks-SlowHTTPTest")

print("[*] Loading FTP-BruteForce samples...")
ftp_df = load_samples(os.path.join(BASE_DIR, "data", "02-14-2018.csv"), "FTP-BruteForce")

print("\n" + "="*80)
print(f"FEATURE COMPARISON: SlowHTTPTest ({len(slow_df)}) vs FTP-BruteForce ({len(ftp_df)})")
print("="*80)

print(f"{'Feature':<30} | {'SlowHTTPTest Mean':<20} | {'FTP-BruteForce Mean':<20} | {'Ratio':<10}")
print("-" * 80)

# Compare all numeric columns to find the ones with biggest difference
diffs = []
for col in slow_df.columns:
    if col not in ftp_df.columns: continue
    
    slow_mean = slow_df[col].mean()
    ftp_mean = ftp_df[col].mean()
    
    if pd.isna(slow_mean) or pd.isna(ftp_mean): continue
    if slow_mean == 0 and ftp_mean == 0: continue
    
    # Calculate ratio (max/min)
    max_val = max(abs(slow_mean), abs(ftp_mean))
    min_val = min(abs(slow_mean), abs(ftp_mean))
    
    if min_val > 0:
        ratio = max_val / min_val
        diffs.append((col, slow_mean, ftp_mean, ratio))

# Sort by ratio descending
diffs.sort(key=lambda x: x[3], reverse=True)

for col, s_mean, f_mean, ratio in diffs[:20]:
    print(f"{col[:28]:<30} | {s_mean:<20.4f} | {f_mean:<20.4f} | {ratio:<10.2f}x")

print("\n" + "="*80)
print("Looking at specific flow features (min/max ranges)")
print("="*80)

target_cols = ['flow duration', 'tot fwd pkts', 'fwd pkts/s', 'bwd pkts/s', 'fwd header len']
for col in target_cols:
    if col in slow_df.columns and col in ftp_df.columns:
        s_min, s_max = slow_df[col].min(), slow_df[col].max()
        f_min, f_max = ftp_df[col].min(), ftp_df[col].max()
        print(f"\n{col.upper()}:")
        print(f"  SlowHTTP: min={s_min:<10.2f} max={s_max:<10.2f}")
        print(f"  FTP-Brute: min={f_min:<10.2f} max={f_max:<10.2f}")

print("\n[DONE]")
