# -*- coding: utf-8 -*-
import sys, os
sys.stdout = open(sys.stdout.fileno(), mode='w', encoding='utf8', buffering=1)

import pandas as pd
import numpy as np

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from ml.pipeline.predict import predict

def test_benign(fpath, n=500):
    enc = "utf-8"
    try:
        pd.read_csv(fpath, nrows=1, encoding="utf-8")
    except UnicodeDecodeError:
        enc = "latin-1"
        
    rows_collected = []
    # Change Benign label matching: CICIDS-2018 usually has "Benign" with Capital 'B'
    for chunk in pd.read_csv(fpath, chunksize=50000, low_memory=False, on_bad_lines="skip", encoding=enc):
        chunk.columns = chunk.columns.str.strip()
        lbl_col = next((c for c in chunk.columns if "label" in c.lower()), None)
        if not lbl_col: continue
        
        chunk[lbl_col] = chunk[lbl_col].astype(str).str.strip().str.lower()
        match = chunk[chunk[lbl_col] == "benign"]
        for _, row in match.head(n - len(rows_collected)).iterrows():
            rows_collected.append(row.to_dict())
        if len(rows_collected) >= n: break
            
    print(f"  Collected {len(rows_collected)} BENIGN samples from {os.path.basename(fpath)}")
    
    total = len(rows_collected)
    if total == 0: return 0.0
    
    false_positives = 0
    fp_labels = {}
    
    for row in rows_collected:
        clean = {}
        for k, v in row.items():
            try:
                clean[str(k).strip().lower()] = float(v)
            except:
                clean[str(k).strip().lower()] = 0.0
                
        res = predict(clean)
        if res["attack"]:
            false_positives += 1
            l = res["attack_type"]
            fp_labels[l] = fp_labels.get(l, 0) + 1
            
    fp_rate = (false_positives / total) * 100
    print(f"  False Positives: {false_positives}/{total} ({fp_rate:.2f}%)")
    if false_positives > 0:
        print("  Misclassified as:")
        for k, v in sorted(fp_labels.items(), key=lambda x: -x[1]):
            print(f"    - {k}: {v}")
            
    return fp_rate

print("==================================================")
print("TESTING NORMAL (BENIGN) TRAFFIC FOR FALSE POSITIVES")
print("==================================================")

files_to_check = [
    "02-14-2018.csv",
    "02-15-2018.csv",
    "02-16-2018.csv",
    "02-21-2018.csv", 
    "02-23-2018.csv"
]

total_fp = []
for f in files_to_check:
    fpath = os.path.join(BASE_DIR, "data", f)
    if os.path.exists(fpath):
        rate = test_benign(fpath, n=1000)
        total_fp.append(rate)

if total_fp:
    print(f"\nAVERAGE FALSE POSITIVE RATE: {np.mean(total_fp):.2f}%")
print("==================================================")
