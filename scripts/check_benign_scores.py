# -*- coding: utf-8 -*-
import sys, os
sys.stdout = open(sys.stdout.fileno(), mode='w', encoding='utf8', buffering=1)

import pandas as pd
import numpy as np
import joblib
import warnings

# Suppress sklearn version warnings
warnings.filterwarnings("ignore")
try:
    from sklearn.exceptions import InconsistentVersionWarning
    warnings.simplefilter("ignore", InconsistentVersionWarning)
except ImportError:
    pass


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)
from ml.pipeline.preprocess import preprocess

ids_model = joblib.load(os.path.join(BASE_DIR, "ml", "models", "network_model.pkl"))
ids_model.verbose = 0

def get_scores(fpath, n=500):
    enc = "utf-8"
    try:
        pd.read_csv(fpath, nrows=1, encoding="utf-8")
    except UnicodeDecodeError:
        enc = "latin-1"
        
    rows_collected = []
    for chunk in pd.read_csv(fpath, chunksize=50000, low_memory=False, on_bad_lines="skip", encoding=enc):
        chunk.columns = chunk.columns.str.strip()
        lbl_col = next((c for c in chunk.columns if "label" in c.lower()), None)
        if not lbl_col: continue
        
        chunk[lbl_col] = chunk[lbl_col].astype(str).str.strip().str.lower()
        match = chunk[chunk[lbl_col] == "benign"]
        for _, row in match.head(n - len(rows_collected)).iterrows():
            rows_collected.append(row.to_dict())
        if len(rows_collected) >= n: break
            
    if not rows_collected: return []
    
    scores = []
    for row in rows_collected:
        clean = {}
        for k, v in row.items():
            try:
                clean[str(k).strip().lower()] = float(v)
            except:
                clean[str(k).strip().lower()] = 0.0
                
        X_scaled, _ = preprocess(clean)
        proba = ids_model.predict_proba(X_scaled)[0]
        scores.append(proba[1])
        
    return scores

files = ["02-14-2018.csv", "02-15-2018.csv", "02-16-2018.csv"]
for f in files:
    fpath = os.path.join(BASE_DIR, "data", f)
    scores = get_scores(fpath, n=1000)
    if scores:
        print(f"\n{f}:")
        print(f"  Min: {np.min(scores):.4f}")
        print(f"  Max: {np.max(scores):.4f}")
        print(f"  Mean: {np.mean(scores):.4f}")
        print(f"  Median: {np.median(scores):.4f}")
        print(f"  90th percentile: {np.percentile(scores, 90):.4f}")
        print(f"  % scoring > 0.20: {sum(1 for s in scores if s >= 0.20)/len(scores)*100:.1f}%")
        print(f"  % scoring > 0.50: {sum(1 for s in scores if s >= 0.50)/len(scores)*100:.1f}%")
