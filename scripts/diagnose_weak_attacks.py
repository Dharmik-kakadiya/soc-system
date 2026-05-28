# -*- coding: utf-8 -*-
"""
Diagnostic: IDS score distribution for the 3 weak attacks
SlowHTTPTest, DDOS-HOIC, Infilteration
"""
import sys, os, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

import numpy as np
import pandas as pd
import joblib
import warnings
warnings.filterwarnings("ignore")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from ml.pipeline.preprocess import preprocess, ids_features

# Load IDS model only
IDS_MODEL_PATH = os.path.join(BASE_DIR, "ml", "models", "network_model.pkl")
ATTACK_MODEL_PATH = os.path.join(BASE_DIR, "ml", "models", "attack_model.pkl")
ENCODER_PATH = os.path.join(BASE_DIR, "ml", "preprocessors", "attack_label_encoder.pkl")

print("[*] Loading models...")
ids_model    = joblib.load(IDS_MODEL_PATH)
attack_model = joblib.load(ATTACK_MODEL_PATH)
label_encoder= joblib.load(ENCODER_PATH)
ids_model.verbose = 0
print("[*] Models loaded.\n")

# Weak attacks and their files
TARGETS = {
    "DoS attacks-SlowHTTPTest": ("02-16-2018.csv", "DoS"),
    "DDOS attack-HOIC":         ("02-21-2018.csv", "DDoS"),
    "Infilteration":            ("02-28-2018.csv", "Infiltration"),
}

from scipy.stats import mode

def run_attack_clf(X_raw):
    predictions = np.array([tree.predict(X_raw) for tree in attack_model.estimators_])
    attack_pred = int(mode(predictions, axis=0, keepdims=False).mode[0])
    return str(label_encoder.inverse_transform([attack_pred])[0])

print("="*65)
print("DIAGNOSTIC: IDS Score + Attack Classifier for 3 Weak Attacks")
print("="*65)

for raw_label, (fname, expected_class) in TARGETS.items():
    fpath = os.path.join(BASE_DIR, "data", fname)
    if not os.path.exists(fpath):
        print("\n[!] File not found: {}".format(fname))
        continue

    print("\n[{}]  =>  Expected: {}".format(raw_label, expected_class))

    enc = "utf-8"
    try:
        pd.read_csv(fpath, nrows=1, encoding="utf-8")
    except UnicodeDecodeError:
        enc = "latin-1"

    rows_collected = []
    for chunk in pd.read_csv(fpath, chunksize=50000, low_memory=False,
                              on_bad_lines="skip", encoding=enc):
        chunk.columns = chunk.columns.str.strip()
        label_col = next((c for c in chunk.columns if c.lower().strip() == "label"), None)
        if not label_col:
            break
        chunk[label_col] = chunk[label_col].astype(str).str.strip()
        rows = chunk[chunk[label_col] == raw_label]
        for _, row in rows.head(50 - len(rows_collected)).iterrows():
            rows_collected.append(row.to_dict())
        if len(rows_collected) >= 50:
            break

    print("  Collected {} samples. Analyzing...".format(len(rows_collected)))

    ids_scores = []
    attack_preds = []
    final_decisions = []

    for row_dict in rows_collected:
        clean = {}
        for k, v in row_dict.items():
            try:
                clean[str(k).strip().lower()] = float(v)
            except:
                clean[str(k).strip().lower()] = 0.0

        X_scaled, X_raw = preprocess(clean)
        proba = ids_model.predict_proba(X_scaled)[0]
        ids_score = proba[1]
        ids_scores.append(ids_score)

        # What does attack classifier say regardless
        atk_pred = run_attack_clf(X_raw)
        attack_preds.append(atk_pred)

        # Current decision (threshold 0.20)
        if ids_score < 0.20:
            final_decisions.append("BENIGN (IDS gated)")
        else:
            final_decisions.append(atk_pred)

    ids_scores = np.array(ids_scores)
    print("\n  -- IDS Score Distribution --")
    print("  Min    : {:.4f}".format(ids_scores.min()))
    print("  Max    : {:.4f}".format(ids_scores.max()))
    print("  Mean   : {:.4f}".format(ids_scores.mean()))
    print("  Median : {:.4f}".format(np.median(ids_scores)))

    below_020 = (ids_scores < 0.20).sum()
    below_015 = (ids_scores < 0.15).sum()
    below_010 = (ids_scores < 0.10).sum()
    print("\n  -- Samples blocked by IDS threshold --")
    print("  < 0.20 (current)  : {}/{} ({:.0f}%)".format(
        below_020, len(ids_scores), below_020/len(ids_scores)*100))
    print("  < 0.15            : {}/{} ({:.0f}%)".format(
        below_015, len(ids_scores), below_015/len(ids_scores)*100))
    print("  < 0.10            : {}/{} ({:.0f}%)".format(
        below_010, len(ids_scores), below_010/len(ids_scores)*100))

    from collections import Counter
    clf_counts = Counter(attack_preds)
    print("\n  -- Attack Classifier (ignoring IDS gate) --")
    for label, cnt in clf_counts.most_common():
        correct = "CORRECT" if label == expected_class else "WRONG"
        print("  {:20s} : {:3d}  {}".format(label, cnt, correct))

    final_counts = Counter(final_decisions)
    print("\n  -- Final Decision (with 0.20 threshold) --")
    for label, cnt in final_counts.most_common():
        print("  {:30s} : {:3d}".format(label, cnt))

print("\n" + "="*65)
print("DONE - use these numbers to tune the threshold in predict.py")
print("="*65 + "\n")
