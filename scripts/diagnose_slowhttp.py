# -*- coding: utf-8 -*-
"""
Deep Diagnostic: SlowHTTPTest Attack Classifier Confusion
Root cause: IDS score=0.99 (good), but attack_clf says BruteForce instead of DoS

This script:
1. Loads 100 SlowHTTPTest samples
2. Checks what attack_model predicts (per-tree vote distribution)
3. Compares SlowHTTPTest vs normal DoS features to find key differences
4. Identifies the top features causing BruteForce misclassification
"""
import sys, os, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

import numpy as np
import pandas as pd
import joblib
import warnings
from scipy.stats import mode
from collections import Counter
warnings.filterwarnings("ignore")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from ml.pipeline.preprocess import preprocess, ids_features, attack_features

ATTACK_MODEL_PATH = os.path.join(BASE_DIR, "ml", "models", "attack_model.pkl")
ENCODER_PATH      = os.path.join(BASE_DIR, "ml", "preprocessors", "attack_label_encoder.pkl")
FEATURES_PATH     = os.path.join(BASE_DIR, "ml", "preprocessors", "features.pkl")

print("[*] Loading attack model...")
attack_model  = joblib.load(ATTACK_MODEL_PATH)
label_encoder = joblib.load(ENCODER_PATH)
print(f"[*] Attack model loaded. Classes: {list(label_encoder.classes_)}\n")

# Load attack feature names
attack_features_raw = joblib.load(FEATURES_PATH)
atk_feat_names = [f for f in attack_features_raw if f.lower() != "timestamp"]

DATA_FILE = os.path.join(BASE_DIR, "data", "02-16-2018.csv")
SAMPLES_NEEDED = 100

# ──────────────────────────────────────────────
# 1. Collect SlowHTTPTest samples
# ──────────────────────────────────────────────
print("[*] Scanning 02-16-2018.csv for DoS attacks-SlowHTTPTest rows...")

rows_collected = []
enc = "utf-8"
try:
    pd.read_csv(DATA_FILE, nrows=1, encoding="utf-8")
except UnicodeDecodeError:
    enc = "latin-1"

for chunk in pd.read_csv(DATA_FILE, chunksize=50000, low_memory=False,
                          on_bad_lines="skip", encoding=enc):
    chunk.columns = chunk.columns.str.strip()
    lbl_col = next((c for c in chunk.columns if c.lower().strip() == "label"), None)
    if not lbl_col:
        continue
    chunk[lbl_col] = chunk[lbl_col].astype(str).str.strip()
    target_rows = chunk[chunk[lbl_col] == "DoS attacks-SlowHTTPTest"]
    for _, row in target_rows.head(SAMPLES_NEEDED - len(rows_collected)).iterrows():
        rows_collected.append(row.to_dict())
    if len(rows_collected) >= SAMPLES_NEEDED:
        break

print(f"[*] Collected {len(rows_collected)} SlowHTTPTest samples.\n")

# ──────────────────────────────────────────────
# 2. Run attack classifier on each sample
# ──────────────────────────────────────────────
print("=" * 65)
print("ATTACK CLASSIFIER PREDICTION BREAKDOWN")
print("=" * 65)

all_labels = []
all_confidences = []
tree_vote_distributions = []
all_X_attack = []

for i, row_dict in enumerate(rows_collected):
    clean = {}
    for k, v in row_dict.items():
        try:
            clean[str(k).strip().lower()] = float(v)
        except:
            clean[str(k).strip().lower()] = 0.0

    _, X_raw = preprocess(clean)
    all_X_attack.append(X_raw)

    # Tree-level vote distribution
    tree_preds = np.array([tree.predict(X_raw) for tree in attack_model.estimators_])
    tree_preds_flat = tree_preds.flatten()

    # Count votes per class — cast keys to int to avoid float64 dtype error
    vote_counter = Counter(int(x) for x in tree_preds_flat)
    total_trees  = len(attack_model.estimators_)

    # Majority label
    winner_enc = int(mode(tree_preds, axis=0, keepdims=False).mode[0])
    winner_lbl = str(label_encoder.inverse_transform([winner_enc])[0])
    conf = vote_counter[winner_enc] / total_trees

    all_labels.append(winner_lbl)
    all_confidences.append(conf)
    tree_vote_distributions.append({
        str(label_encoder.inverse_transform([int(k)])[0]): v / total_trees
        for k, v in vote_counter.items()
    })

# Summary
label_counts = Counter(all_labels)
print("\n  Label Distribution (100 SlowHTTPTest samples):")
for lbl, cnt in label_counts.most_common():
    correct = "<-- CORRECT" if lbl == "DoS" else "<-- WRONG"
    print(f"    {lbl:20s}: {cnt:3d}  {correct}")

dos_conf   = [c for l, c in zip(all_labels, all_confidences) if l == "DoS"]
brute_conf = [c for l, c in zip(all_labels, all_confidences) if l == "BruteForce"]
print(f"\n  DoS predictions     avg confidence: {np.mean(dos_conf):.3f}" if dos_conf else "")
print(f"  BruteForce pred     avg confidence: {np.mean(brute_conf):.3f}" if brute_conf else "")

# ──────────────────────────────────────────────
# 3. Check what % of DoS trees vote DoS vs BruteForce
# ──────────────────────────────────────────────
print("\n" + "=" * 65)
print("TREE-VOTE PROFILE (averaged across all 100 samples)")
print("=" * 65)

from collections import defaultdict
avg_votes = defaultdict(list)
for dist in tree_vote_distributions:
    for lbl, frac in dist.items():
        avg_votes[lbl].append(frac)

for lbl, vals in sorted(avg_votes.items(), key=lambda x: -np.mean(x[1])):
    print(f"  {lbl:20s}: avg vote share = {np.mean(vals):.3f}  (max={np.max(vals):.3f})")

# ──────────────────────────────────────────────
# 4. Feature importance — which features push BruteForce classification?
# ──────────────────────────────────────────────
print("\n" + "=" * 65)
print("TOP 20 MOST IMPORTANT FEATURES (attack_model)")
print("=" * 65)

importances = attack_model.feature_importances_
sorted_idx  = np.argsort(importances)[::-1]
feat_names  = atk_feat_names

for rank, idx in enumerate(sorted_idx[:20], 1):
    fname = feat_names[idx] if idx < len(feat_names) else f"feat_{idx}"
    print(f"  #{rank:2d}  {fname:35s}  importance={importances[idx]:.5f}")

# ──────────────────────────────────────────────
# 5. Feature value comparison: SlowHTTPTest vs BruteForce samples
#    (show mean values of top-10 features)
# ──────────────────────────────────────────────
print("\n" + "=" * 65)
print("FEATURE MEAN VALUES FOR TOP-10 FEATURES (SlowHTTPTest samples)")
print("=" * 65)

# Stack all X_attack arrays
X_stack = np.vstack(all_X_attack)   # shape (N, num_features)

wrong_mask   = np.array(all_labels) != "DoS"
correct_mask = ~wrong_mask

print(f"\n  Samples correctly predicted as DoS    : {correct_mask.sum()}")
print(f"  Samples wrongly predicted as BruteForce: {wrong_mask.sum()}")

top10_idx = sorted_idx[:10]
print(f"\n  {'Feature':35s}  {'DoS-correct':>12s}  {'BruteForce-wrong':>17s}  {'Diff':>8s}")
print(f"  {'-'*35}  {'-'*12}  {'-'*17}  {'-'*8}")

for idx in top10_idx:
    fname = feat_names[idx] if idx < len(feat_names) else f"feat_{idx}"
    if X_stack.shape[1] <= idx:
        continue
    vals_correct = X_stack[correct_mask, idx] if correct_mask.sum() > 0 else np.array([0])
    vals_wrong   = X_stack[wrong_mask, idx]   if wrong_mask.sum() > 0   else np.array([0])
    mean_correct = np.mean(vals_correct)
    mean_wrong   = np.mean(vals_wrong)
    diff         = mean_wrong - mean_correct
    print(f"  {fname:35s}  {mean_correct:12.4f}  {mean_wrong:17.4f}  {diff:+8.4f}")

# ──────────────────────────────────────────────
# 6. What does the attack_model think DoS class looks like? 
#    Try checking the class encoding
# ──────────────────────────────────────────────
print("\n" + "=" * 65)
print("LABEL ENCODER CLASSES (encoded index mapping)")
print("=" * 65)
for i, cls in enumerate(label_encoder.classes_):
    print(f"  Index {i} => {cls}")

print("\n" + "=" * 65)
print("RECOMMENDATION")
print("=" * 65)
print("""
  Based on tree vote distribution, SlowHTTPTest is being confused because:

  Option A: DoS vote fraction is close to BruteForce (both ~35-40%)
    => Fix: Add a DoS-specific rule based on key network features
            (e.g., Flow Duration, Packet Length, Fwd Packets/s)

  Option B: Majority vote always picks BruteForce (>60% trees)
    => Fix: Use a post-classifier rule based on flow features:
            SlowHTTPTest has very long flow duration + small packets
            -> If IDS_score>0.8 AND flow_duration>1e6 AND avg_pkt<500
               -> Override to DoS

  See feature means table above to identify the best discriminating features.
""")

print("[DONE]")
