# train_ids_model.py
# ==================
# Binary classifier: BENIGN (0) vs ATTACK (1)
# Same CSV data use karta hai jaise attack_model ne kiya
# Run: miniconda3/python.exe scripts/train_ids_model.py

import pandas as pd
import numpy as np
import joblib
import glob
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

# =========================
# Paths
# =========================
BASE_DIR = os.path.dirname(os.path.dirname(__file__))

DATA_PATH     = os.path.join(BASE_DIR, "data", "*.csv")
FEATURES_PATH = os.path.join(BASE_DIR, "ml", "preprocessors", "features.pkl")
SCALER_PATH   = os.path.join(BASE_DIR, "ml", "preprocessors", "scaler.pkl")
IDS_MODEL_PATH = os.path.join(BASE_DIR, "ml", "models", "ids_model.pkl")

CHUNK_SIZE = 50_000

# =========================
# Load features & scaler
# =========================
features = joblib.load(FEATURES_PATH)
NON_NUMERIC = {"timestamp"}
features = [f for f in features if f.lower() not in NON_NUMERIC]

scaler = joblib.load(SCALER_PATH)
print(f"[*] Features loaded: {len(features)}")

# =========================
# Labels that mean BENIGN
# =========================
BENIGN_LABELS = {"BENIGN", "Benign", "benign"}

# =========================
# Model
# =========================
model = RandomForestClassifier(
    n_estimators=10,
    warm_start=True,
    n_jobs=-1,
    random_state=42
)

total_trees = 0
files = [f for f in glob.glob(DATA_PATH) if f.endswith(".csv")]
print(f"[*] Found {len(files)} CSV files\n")

FLOAT32_MAX = np.finfo(np.float32).max

for file in files:
    print(f"[*] Processing: {os.path.basename(file)}")

    for i, chunk in enumerate(pd.read_csv(file, chunksize=CHUNK_SIZE,
                                           low_memory=False, on_bad_lines="skip")):

        print(f"    -> Chunk {i+1}", end="  ")

        # Normalize column names
        chunk.columns = chunk.columns.str.strip().str.lower()

        if "label" not in chunk.columns:
            print("[SKIP] no label column")
            continue

        # Binary label: 0 = BENIGN, 1 = ATTACK
        chunk["ids_label"] = chunk["label"].apply(
            lambda x: 0 if str(x).strip() in BENIGN_LABELS else 1
        )

        # Align to feature set
        chunk = chunk.reindex(columns=features + ["ids_label"], fill_value=0)

        # Clean numeric values
        chunk.replace([np.inf, -np.inf], np.nan, inplace=True)
        chunk.dropna(inplace=True)

        if chunk.empty:
            print("[SKIP] empty after clean")
            continue

        # Prepare X
        X = chunk[features].apply(pd.to_numeric, errors="coerce")
        X = X.clip(-FLOAT32_MAX, FLOAT32_MAX).fillna(0).astype("float32")
        y = chunk["ids_label"]

        # Scale using existing scaler
        X_scaled = scaler.transform(X)

        # Grow forest
        total_trees += 10
        model.n_estimators = total_trees
        model.fit(X_scaled, y)

        benign_count = (y == 0).sum()
        attack_count = (y == 1).sum()
        print(f"OK  benign={benign_count:,}  attack={attack_count:,}  trees={total_trees}")

# =========================
# Save
# =========================
print(f"\n[*] Saving IDS model ({total_trees} trees)...")
joblib.dump(model, IDS_MODEL_PATH)
print(f"[+] IDS model saved -> {IDS_MODEL_PATH}")
