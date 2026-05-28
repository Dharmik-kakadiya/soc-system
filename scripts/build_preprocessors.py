# build_preprocessors.py
# ======================
# Scaler + categorical encoders CSV data se fit karke save karta hai.
# Run: miniconda3/python.exe scripts/build_preprocessors.py

import pandas as pd
import numpy as np
import joblib
import glob
import os
from sklearn.preprocessing import StandardScaler, LabelEncoder

# =========================
# Paths
# =========================
BASE_DIR = os.path.dirname(os.path.dirname(__file__))

DATA_PATH      = os.path.join(BASE_DIR, "data", "*.csv")
FEATURES_PATH  = os.path.join(BASE_DIR, "ml", "preprocessors", "features.pkl")
SCALER_PATH    = os.path.join(BASE_DIR, "ml", "preprocessors", "scaler.pkl")
PROTO_ENC_PATH = os.path.join(BASE_DIR, "ml", "preprocessors", "protocol_encoder.pkl")
FLAG_ENC_PATH  = os.path.join(BASE_DIR, "ml", "preprocessors", "flag_encoder.pkl")

CHUNK_SIZE = 50_000
MAX_CHUNKS = 20          # pehle 20 chunks se fit karna kaafi hai scaler ke liye

# =========================
# Load feature list
# =========================
features = joblib.load(FEATURES_PATH)

# Drop non-numeric columns same as train script
NON_NUMERIC = {"timestamp"}
num_features = [f for f in features if f.lower() not in NON_NUMERIC]

print(f"[*] Numeric features to scale: {len(num_features)}")

# =========================
# Collect samples for fitting
# =========================
files = [f for f in glob.glob(DATA_PATH) if f.endswith(".csv")]
print(f"[*] Found {len(files)} CSV files")

X_sample  = []
proto_vals = set()
flag_vals  = set()

chunks_done = 0

for file in files:
    print(f"\n[*] {os.path.basename(file)}")
    for chunk in pd.read_csv(file, chunksize=CHUNK_SIZE,
                             low_memory=False, on_bad_lines="skip"):

        # Normalize column names
        chunk.columns = chunk.columns.str.strip().str.lower()

        # Collect protocol values
        if "protocol" in chunk.columns:
            proto_vals.update(chunk["protocol"].dropna().astype(str).unique())

        # Collect flag values (some datasets have "flag" column)
        if "flag" in chunk.columns:
            flag_vals.update(chunk["flag"].dropna().astype(str).unique())

        # Collect numeric feature rows for scaler
        available = [f for f in num_features if f in chunk.columns]
        sub = chunk[available].apply(pd.to_numeric, errors="coerce")
        sub.replace([np.inf, -np.inf], np.nan, inplace=True)

        FLOAT32_MAX = np.finfo(np.float32).max
        sub = sub.clip(-FLOAT32_MAX, FLOAT32_MAX).fillna(0)

        X_sample.append(sub)
        chunks_done += 1

        if chunks_done >= MAX_CHUNKS:
            break

    if chunks_done >= MAX_CHUNKS:
        break

print(f"\n[*] Collected {chunks_done} chunks for fitting")

# =========================
# Fit & save Scaler
# =========================
print("[*] Fitting StandardScaler...")
X_all = pd.concat(X_sample, ignore_index=True)

# Build a full-width array aligned to num_features (fill missing cols with 0)
X_aligned = pd.DataFrame(0.0, index=X_all.index, columns=num_features)
for col in num_features:
    if col in X_all.columns:
        X_aligned[col] = X_all[col]

scaler = StandardScaler()
scaler.fit(X_aligned.values.astype("float32"))
joblib.dump(scaler, SCALER_PATH)
print(f"    -> Scaler saved  ({len(num_features)} features)")

# =========================
# Fit & save Protocol Encoder
# =========================
print("[*] Fitting Protocol LabelEncoder...")
if not proto_vals:
    proto_vals = {"tcp", "udp", "icmp", "0", "6", "17"}    # safe fallback
proto_le = LabelEncoder()
proto_le.fit(sorted(proto_vals))
joblib.dump(proto_le, PROTO_ENC_PATH)
print(f"    -> Protocol encoder saved  classes={list(proto_le.classes_)}")

# =========================
# Fit & save Flag Encoder
# =========================
print("[*] Fitting Flag LabelEncoder...")
if not flag_vals:
    flag_vals = {"SF", "S0", "REJ", "RSTO", "SH", "OTH", "S1", "S2", "S3", "RSTR"}
flag_le = LabelEncoder()
flag_le.fit(sorted(flag_vals))
joblib.dump(flag_le, FLAG_ENC_PATH)
print(f"    -> Flag encoder saved  classes={list(flag_le.classes_)}")

print("\n[+] ALL preprocessors built and saved successfully!")
print(f"    scaler          -> {SCALER_PATH}")
print(f"    protocol_encoder-> {PROTO_ENC_PATH}")
print(f"    flag_encoder    -> {FLAG_ENC_PATH}")
