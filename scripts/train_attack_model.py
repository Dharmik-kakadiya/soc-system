import pandas as pd
import joblib
import os
import glob
import numpy as np

from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

# =========================
# Paths
# =========================
BASE_DIR = os.path.dirname(os.path.dirname(__file__))

DATA_PATH = os.path.join(BASE_DIR, "data", "*.csv")

FEATURES_PATH = os.path.join(BASE_DIR, "ml", "preprocessors", "features.pkl")
MODEL_PATH = os.path.join(BASE_DIR, "ml", "models", "attack_model.pkl")
ENCODER_PATH = os.path.join(BASE_DIR, "ml", "preprocessors", "attack_label_encoder.pkl")

# =========================
# Attack Mapping (LOWERCASE FIXED)
# =========================
attack_map = {
    # DoS
    "dos attacks-hulk": "DoS",
    "dos attacks-goldeneye": "DoS",
    "dos attacks-slowloris": "DoS",
    "dos attacks-slowhttptest": "DoS",

    # DDoS
    "ddos attack-hoic": "DDoS",
    "ddos attack-loic-udp": "DDoS",
    "ddos attacks-loic-http": "DDoS",

    # 🔥 FIX (important)
    "ftp-bruteforce": "BruteForce",
    "ssh-bruteforce": "BruteForce",

    # Web
    "brute force -web": "BruteForce",
    "brute force -xss": "BruteForce",
    "sql injection": "WebAttack",

    # Other
    "infilteration": "Infiltration",
    "bot": "Bot"
}
all_classes = sorted(set(attack_map.values()))

# =========================
# Load features
# =========================
print("[*] Loading features...")
features = joblib.load(FEATURES_PATH)
features = [f for f in features if f.lower() != "timestamp"]

# =========================
# Label Encoder
# =========================
le = LabelEncoder()
le.fit(all_classes)
joblib.dump(le, ENCODER_PATH)

# =========================
# Collect Data
# =========================
X_all = []
y_all = []

files = [f for f in glob.glob(DATA_PATH) if f.endswith(".csv")]
print(f"[*] Found {len(files)} CSV files")

for file in files:
    print(f"\n[*] Processing: {os.path.basename(file)}")

    for chunk in pd.read_csv(file, chunksize=50000, low_memory=False, on_bad_lines='skip'):

        # Normalize column names
        chunk.columns = chunk.columns.str.strip().str.lower()

        if "label" not in chunk.columns:
            continue
            
        # 🔥 FIX: Map lowercase columns back to exact CamelCase features before reindexing
        feature_map = {f.lower(): f for f in features}
        chunk.rename(columns=feature_map, inplace=True)

        # =========================
        # 🔥 CLEAN LABELS (IMPORTANT)
        # =========================
        chunk["label"] = chunk["label"].astype(str).str.strip().str.lower()
        chunk["label"] = chunk["label"].str.replace("–", "-", regex=False)

        # =========================
        # 🔥 MAP LABELS
        # =========================
        chunk["attack_type"] = chunk["label"].map(attack_map)

        # DEBUG (first few chunks)
        if len(X_all) < 5:
            print("Raw:", chunk["label"].unique()[:5])
            print("Mapped:", chunk["attack_type"].dropna().unique())

        chunk = chunk.dropna(subset=["attack_type"])

        if chunk.empty:
            continue

        # Encode labels
        chunk["attack_type"] = le.transform(chunk["attack_type"])

        # Align features
        chunk = chunk.reindex(columns=features + ["attack_type"], fill_value=0)

        # Clean numeric values
        chunk.replace([np.inf, -np.inf], np.nan, inplace=True)
        chunk.dropna(inplace=True)

        if chunk.empty:
            continue

        X = chunk[features].apply(pd.to_numeric, errors="coerce")

        # 🔥 FIX INF + LARGE VALUES
        X.replace([np.inf, -np.inf], np.nan, inplace=True)

        FLOAT32_MAX = np.finfo(np.float32).max
        X = X.clip(-FLOAT32_MAX, FLOAT32_MAX)

        X = X.fillna(0).astype("float32")

        y = chunk["attack_type"]

        X_all.append(X.values)
        y_all.append(y.values)

        print(f"    collected rows={len(X)}")

# =========================
# Final Training
# =========================
print("\n[*] Merging data...")
X_all = np.vstack(X_all)
y_all = np.hstack(y_all)

print(f"[*] Final dataset: {X_all.shape}")
print(f"[*] Classes: {np.unique(y_all)}")

model = RandomForestClassifier(
    n_estimators=200,
    n_jobs=-1,
    random_state=42
)

print("[*] Training model...")
model.fit(X_all, y_all)

# =========================
# Save model
# =========================
joblib.dump(model, MODEL_PATH)

print(f"[+] Model saved -> {MODEL_PATH}")