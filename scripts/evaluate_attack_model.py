import pandas as pd
import numpy as np
import joblib
import os
import glob
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix

# =========================
# Paths
# =========================
BASE_DIR = os.path.dirname(os.path.dirname(__file__))

DATA_PATH = os.path.join(BASE_DIR, "data", "*.csv")
MODEL_PATH = os.path.join(BASE_DIR, "ml", "models", "attack_model.pkl")
ENCODER_PATH = os.path.join(BASE_DIR, "ml", "preprocessors", "attack_label_encoder.pkl")
FEATURES_PATH = os.path.join(BASE_DIR, "ml", "preprocessors", "features.pkl")

# =========================
# Attack Mapping
# =========================
attack_map = {
    "DoS attacks-Hulk": "DoS",
    "DoS attacks-GoldenEye": "DoS",
    "DoS attacks-Slowloris": "DoS",
    "DoS attacks-SlowHTTPTest": "DoS",
    "DDOS attack-HOIC": "DDoS",
    "DDOS attack-LOIC-UDP": "DDoS",
    "DDoS attacks-LOIC-HTTP": "DDoS",
    "Brute Force -Web": "BruteForce",
    "Brute Force -XSS": "BruteForce",
    "SQL Injection": "WebAttack",
    "Infilteration": "Infiltration",
    "Bot": "Bot"
}

# =========================
# Load Models & Features
# =========================
print("[*] Loading Model and Preprocessors...")
try:
    model = joblib.load(MODEL_PATH)
    le = joblib.load(ENCODER_PATH)
    features = joblib.load(FEATURES_PATH)
    features = [f for f in features if f.lower() != "timestamp"]
except Exception as e:
    print(f"[!] Error loading model: {e}")
    exit(1)

# =========================
# Load Test Data
# =========================
files = [f for f in glob.glob(DATA_PATH) if f.endswith(".csv")]
if not files:
    print("[!] No CSV files found in data folder.")
    exit(1)

# Grab the first file for a quick accuracy test
test_file = files[0]
print(f"[*] Extracting Test Data from: {os.path.basename(test_file)}")

# Read only 150k rows to keep evaluation fast
df = pd.read_csv(test_file, nrows=150000, low_memory=False, on_bad_lines="skip")
df.columns = df.columns.str.strip().str.lower()

if "label" not in df.columns:
    print("[!] Label column missing in test file.")
    exit(1)

# Filter out only the attacks (we evaluate the attack model)
df["attack_type"] = df["label"].map(attack_map)
df = df.dropna(subset=["attack_type"])

print(f"[*] Found {len(df)} Attack samples for testing.")

if len(df) == 0:
    print("[!] No attack data found in this chunk. Run again or test another file.")
    exit(0)

# =========================
# Preprocess
# =========================
print("[*] Preprocessing...")
X_test = df[features].apply(pd.to_numeric, errors="coerce")
X_test.replace([np.inf, -np.inf], np.nan, inplace=True)
FLOAT32_MAX = np.finfo(np.float32).max
X_test = X_test.clip(-FLOAT32_MAX, FLOAT32_MAX).fillna(0).astype("float32")

y_true_labels = df["attack_type"].values

# =========================
# Predict & Evaluate
# =========================
print("[*] Predicting...")
# We use .values to avoid feature name warnings
y_pred_encoded = model.predict(X_test.values)
y_pred_labels = le.inverse_transform(y_pred_encoded)

print("\n" + "="*40)
print("=== ACCURACY REPORT ===")
print("="*40)

acc = accuracy_score(y_true_labels, y_pred_labels)
print(f"Overall Accuracy: {acc * 100:.2f}%\n")

print("Detailed Classification Report:")
print(classification_report(y_true_labels, y_pred_labels, zero_division=0))

print("Confusion Matrix:")
print(confusion_matrix(y_true_labels, y_pred_labels))
print("="*40)
