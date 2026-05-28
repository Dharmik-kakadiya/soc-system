import joblib
import os

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
ENCODER_PATH = os.path.join(BASE_DIR, "ml", "preprocessors", "attack_label_encoder.pkl")

# Raw dataset keys mapped to final model labels
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

print("\n" + "="*50)
print("=== DATASET RAW LABELS TO MODEL MAPPING ===")
print("="*50)
for raw_label, model_class in attack_map.items():
    print(f"  {raw_label:<25} -->  {model_class}")

print("\n" + "="*50)
print("=== FINAL MODEL TRAINED CLASSES (What it predicts) ===")
print("="*50)
try:
    le = joblib.load(ENCODER_PATH)
    classes = le.classes_
    print("The Attack Model is trained to predict these categories:")
    for i, c in enumerate(classes):
        print(f"  {i}: {c}")
except Exception as e:
    print(f"[!] Error loading encoder: {e}")
print("="*50 + "\n")
