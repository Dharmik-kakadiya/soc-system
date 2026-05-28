import sys
import os
import pandas as pd

# =========================
# Fix path
# =========================
BASE_DIR = os.path.dirname(os.path.dirname(__file__))
sys.path.append(BASE_DIR)

from ml.pipeline.predict import predict

print("\n" + "="*60)
print("=== SOC SYSTEM PIPELINE TEST (MULTI-ATTACK PROOF) ===")
print("="*60)

# Files we know contain different attacks
test_files = [
    "02-14-2018.csv", # Bot / BruteForce
    "02-16-2018.csv", # DoS
    "02-20-2018.csv", # DDoS
    "03-01-2018.csv", # Infiltration
]

found_labels = set()

for file in test_files:
    file_path = os.path.join(BASE_DIR, "data", file)
    if not os.path.exists(file_path): continue
    
    # Read just a few rows to find an attack
    df = pd.read_csv(file_path, nrows=50000, low_memory=False)
    df.columns = df.columns.str.strip().str.lower()
    df["label"] = df["label"].astype(str).str.strip().str.lower()
    
    # Only look at attacks
    attack_df = df[df["label"] != "benign"]
    
    for _, row in attack_df.iterrows():
        label = row["label"]
        # If we haven't tested this attack type yet
        if label not in found_labels:
            found_labels.add(label)
            print(f"\n[*] Found new attack: {label.upper()} (in {file})")
            
            try:
                result = predict(row.to_dict())
                print(f"-> ACTUAL LABEL : {label}")
                print(f"-> PREDICTION   : {result['attack_type']}")
            except Exception as e:
                # Skip broken rows (e.g. nested CSV headers)
                found_labels.remove(label)
                continue
            
            # Stop if we found 5 different attacks
            if len(found_labels) >= 5:
                break
    if len(found_labels) >= 5:
        break

print("\n" + "="*60)