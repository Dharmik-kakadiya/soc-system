import pandas as pd
import glob
import os

files = glob.glob("data/*.csv")
all_labels = set()

for file in files:
    print(f"Scanning {os.path.basename(file)}...")
    try:
        # Read only the first 500k rows to be fast, just need unique labels
        df = pd.read_csv(file, nrows=500000, low_memory=False, on_bad_lines="skip")
        df.columns = df.columns.str.strip().str.lower()
        if "label" in df.columns:
            all_labels.update(df["label"].dropna().unique())
    except Exception as e:
        print(f"Error reading {file}: {e}")

print("\n=== ALL UNIQUE LABELS ACROSS ALL FILES ===")
print(all_labels)
