import pandas as pd
import glob
import os

# =========================
# Paths (UPDATED)
# =========================
BASE_DIR = os.path.dirname(os.path.dirname(__file__))  # go to root (soc-system)
DATA_PATH = os.path.join(BASE_DIR, "data", "*.csv")
OUTPUT_FILE = os.path.join(BASE_DIR, "data", "final_dataset.csv")

CHUNK_SIZE = 100000  # adjust if needed

# =========================
# Get all CSV files
# =========================
files = glob.glob(DATA_PATH)

# ❗ Ignore zip file if present
files = [f for f in files if f.endswith(".csv")]
# Ignore output file if it already exists
files = [f for f in files if os.path.abspath(f) != os.path.abspath(OUTPUT_FILE)]

if not files:
    print("❌ No CSV files found in data/")
    exit()

print(f"📂 Found {len(files)} CSV files")

if os.path.exists(OUTPUT_FILE):
    os.remove(OUTPUT_FILE)

first_chunk = True
total_rows = 0

# =========================
# Process each file
# =========================
for file in files:
    print(f"🔄 Processing: {os.path.basename(file)}")

    try:
        for chunk in pd.read_csv(file, chunksize=CHUNK_SIZE, low_memory=False):

            # Clean column names
            chunk.columns = chunk.columns.str.strip()

            # Fix label column
            if "Label" in chunk.columns:
                chunk.rename(columns={"Label": "label"}, inplace=True)

            # Drop NaN
            chunk.dropna(inplace=True)

            # Replace infinity
            chunk.replace([float("inf"), -float("inf")], 0, inplace=True)

            # Append to CSV
            chunk.to_csv(OUTPUT_FILE, mode='a', header=first_chunk, index=False)
            first_chunk = False
            total_rows += len(chunk)

    except Exception as e:
        print(f"⚠️ Error in {file}: {e}")

print("\n✅ FINAL DATASET READY")
print(f"📁 Saved at: {OUTPUT_FILE}")
print(f"📊 Total Rows: {total_rows}")