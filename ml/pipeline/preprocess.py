import joblib
import os
import numpy as np

# All models live inside the project — no external dependencies!
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MODEL_DIR = os.path.join(BASE_DIR, "ml", "models")
ATTACK_PREPROCESS_DIR = os.path.join(BASE_DIR, "ml", "preprocessors")

# IDS model expects 78 CamelCase features — loaded once at startup
ids_features = joblib.load(os.path.join(MODEL_DIR, "ids_features.pkl"))

# Attack model features (lowercase, timestamp excluded)
attack_features_raw = joblib.load(os.path.join(ATTACK_PREPROCESS_DIR, "features.pkl"))
attack_features = [f for f in attack_features_raw if f.lower() != "timestamp"]

# Scaler for IDS model
scaler = joblib.load(os.path.join(MODEL_DIR, "scaler.pkl"))

# =============================================================
# Lowercase alias map:
# IDS model uses CamelCase (e.g. "Flow Duration")
# Incoming data uses lowercase (e.g. "flow duration")
# We normalize everything to lowercase for lookup.
# =============================================================
# Build a lowercase -> value lookup at preprocess time (done per call)

def _normalize_key(k: str) -> str:
    """Strip, lowercase. Handles 'Dst Port' -> 'dst port' etc."""
    return k.strip().lower()


def preprocess(data: dict):
    """
    Accepts a flat dict of network flow features (any case).
    Returns:
        X_scaled  — (1, 78) array for IDS model  (scaled)
        X_attack  — (1, N)  array for Attack classifier (raw)
    """
    # ── Step 1: Normalize all incoming keys to lowercase ──────────────────
    norm = {_normalize_key(k): v for k, v in data.items()}

    # ── Step 2: Protocol — keep numeric (6=tcp, 17=udp, 1=icmp) ──────────
    # If someone sends "tcp"/"udp" string, convert to number
    if "protocol" in norm:
        proto_val = norm["protocol"]
        if isinstance(proto_val, str):
            proto_map_str = {"tcp": 6, "udp": 17, "icmp": 1}
            norm["protocol"] = proto_map_str.get(proto_val.lower(), 0)
        # else already numeric — leave as-is

    # ── Step 3: Build IDS input vector (78 features, CamelCase) ──────────
    # ids_features has CamelCase names — we look them up by lowercasing them
    row_ids = []
    missing_mask = []
    for feat in ids_features:
        key = _normalize_key(feat)
        if key in norm:
            val = norm[key]
            try:
                val = float(val)
            except (ValueError, TypeError):
                val = 0.0
            row_ids.append(val)
            missing_mask.append(False)
        else:
            row_ids.append(0.0)
            missing_mask.append(True)

    row_ids = np.array(row_ids, dtype=np.float64).reshape(1, -1)
    # Clip inf/-inf and replace NaN so scaler never crashes (e.g. Infiltration rows)
    # Use float32 max because sklearn scalers internally use float32
    FLOAT32_MAX = float(np.finfo(np.float32).max) * 0.5
    row_ids = np.clip(row_ids, -FLOAT32_MAX, FLOAT32_MAX)
    row_ids = np.nan_to_num(row_ids, nan=0.0, posinf=FLOAT32_MAX, neginf=-FLOAT32_MAX)
    
    row_scaled = scaler.transform(row_ids)
    
    # Post-scaler clip: scaler itself can produce large values from extreme inputs
    row_scaled = np.clip(row_scaled, -FLOAT32_MAX, FLOAT32_MAX)
    row_scaled = np.nan_to_num(row_scaled, nan=0.0)
    
    # Impute missing features with 0.0 (the scaled mean)
    # This is CRITICAL for live sniffer data which only has 10 features.
    for i, is_missing in enumerate(missing_mask):
        if is_missing:
            row_scaled[0, i] = 0.0

    # ── Step 4: Build Attack model input vector ───────────────────────────
    # attack_features are already lowercase
    row_attack = []
    for feat in attack_features:
        key = _normalize_key(feat)
        row_attack.append(float(norm.get(key, 0.0)))

    row_attack = np.array(row_attack, dtype=np.float64).reshape(1, -1)
    # Clip inf/NaN in attack vector too (same as IDS vector)
    # Infiltration rows have Inf values that crash sklearn tree predictors
    row_attack = np.clip(row_attack, -FLOAT32_MAX, FLOAT32_MAX)
    row_attack = np.nan_to_num(row_attack, nan=0.0, posinf=FLOAT32_MAX, neginf=-FLOAT32_MAX)

    return row_scaled, row_attack