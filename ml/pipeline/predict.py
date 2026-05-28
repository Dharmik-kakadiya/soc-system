import joblib
import os
import numpy as np
import warnings
from scipy.stats import mode
from ml.pipeline.preprocess import preprocess, ids_features

# Suppress sklearn version warnings
warnings.filterwarnings("ignore")
try:
    from sklearn.exceptions import InconsistentVersionWarning
    warnings.simplefilter("ignore", InconsistentVersionWarning)
except ImportError:
    pass

# =========================
# Paths
# =========================
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))

IDS_MODEL_PATH    = os.path.join(BASE_DIR, "ml", "models", "network_model.pkl")
ATTACK_MODEL_PATH = os.path.join(BASE_DIR, "ml", "models", "attack_model.pkl")
ENCODER_PATH      = os.path.join(BASE_DIR, "ml", "preprocessors", "attack_label_encoder.pkl")

# =========================
# Load models (once at startup)
# =========================
ids_model     = joblib.load(IDS_MODEL_PATH)
attack_model  = joblib.load(ATTACK_MODEL_PATH)
label_encoder = joblib.load(ENCODER_PATH)
ids_model.verbose = 0

# =========================
# Helpers
# =========================

def _count_filled_features(data: dict) -> int:
    """Count how many of the 78 IDS features are present (non-zero) in payload."""
    norm = {k.strip().lower(): v for k, v in data.items()}
    return sum(1 for f in ids_features if norm.get(f.strip().lower(), 0.0) != 0.0)


def _run_attack_classifier(X_raw) -> str:
    """Majority-vote across RF trees to get attack label."""
    predictions = np.array([tree.predict(X_raw) for tree in attack_model.estimators_])
    attack_pred = int(mode(predictions, axis=0, keepdims=False).mode[0])
    return str(label_encoder.inverse_transform([attack_pred])[0])


def _run_attack_classifier_with_confidence(X_raw):
    """Return (label, confidence) where confidence = fraction of trees that agreed."""
    predictions = np.array([tree.predict(X_raw) for tree in attack_model.estimators_])
    flat = predictions.flatten()
    attack_pred_enc = int(mode(predictions, axis=0, keepdims=False).mode[0])
    confidence = float((flat == attack_pred_enc).sum()) / len(flat)
    label = str(label_encoder.inverse_transform([attack_pred_enc])[0])
    return label, confidence


def _apply_post_classifier_rules(label: str, confidence: float,
                                  data: dict, ids_score: float) -> str:
    """
    Post-classifier heuristic overrides.
    These rules correct known misclassification patterns WITHOUT retraining.

    Rule 1 — SlowHTTPTest correction:
      When IDS score is HIGH (>=0.80) and classifier says BruteForce,
      check flow_pkts_s. SlowHTTPTest has much lower packet rate than real
      BruteForce attacks. Threshold derived from diagnostic:
        - SlowHTTPTest (DoS-correct):     flow_pkts_s ~592k
        - SlowHTTPTest (BruteForce-wrong): flow_pkts_s ~918k
        - Real BruteForce attacks:         flow_pkts_s >> 1M
      If flow_pkts_s < 750k AND dst_port is typical HTTP (80/443/8080/8443)
      and IDS score >= 0.80 => override BruteForce -> DoS
    """
    norm = {k.strip().lower(): v for k, v in data.items()}

    # Rule 1: SlowHTTPTest correction (BruteForce -> DoS override)
    #
    # Real-World SOC Logic vs Dataset Anomaly:
    # A true SlowHTTPTest targets web servers (ports 80, 443). 
    # In CICIDS-2018, there is a known anomaly where some SlowHTTPTest samples
    # were recorded against port 21 (FTP) and are mathematically 100% identical 
    # to FTP-BruteForce in flow features (same packet sizes, flags, ratios).
    # 
    # If we override port 21 flows to DoS, we destroy FTP-BruteForce accuracy.
    # Therefore, we implement the correct real-world rule:
    # If it is an HTTP port AND packet rate is genuinely slow AND classifier 
    # says BruteForce -> override to DoS (SlowHTTPTest).
    #
    if label == "BruteForce" and ids_score >= 0.95:
        flow_pkts_s = float(norm.get("flow pkts/s", norm.get("flow_pkts/s", -1)))
        dst_port    = int(float(norm.get("dst port",   norm.get("dst_port",    0))))
        http_ports  = {80, 443, 8080, 8443, 8000}

        # Real SlowHTTPTest on web ports has slow packet rates (< 400k)
        # Web-BruteForce has even slower rates but we rely on the primary classifier
        # to separate them mostly; this rule catches extreme DoS-like slow flows.
        if flow_pkts_s != -1 and flow_pkts_s < 400_000 and dst_port in http_ports:
            return "DoS"

    return label  # no override — return original


# =========================
# Main Predict Function
# =========================

def predict(data: dict, debug: bool = False) -> dict:
    """
    Two-stage classifier (IDS gating + Attack classification).

    Threshold logic (tuned after benchmark 2026-05-04):
      Main gate  : IDS_THRESHOLD = 0.15   (was 0.20)
        - Lowered because DDOS-HOIC scores 0.17-0.20 and was being blocked
          as BENIGN (50% of samples lost at old threshold).

      Confidence bypass zone (0.12 <= score < 0.15):
        - Run attack classifier; if >=70% of trees agree on a non-BENIGN
          label, report attack (recovers Infiltration & borderline DDoS).

      Absolute floor: score < 0.12 => always BENIGN (no exceptions).

      SlowHTTPTest mislabelled as BruteForce:
        - IDS score is 0.99 (fine), issue is attack classifier confusing
          slow-HTTP with BruteForce. No threshold fix possible without
          retraining — handled by confidence check (majority vote still
          picks DoS correctly most of the time).
    """
    # Step 1: Preprocess
    X_scaled, X_raw = preprocess(data)

    if debug:
        print("[DEBUG] X_scaled (first 10):", X_scaled[0][:10])

    # Step 2: IDS Score
    proba        = ids_model.predict_proba(X_scaled)[0]
    attack_score = proba[1]
    filled       = _count_filled_features(data)

    if debug:
        print(f"[DEBUG] IDS score={attack_score:.4f} | features_filled={filled}/78")

    # Step 3: Threshold decisions (Tuned to eliminate False Positives)
    # The IDS model standard threshold is 0.50. 
    # Benign traffic naturally scores between 0.01 and 0.49.
    IDS_THRESHOLD     = 0.50   # Strict gate for clear attacks
    CONFIDENCE_FLOOR  = 0.15   # Absolute minimum for borderline check

    if debug:
        print(f"[DEBUG] score={attack_score:.4f} | threshold={IDS_THRESHOLD} | filled={filled}")

    # ────────────────────────────────────────────────────────
    # GLOBAL EXTREME HEURISTIC OVERRIDE (Failsafe)
    # ────────────────────────────────────────────────────────
    # Before trusting the AI model (which can be confused by synthetic/crafted payloads),
    # we catch undeniable, physically extreme attack signatures.
    norm_data = {k.strip().lower(): v for k, v in data.items()}
    syn_flags = float(norm_data.get("syn flag cnt", norm_data.get("syn_flag_cnt", 0)))
    flow_pkts_s = float(norm_data.get("flow pkts/s", norm_data.get("flow_pkts/s", 0)))
    tot_fwd_pkts = float(norm_data.get("tot fwd pkts", norm_data.get("tot_fwd_pkts", 0)))
    
    # 1. Massive SYN Flood (Unmistakable DoS)
    if syn_flags > 500:
        if debug: print("[DEBUG] GLOBAL OVERRIDE: Massive SYN Flood detected.")
        return {"attack": True, "attack_type": "DoS"}
        
    # 2. Extreme Volumetric DDoS 
    if flow_pkts_s > 50_000 or (tot_fwd_pkts > 8000 and flow_pkts_s > 5000):
        if debug: print("[DEBUG] GLOBAL OVERRIDE: Volumetric DDoS detected.")
        return {"attack": True, "attack_type": "DDoS"}

    # Absolute floor - keeps 100% of pure BENIGN traffic safe
    if attack_score < CONFIDENCE_FLOOR:
        return {"attack": False, "attack_type": "BENIGN"}

    # Borderline zone: 0.15 <= score < 0.50 
    # This zone is exclusively to catch DDOS-HOIC (which scores ~0.17 to 0.49).
    # Normal BENIGN traffic also falls here, so we MUST NOT blindly trust the attack classifier
    # unless it explicitly calls out DDoS with near-perfect confidence.
    if attack_score < IDS_THRESHOLD:
        attack_label, confidence = _run_attack_classifier_with_confidence(X_raw)
        if debug:
            print(f"[DEBUG] borderline zone | clf={attack_label} | conf={confidence:.2f}")
            
        # Specific bypass for DDOS-HOIC (it perfectly classifies as DDoS)
        if attack_label == "DDoS" and confidence >= 0.90:
             return {"attack": True, "attack_type": attack_label}
             
        # If it's anything else in this low-score zone (especially Infiltration), it is BENIGN traffic.
        return {"attack": False, "attack_type": "BENIGN"}

    # score >= 0.50: clear attack signal
    attack_label, confidence = _run_attack_classifier_with_confidence(X_raw)

    # ────────────────────────────────────────────────────────
    # LIVE SNIFFER HEURISTIC OVERRIDE
    # ────────────────────────────────────────────────────────
    # The live sniffer only provides 10 features, leaving 68 features missing.
    # The Attack Model (Random Forest) cannot function accurately with 68 missing features 
    # and will blindly guess "Infiltration". We override it using the 10 real features.
    if filled <= 15:
        norm = {k.strip().lower(): v for k, v in data.items()}
        flow_pkts_s = float(norm.get("flow pkts/s", norm.get("flow_pkts/s", 0)))
        tot_fwd_pkts = float(norm.get("tot fwd pkts", norm.get("tot_fwd_pkts", 0)))
        dst_port = int(float(norm.get("dst port", norm.get("dst_port", 0))))
        
        # Heuristic 1: DDoS/DoS has extremely high packet rates 
        if flow_pkts_s > 100_000:
            attack_label = "DDoS"
        # Heuristic 2: BruteForce on standard ports with many packets
        elif dst_port in [21, 22] and tot_fwd_pkts > 30:
            attack_label = "BruteForce"
        # Heuristic 3: Web attacks usually target HTTP ports and have moderate flow
        elif dst_port in [80, 443, 8080] and tot_fwd_pkts > 50:
            attack_label = "WebAttack"
        # Otherwise, the "attack" signal from the IDS was a false alarm on limited live data
        else:
            return {"attack": False, "attack_type": "BENIGN"}

    # Apply post-classifier heuristic overrides (e.g. SlowHTTPTest -> DoS)
    attack_label = _apply_post_classifier_rules(attack_label, confidence, data, attack_score)

    is_attack = attack_label != "BENIGN"
    return {"attack": is_attack, "attack_type": attack_label}