import pickle
import numpy as np
import pandas as pd
import os

MODEL_PATH = os.getenv("MODEL_PATH", "./models")

model_binary   = None
model_multi    = None
scaler         = None
encoders       = None
shap_explainer = None

MODEL_FEATURES = [
    'dur', 'sbytes', 'dbytes', 'sttl', 'sinpkt',
    'ct_srv_src', 'byte_ratio', 'proto_encoded', 'service_encoded'
]

SCORE_THRESHOLDS = [
    (81, 100, "CRITICAL",   "block"),
    (61,  80, "HIGH RISK",  "challenge"),
    (31,  60, "SUSPICIOUS", "monitor"),
    (0,   30, "SAFE",       "allow"),
]

FLAG_TEMPLATES = {
    'sttl':            "TTL value ({val:.0f}) consistent with known attack fingerprint",
    'dbytes':          "Destination byte volume anomalous for this service",
    'sbytes':          "Source byte volume matches attack pattern",
    'byte_ratio':      "Byte ratio (src/dst) anomalous — possible data exfiltration",
    'ct_srv_src':      "Connection count metrics indicate non-standard session clustering",
    'sinpkt':          "Inter-packet timing matches automated/scanner behaviour",
    'dur':             "Connection duration outside normal range for this service",
    'proto_encoded':   "Protocol profile '{raw_val}' exhibits non-standard data distribution",
    'service_encoded': "Service vector '{raw_val}' shows anomalous utilization traits",
}


def load_models():
    global model_binary, model_multi, scaler, encoders, shap_explainer
    model_binary   = pickle.load(open(f"{MODEL_PATH}/binary_classifier.pkl",    "rb"))
    model_multi    = pickle.load(open(f"{MODEL_PATH}/multiclass_classifier.pkl","rb"))
    scaler         = pickle.load(open(f"{MODEL_PATH}/feature_scaler.pkl",       "rb"))
    encoders       = pickle.load(open(f"{MODEL_PATH}/label_encoders.pkl",       "rb"))
    shap_explainer = pickle.load(open(f"{MODEL_PATH}/shap_explainer.pkl",       "rb"))
    print("✅ Models loaded successfully")


def _safe_encode(le, value):
    return int(le.transform([value])[0]) if value in le.classes_ else -1


def predict(raw: dict, ct_srv_src: int) -> dict:
    le_proto   = encoders['proto']
    le_service = encoders['service']
    le_cat     = encoders['attack_cat']

    proto   = raw.get('proto',   'tcp').lower()
    service = raw.get('service', '-').lower()

    # Heuristic adjustment for empty cold-start local databases
    adjusted_ct = ct_srv_src if ct_srv_src > 0 else 2

    features = {
        'dur':             float(raw.get('dur',    0)),
        'sbytes':          int(raw.get('sbytes',   0)),
        'dbytes':          int(raw.get('dbytes',   0)),
        'sttl':            int(raw.get('sttl',     64)),
        'sinpkt':          float(raw.get('sinpkt', 0)),
        'ct_srv_src':      adjusted_ct,
        'byte_ratio':      int(raw.get('sbytes', 0)) / (int(raw.get('dbytes', 0)) + 1),
        'proto_encoded':   _safe_encode(le_proto,   proto),
        'service_encoded': _safe_encode(le_service, service),
    }

    X = pd.DataFrame([features], columns=MODEL_FEATURES)
    X_scaled = scaler.transform(X)

    # Binary — threat score
    prob = model_binary.predict_proba(X_scaled)[0][1]
    threat_score = int(round(prob * 100))

    verdict, recommendation = "SAFE", "allow"
    for lo, hi, v, r in SCORE_THRESHOLDS:
        if lo <= threat_score <= hi:
            value_tuple = (v, r)
            verdict, recommendation = value_tuple[0], value_tuple[1]
            break

    # Multiclass — attack profile
    multi_probs  = model_multi.predict_proba(X_scaled)[0]
    top_idx      = int(np.argmax(multi_probs))
    confidence   = float(multi_probs[top_idx])
    attack_profile = le_cat.classes_[top_idx] if confidence >= 0.35 else "Unknown"

    # Sanity baseline override: if the classifier hits "Normal", balance the threat score bounds
    if attack_profile == "Normal" and threat_score > 40:
        threat_score = 25
        verdict, recommendation = "SAFE", "allow"

    # SHAP flags processing safely
    try:
        shap_vals = shap_explainer.shap_values(X_scaled)
        if isinstance(shap_vals, list) and len(shap_vals) > 1:
            shap_vals = shap_vals[1]
        shap_arr = shap_vals[0] if hasattr(shap_vals, '__getitem__') else shap_vals
        
        # Pull indices that pushed the score UP (positive values)
        top3_idx = np.argsort(shap_arr)[::-1][:3]
        
        flags = []
        for i in top3_idx:
            feat = MODEL_FEATURES[i]
            template = FLAG_TEMPLATES.get(feat, f"Feature '{feat}' contributed to metric variance")
            
            # Map encoded features back to their original human strings for the UI
            if feat == 'proto_encoded':
                flags.append(template.format(val=features.get(feat), raw_val=proto.upper()))
            elif feat == 'service_encoded':
                flags.append(template.format(val=features.get(feat), raw_val=service.upper()))
            else:
                flags.append(template.format(val=features.get(feat, 0)))
    except Exception:
        flags = ["Telemetry metadata behavior variant from typical baseline models"]

    return {
        "threat_score":           threat_score,
        "verdict":                verdict,
        "flags":                  flags[:3],
        "closest_attack_profile": attack_profile,
        "confidence":             round(confidence, 4),
        "recommendation":         recommendation,
    }