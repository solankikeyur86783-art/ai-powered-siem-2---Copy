"""
====================================================
  UNSW-NB15 ML Model Trainer + MITRE ATT&CK Mapper
  AI-Powered SIEM Project (Windows Fixed + Improved)
====================================================
"""

import pandas as pd
import numpy as np
import pickle
import os
import warnings
warnings.filterwarnings("ignore")

from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report, accuracy_score

# ─────────────────────────────────────────────
#  PATHS (WINDOWS + CROSS PLATFORM)
# ─────────────────────────────────────────────
TRAIN_PATH = "dataset/UNSW_NB15_training-set.csv"
TEST_PATH  = "dataset/UNSW_NB15_testing-set.csv"

MODEL_DIR  = "ml_model"
MODEL_PATH = os.path.join(MODEL_DIR, "siem_rf_model.pkl")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.pkl")
ENCODER_PATH = os.path.join(MODEL_DIR, "label_encoders.pkl")
MITRE_PATH = os.path.join(MODEL_DIR, "mitre_mapping.pkl")
FEATURE_PATH = os.path.join(MODEL_DIR, "feature_columns.pkl")

os.makedirs(MODEL_DIR, exist_ok=True)

# ─────────────────────────────────────────────
#  MITRE ATT&CK MAPPING
# ─────────────────────────────────────────────
MITRE_MAPPING = {
    "Normal": {"tactic": "None", "technique": "None", "technique_id": "None", "severity": "INFO",
               "description": "Normal network traffic — no threat detected."},
    "DoS": {"tactic": "Impact", "technique": "Network Denial of Service", "technique_id": "T1498",
            "severity": "HIGH", "description": "Attacker floods network."},
    "Exploits": {"tactic": "Execution", "technique": "Exploitation for Client Execution",
                 "technique_id": "T1203", "severity": "CRITICAL"},
    "Fuzzers": {"tactic": "Discovery", "technique": "Network Service Discovery",
                "technique_id": "T1046", "severity": "MEDIUM"},
    "Generic": {"tactic": "Initial Access", "technique": "Exploit Public-Facing Application",
                "technique_id": "T1190", "severity": "HIGH"},
    "Reconnaissance": {"tactic": "Reconnaissance", "technique": "Active Scanning",
                       "technique_id": "T1595", "severity": "MEDIUM"},
    "Backdoor": {"tactic": "Persistence", "technique": "Web Shell",
                 "technique_id": "T1505.003", "severity": "CRITICAL"},
    "Analysis": {"tactic": "Collection", "technique": "Network Sniffing",
                 "technique_id": "T1040", "severity": "MEDIUM"},
    "Shellcode": {"tactic": "Execution", "technique": "Native API",
                  "technique_id": "T1106", "severity": "CRITICAL"},
    "Worms": {"tactic": "Lateral Movement", "technique": "Replication",
              "technique_id": "T1091", "severity": "HIGH"},
}

# ─────────────────────────────────────────────
#  LOAD DATA
# ─────────────────────────────────────────────
def safe_label_transform(le, value):
    return le.transform([value])[0] if value in le.classes_ else -1

def preprocess(df, encoders=None, scaler=None, fit=False):
    df = df.copy()
    DROP_COLS = ['id', 'attack_cat', 'label']
    CAT_COLS  = ['proto', 'service', 'state']
    feature_cols = [c for c in df.columns if c not in DROP_COLS]
    X = df[feature_cols].copy()
    X.fillna(0, inplace=True)

    if fit:
        encoders = {}
        for col in CAT_COLS:
            if col in X.columns:
                le = LabelEncoder()
                X[col] = le.fit_transform(X[col].astype(str))
                encoders[col] = le
    else:
        for col in CAT_COLS:
            if col in X.columns:
                le = encoders[col]
                X[col] = X[col].astype(str).apply(lambda v: safe_label_transform(le, v))

    if fit:
        scaler = StandardScaler()
        X = scaler.fit_transform(X)
    else:
        X = scaler.transform(X)

    return X, encoders, scaler, feature_cols

def train():
    """Main training function called by API or CLI"""
    print("=" * 60)
    print("  SIEM ML MODEL TRAINER")
    print("=" * 60)

    print("\n[1/5] Loading data...")
    if not os.path.exists(TRAIN_PATH) or not os.path.exists(TEST_PATH):
        print(f"[ERROR] Dataset not found at {TRAIN_PATH}")
        return {"error": "Dataset not found"}

    train_df = pd.read_csv(TRAIN_PATH)
    test_df  = pd.read_csv(TEST_PATH)

    train_df.columns = train_df.columns.str.strip().str.replace('\ufeff', '')
    test_df.columns  = test_df.columns.str.strip().str.replace('\ufeff', '')

    # Labels
    y_train = train_df['attack_cat']
    y_test  = test_df['attack_cat']

    cat_encoder = LabelEncoder()
    y_train_enc = cat_encoder.fit_transform(y_train)
    y_test_enc  = cat_encoder.transform(y_test)

    X_train, encoders, scaler, feature_cols = preprocess(train_df, fit=True)
    X_test, _, _, _ = preprocess(test_df, encoders=encoders, scaler=scaler, fit=False)

    print("\n[3/5] Training model...")
    model = RandomForestClassifier(
        n_estimators=80,
        max_depth=18,
        min_samples_split=10,
        n_jobs=-1,
        random_state=42,
        class_weight='balanced'
    )
    model.fit(X_train, y_train_enc)

    print("\n[4/5] Evaluating...")
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test_enc, y_pred)

    print("\n[5/5] Saving model...")
    pickle.dump(model, open(MODEL_PATH, "wb"))
    pickle.dump(scaler, open(SCALER_PATH, "wb"))
    pickle.dump({'cat_cols': encoders, 'cat_encoder': cat_encoder}, open(ENCODER_PATH, "wb"))
    pickle.dump(MITRE_MAPPING, open(MITRE_PATH, "wb"))
    pickle.dump(feature_cols, open(FEATURE_PATH, "wb"))

    print("[OK] TRAINING COMPLETE!")
    return {
        "accuracy": float(acc),
        "n_samples": len(train_df) + len(test_df),
        "classes": list(cat_encoder.classes_)
    }

if __name__ == "__main__":
    train()