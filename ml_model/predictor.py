# ml_model/predictor.py
from datetime import datetime
import pickle
import pandas as pd
import numpy as np
import os

BASE = os.path.dirname(os.path.abspath(__file__))

# Load artifacts safely
def load_pkl(filename):
    path = os.path.join(BASE, filename)
    if os.path.exists(path):
        return pickle.load(open(path, "rb"))
    return None

model   = load_pkl("siem_rf_model.pkl")
encs    = load_pkl("label_encoders.pkl") or {}
mitre   = load_pkl("mitre_mapping.pkl") or {}
feature_cols = load_pkl("feature_columns.pkl") or []

is_multi = encs.get("binary", False)

if is_multi:
    pipe_data = load_pkl("dataset_pipelines.pkl") or {}
    final_scaler = pipe_data.get('final_scaler')
    pipelines = pipe_data.get('pipelines', {})
else:
    scaler = load_pkl("scaler.pkl")
    CAT_COLS  = ['proto', 'service', 'state']
    DROP_COLS = ['id', 'attack_cat', 'label']

def get_model_info():
    """Retrieve metadata about the currently loaded model"""
    if model is None: return None
    try:
        n_est = getattr(model, 'n_estimators', 0)
        return {
            "type": "RandomForestClassifier",
            "n_features": len(feature_cols),
            "n_estimators": n_est,
            "classes": list(encs.get('cat_encoder').classes_) if encs.get('cat_encoder') else [],
            "last_loaded": datetime.utcnow().isoformat(),
            "is_multi_dataset": is_multi
        }
    except Exception:
        return None

def predict_attack(row: dict) -> dict:
    if model is None:
        return {"attack_type": "Normal", "confidence": 1.0}
    if is_multi:
        return _predict_multi(row)
    else:
        return _predict_single(row)

def _predict_single(row: dict) -> dict:
    df = pd.DataFrame([row])
    df.drop(columns=[c for c in DROP_COLS if c in df.columns], inplace=True)
    
    for col in CAT_COLS:
        if col in df.columns:
            le = encs['cat_cols'].get(col)
            if le:
                val = str(df[col].iloc[0])
                df[col] = le.transform([val])[0] if val in le.classes_ else -1
                
    for feat in feature_cols:
        if feat not in df.columns:
            df[feat] = 0
            
    df = df[feature_cols].fillna(0)
    X = scaler.transform(df)
    
    pred_idx   = model.predict(X)[0]
    pred_label = encs['cat_encoder'].classes_[pred_idx]
    confidence = round(float(model.predict_proba(X)[0].max()), 4)
    mitre_info = mitre.get(pred_label, {})
    
    return {
        "attack_type":      pred_label,
        "confidence":       confidence,
        "severity":         mitre_info.get("severity", "INFO"),
        "mitre_tactic":     mitre_info.get("tactic", "None"),
        "mitre_technique":  mitre_info.get("technique", "None"),
        "technique_id":     mitre_info.get("technique_id", "None"),
        "description":      mitre_info.get("description", ""),
    }

def _predict_multi(row: dict) -> dict:
    # Use UNSW-NB15 pipeline as default for simulated logs
    unsw_pipe = pipelines.get("UNSW-NB15")
    if not unsw_pipe:
        return {"attack_type": "Normal", "confidence": 1.0}
        
    df = pd.DataFrame([row])
    
    les = unsw_pipe.get('les', {})
    for col, le in les.items():
        if col in df.columns:
            val = str(df[col].iloc[0])
            df[col] = le.transform([val])[0] if val in le.classes_ else -1
            
    feat = unsw_pipe['feat']
    for f in feat:
        if f not in df.columns:
            df[f] = 0
            
    df = df[feat].replace([np.inf, -np.inf], np.nan).fillna(0)
    
    X_sc = unsw_pipe['sc'].transform(df)
    X_pca = unsw_pipe['pca'].transform(X_sc)
    
    N_PCA = len(feature_cols)
    if X_pca.shape[1] < N_PCA:
        X_pca = np.hstack([X_pca, np.zeros((X_pca.shape[0], N_PCA - X_pca.shape[1]))])
        
    X_final = final_scaler.transform(X_pca)
    
    pred_idx = model.predict(X_final)[0]
    pred_label = encs['cat_encoder'].classes_[pred_idx]
    confidence = round(float(model.predict_proba(X_final)[0].max()), 4)
    mitre_info = mitre.get(pred_label, {})
    
    return {
        "attack_type":      pred_label,
        "confidence":       confidence,
        "severity":         mitre_info.get("severity", "INFO"),
        "mitre_tactic":     mitre_info.get("tactic", "None"),
        "mitre_technique":  mitre_info.get("technique", "None"),
        "technique_id":     mitre_info.get("technique_id", "None"),
        "description":      mitre_info.get("description", ""),
    }
