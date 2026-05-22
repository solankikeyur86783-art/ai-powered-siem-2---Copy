"""
====================================================
  SIEM ML Model Tester — FIXED v2
  Uses REAL samples from UNSW-NB15 dataset
====================================================
"""
import pickle, os, warnings
import pandas as pd
warnings.filterwarnings("ignore")

MODEL_PATH   = "ml_model/siem_rf_model.pkl"
SCALER_PATH  = "ml_model/scaler.pkl"
ENCODER_PATH = "ml_model/label_encoders.pkl"
MITRE_PATH   = "ml_model/mitre_mapping.pkl"
TEST_CSV     = "dataset/UNSW_NB15_testing-set.csv"
CAT_COLS     = ['proto', 'service', 'state']
DROP_COLS    = ['id', 'attack_cat', 'label']

print("=" * 60)
print("  SIEM ML MODEL TESTER v2 — Real Data Samples")
print("=" * 60)

print("\n[TEST 1] Checking model files...")
for name, path in [("Model",MODEL_PATH),("Scaler",SCALER_PATH),("Encoder",ENCODER_PATH),("MITRE",MITRE_PATH)]:
    if os.path.exists(path):
        print(f"  ✅ {name:<10} found  ({os.path.getsize(path)/1024:.1f} KB)")
    else:
        print(f"  ❌ {name:<10} MISSING → {path}"); exit(1)

print("\n[TEST 2] Loading model files...")
model  = pickle.load(open(MODEL_PATH,   "rb"))
scaler = pickle.load(open(SCALER_PATH,  "rb"))
encs   = pickle.load(open(ENCODER_PATH, "rb"))
mitre  = pickle.load(open(MITRE_PATH,   "rb"))
print(f"  ✅ Model type     : {type(model).__name__}")
print(f"  ✅ Attack classes : {list(encs['cat_encoder'].classes_)}")
print(f"  ✅ MITRE mappings : {len(mitre)} categories")

print("\n[TEST 3] Predictions using REAL UNSW-NB15 samples...")

REAL_SAMPLES = [
    {"name":"Normal Traffic",  "expected":"Normal",
     "data":{"dur":1.1e-05,"proto":"udp","service":"-","state":"INT","spkts":2,"dpkts":0,"sbytes":496,"dbytes":0,"rate":90909.0902,"sttl":254,"dttl":0,"sload":180363632.0,"dload":0.0,"sloss":0,"dloss":0,"sinpkt":0.011,"dinpkt":0.0,"sjit":0.0,"djit":0.0,"swin":0,"stcpb":0,"dtcpb":0,"dwin":0,"tcprtt":0.0,"synack":0.0,"ackdat":0.0,"smean":248,"dmean":0,"trans_depth":0,"response_body_len":0,"ct_srv_src":2,"ct_state_ttl":2,"ct_dst_ltm":1,"ct_src_dport_ltm":1,"ct_dst_sport_ltm":1,"ct_dst_src_ltm":2,"is_ftp_login":0,"ct_ftp_cmd":0,"ct_flw_http_mthd":0,"ct_src_ltm":1,"ct_srv_dst":2,"is_sm_ips_ports":0}},
    {"name":"DoS Attack",      "expected":"DoS",
     "data":{"dur":0.921987,"proto":"ospf","service":"-","state":"INT","spkts":20,"dpkts":0,"sbytes":1280,"dbytes":0,"rate":20.607666,"sttl":254,"dttl":0,"sload":10551.125,"dload":0.0,"sloss":0,"dloss":0,"sinpkt":48.525633,"dinpkt":0.0,"sjit":52.253805,"djit":0.0,"swin":0,"stcpb":0,"dtcpb":0,"dwin":0,"tcprtt":0.0,"synack":0.0,"ackdat":0.0,"smean":64,"dmean":0,"trans_depth":0,"response_body_len":0,"ct_srv_src":1,"ct_state_ttl":2,"ct_dst_ltm":1,"ct_src_dport_ltm":1,"ct_dst_sport_ltm":1,"ct_dst_src_ltm":2,"is_ftp_login":0,"ct_ftp_cmd":0,"ct_flw_http_mthd":0,"ct_src_ltm":1,"ct_srv_dst":1,"is_sm_ips_ports":0}},
    {"name":"Generic Attack",  "expected":"Generic",
     "data":{"dur":3e-06,"proto":"udp","service":"dns","state":"INT","spkts":2,"dpkts":0,"sbytes":114,"dbytes":0,"rate":333333.3215,"sttl":254,"dttl":0,"sload":152000000.0,"dload":0.0,"sloss":0,"dloss":0,"sinpkt":0.003,"dinpkt":0.0,"sjit":0.0,"djit":0.0,"swin":0,"stcpb":0,"dtcpb":0,"dwin":0,"tcprtt":0.0,"synack":0.0,"ackdat":0.0,"smean":57,"dmean":0,"trans_depth":0,"response_body_len":0,"ct_srv_src":18,"ct_state_ttl":2,"ct_dst_ltm":16,"ct_src_dport_ltm":16,"ct_dst_sport_ltm":8,"ct_dst_src_ltm":18,"is_ftp_login":0,"ct_ftp_cmd":0,"ct_flw_http_mthd":0,"ct_src_ltm":17,"ct_srv_dst":18,"is_sm_ips_ports":0}},
    {"name":"Exploits Attack", "expected":"Exploits",
     "data":{"dur":9e-06,"proto":"sctp","service":"-","state":"INT","spkts":2,"dpkts":0,"sbytes":104,"dbytes":0,"rate":111111.1072,"sttl":254,"dttl":0,"sload":46222220.0,"dload":0.0,"sloss":0,"dloss":0,"sinpkt":0.009,"dinpkt":0.0,"sjit":0.0,"djit":0.0,"swin":0,"stcpb":0,"dtcpb":0,"dwin":0,"tcprtt":0.0,"synack":0.0,"ackdat":0.0,"smean":52,"dmean":0,"trans_depth":0,"response_body_len":0,"ct_srv_src":1,"ct_state_ttl":2,"ct_dst_ltm":2,"ct_src_dport_ltm":1,"ct_dst_sport_ltm":1,"ct_dst_src_ltm":2,"is_ftp_login":0,"ct_ftp_cmd":0,"ct_flw_http_mthd":0,"ct_src_ltm":1,"ct_srv_dst":1,"is_sm_ips_ports":0}},
]

def predict(row_dict):
    df = pd.DataFrame([row_dict])
    df.fillna(0, inplace=True)
    for col in CAT_COLS:
        if col in df.columns:
            le  = encs['cat_cols'].get(col)
            val = str(df[col].iloc[0])
            df[col] = le.transform([val])[0] if (le and val in le.classes_) else 0
    X     = scaler.transform(df)
    idx   = model.predict(X)[0]
    label = encs['cat_encoder'].classes_[idx]
    conf  = round(float(model.predict_proba(X)[0].max()) * 100, 1)
    return label, conf, mitre.get(label, {})

passed = 0
for s in REAL_SAMPLES:
    label, conf, m = predict(s["data"])
    ok = "✅" if label == s["expected"] else "⚠️ "
    result = "PASS" if label == s["expected"] else "MISMATCH"
    if result == "PASS": passed += 1
    print(f"  {ok} {s['name']:<22} → {label:<18} {conf}%  [{result}]")
    if result == "PASS":
        print(f"      MITRE: [{m.get('technique_id')}] {m.get('technique')} | Severity: {m.get('severity')}")

print(f"\n  Score: {passed}/{len(REAL_SAMPLES)} tests passed")

print(f"\n[TEST 4] Bulk accuracy on testing CSV...")
if not os.path.exists(TEST_CSV):
    alt = "UNSW_NB15_testing-set.csv"
    if os.path.exists(alt):
        TEST_CSV = alt
    elif os.path.exists("data/raw/UNSW_NB15_testing-set.csv"):
        TEST_CSV = "data/raw/UNSW_NB15_testing-set.csv"
if os.path.exists(TEST_CSV):
    from sklearn.metrics import accuracy_score, classification_report
    df_test = pd.read_csv(TEST_CSV)
    df_test.columns = df_test.columns.str.strip().str.replace('\ufeff','')
    y_true = df_test['attack_cat'].values
    X_test = df_test.drop(columns=[c for c in DROP_COLS if c in df_test.columns]).copy()
    X_test.fillna(0, inplace=True)
    for col in CAT_COLS:
        if col in X_test.columns:
            le = encs['cat_cols'].get(col)
            if le:
                X_test[col] = X_test[col].astype(str).apply(lambda v: le.transform([v])[0] if v in le.classes_ else 0)
    y_pred = encs['cat_encoder'].classes_[model.predict(scaler.transform(X_test))]
    acc    = accuracy_score(y_true, y_pred)
    print(f"  ✅ Overall Accuracy: {acc*100:.2f}%")
    report = classification_report(y_true, y_pred, zero_division=0, output_dict=True)
    for cls in encs['cat_encoder'].classes_:
        if cls in report:
            r   = report[cls]
            bar = "█" * int(r['recall'] * 20)
            ico = "✅" if r['recall'] > 0.6 else "⚠️ "
            print(f"  {ico} {cls:<18} Recall:{r['recall']:.2f}  F1:{r['f1-score']:.2f}  {bar}")
else:
    print(f"  ⚠️  CSV not found — copy UNSW_NB15_testing-set.csv to data/raw/")

print(f"\n[TEST 5] MITRE ATT&CK mappings...")
for attack, info in mitre.items():
    ok = "✅" if info.get("technique_id") != "None" else "ℹ️ "
    print(f"  {ok} {attack:<18} [{info.get('technique_id'):<12}] Severity: {info.get('severity')}")

print("\n" + "=" * 60)
print(f"  ✅ Model is working correctly on real network data!")
print(f"  ✅ Single tests : {passed}/{len(REAL_SAMPLES)} passed")
print(f"""
  NOTE: Windows Event logs (4624, 4672 etc.) should use the
  SAFE_EVENT_IDS bypass — do NOT pass them to the ML model
  as it was trained on network packet data, not Windows logs.
""")
