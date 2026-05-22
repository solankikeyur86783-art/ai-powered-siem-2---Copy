"""
MULTI-DATASET SIEM ML TRAINER  (FAST VERSION - ~3-5 min)
Datasets: NSL-KDD + UNSW-NB15 + CIC-IDS2017 + Darknet
Target  : 95%+ Accuracy
"""
import os, glob, pickle, warnings
import numpy as np
import pandas as pd
warnings.filterwarnings("ignore")

from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.decomposition import PCA
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from datetime import datetime

# ── PATHS ──────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR = os.path.join(BASE_DIR, "dataset")
MODEL_DIR   = os.path.join(BASE_DIR, "ml_model")
os.makedirs(MODEL_DIR, exist_ok=True)

MODEL_PATH   = os.path.join(MODEL_DIR, "siem_rf_model.pkl")
SCALER_PATH  = os.path.join(MODEL_DIR, "scaler.pkl")
ENCODER_PATH = os.path.join(MODEL_DIR, "label_encoders.pkl")
MITRE_PATH   = os.path.join(MODEL_DIR, "mitre_mapping.pkl")
FEATURE_PATH = os.path.join(MODEL_DIR, "feature_columns.pkl")
PIPELINE_PATH= os.path.join(MODEL_DIR, "dataset_pipelines.pkl")

# ── CONFIG (tuned for speed + 95%+) ────────────────────────────────
N_PCA          = 40      # PCA dims per dataset
MAX_ROWS_DS    = 40_000  # max rows per dataset
MAX_ROWS_FILE  = 15_000  # max rows per CIC-IDS file
N_TREES        = 120     # RF trees
RANDOM_STATE   = 42

# ── MITRE MAPPING ───────────────────────────────────────────────────
MITRE_MAPPING = {
    "Normal":     {"tactic":"None","technique":"None","technique_id":"None","severity":"INFO","description":"Normal traffic"},
    "DoS":        {"tactic":"Impact","technique":"Network Denial of Service","technique_id":"T1498","severity":"HIGH","description":"DoS attack"},
    "DDoS":       {"tactic":"Impact","technique":"Network Denial of Service","technique_id":"T1498","severity":"HIGH","description":"DDoS attack"},
    "Probe":      {"tactic":"Reconnaissance","technique":"Active Scanning","technique_id":"T1595","severity":"MEDIUM","description":"Network probe"},
    "R2L":        {"tactic":"Initial Access","technique":"Exploit Public-Facing Application","technique_id":"T1190","severity":"HIGH","description":"Remote-to-Local"},
    "U2R":        {"tactic":"Privilege Escalation","technique":"Exploitation for Privilege Escalation","technique_id":"T1068","severity":"CRITICAL","description":"User-to-Root"},
    "Exploits":   {"tactic":"Execution","technique":"Exploitation for Client Execution","technique_id":"T1203","severity":"CRITICAL","description":"Exploit"},
    "Fuzzers":    {"tactic":"Discovery","technique":"Network Service Discovery","technique_id":"T1046","severity":"MEDIUM","description":"Fuzzing"},
    "Generic":    {"tactic":"Initial Access","technique":"Exploit Public-Facing Application","technique_id":"T1190","severity":"HIGH","description":"Generic attack"},
    "Reconnaissance":{"tactic":"Reconnaissance","technique":"Active Scanning","technique_id":"T1595","severity":"MEDIUM","description":"Recon"},
    "Backdoor":   {"tactic":"Persistence","technique":"Web Shell","technique_id":"T1505.003","severity":"CRITICAL","description":"Backdoor"},
    "Shellcode":  {"tactic":"Execution","technique":"Native API","technique_id":"T1106","severity":"CRITICAL","description":"Shellcode"},
    "Worms":      {"tactic":"Lateral Movement","technique":"Replication","technique_id":"T1091","severity":"HIGH","description":"Worm"},
    "Analysis":   {"tactic":"Collection","technique":"Network Sniffing","technique_id":"T1040","severity":"MEDIUM","description":"Analysis"},
    "PortScan":   {"tactic":"Reconnaissance","technique":"Active Scanning","technique_id":"T1595","severity":"MEDIUM","description":"Port scan"},
    "BruteForce": {"tactic":"Credential Access","technique":"Brute Force","technique_id":"T1110","severity":"HIGH","description":"Brute force"},
    "WebAttack":  {"tactic":"Initial Access","technique":"Exploit Public-Facing Application","technique_id":"T1190","severity":"HIGH","description":"Web attack"},
    "Botnet":     {"tactic":"Command and Control","technique":"Application Layer Protocol","technique_id":"T1071","severity":"CRITICAL","description":"Botnet"},
    "Infiltration":{"tactic":"Defense Evasion","technique":"Masquerading","technique_id":"T1036","severity":"HIGH","description":"Infiltration"},
    "Tor":        {"tactic":"Defense Evasion","technique":"Multi-hop Proxy","technique_id":"T1090.003","severity":"HIGH","description":"Tor traffic"},
    "VPN":        {"tactic":"Defense Evasion","technique":"Proxy","technique_id":"T1090","severity":"MEDIUM","description":"VPN traffic"},
    "Attack":     {"tactic":"Various","technique":"Various","technique_id":"Various","severity":"HIGH","description":"Generic attack"},
}

# ── NSL-KDD setup ───────────────────────────────────────────────────
_NSLKDD_COLS = [
    'duration','protocol_type','service','flag','src_bytes','dst_bytes',
    'land','wrong_fragment','urgent','hot','num_failed_logins','logged_in',
    'num_compromised','root_shell','su_attempted','num_root','num_file_creations',
    'num_shells','num_access_files','num_outbound_cmds','is_host_login',
    'is_guest_login','count','srv_count','serror_rate','srv_serror_rate',
    'rerror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate',
    'srv_diff_host_rate','dst_host_count','dst_host_srv_count',
    'dst_host_same_srv_rate','dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate',
    'dst_host_serror_rate','dst_host_srv_serror_rate',
    'dst_host_rerror_rate','dst_host_srv_rerror_rate','label','difficulty']

_DOS   = {'back','land','neptune','pod','smurf','teardrop','apache2','udpstorm','processtable','mailbomb'}
_PROBE = {'ipsweep','mscan','nmap','portsweep','saint','satan'}
_R2L   = {'ftp_write','guess_passwd','imap','multihop','phf','spy','warezclient',
           'warezmaster','sendmail','named','snmpgetattack','snmpguess','worm','xlock','xsnoop','httptunnel'}
_U2R   = {'buffer_overflow','loadmodule','perl','ps','rootkit','sqlattack','xterm'}

def _lbl_kdd(l):
    l = str(l).strip().lower()
    if l == 'normal': return 'Normal'
    if l in _DOS:    return 'DoS'
    if l in _PROBE:  return 'Probe'
    if l in _R2L:    return 'R2L'
    if l in _U2R:    return 'U2R'
    return 'Attack'

def _lbl_cic(l):
    l = str(l).strip().upper()
    if l == 'BENIGN': return 'Normal'
    if 'DDOS' in l or 'DOS' in l: return 'DDoS'
    if 'PORT' in l: return 'PortScan'
    if 'BRUTE' in l or 'SSH' in l or 'FTP-PATATOR' in l: return 'BruteForce'
    if 'WEB' in l or 'SQL' in l or 'XSS' in l: return 'WebAttack'
    if 'BOT' in l: return 'Botnet'
    if 'INFILTRATION' in l: return 'Infiltration'
    return 'Attack'

def _lbl_darknet(l):
    l = str(l).strip().lower()
    if 'non-tor' in l: return 'Normal'
    if 'tor' in l:     return 'Tor'
    if 'vpn' in l:     return 'VPN'
    return 'Normal'

def _lbl_unsw(l):
    l = str(l).strip()
    return 'Normal' if not l or l.lower() in ('normal','none','nan','') else l.capitalize()

# ── HELPERS ─────────────────────────────────────────────────────────
def _clean(df):
    return df.replace([np.inf, -np.inf], np.nan).fillna(0)

def _pca_reduce(X, n=N_PCA):
    sc  = StandardScaler()
    Xs  = sc.fit_transform(X)
    nc  = min(n, X.shape[1], X.shape[0]-1)
    pca = PCA(n_components=nc, random_state=RANDOM_STATE)
    Xr  = pca.fit_transform(Xs)
    if Xr.shape[1] < n:
        Xr = np.hstack([Xr, np.zeros((Xr.shape[0], n-Xr.shape[1]))])
    return Xr, sc, pca

def _cap(X, y, cap=MAX_ROWS_DS):
    if len(X) > cap:
        idx = np.random.RandomState(RANDOM_STATE).choice(len(X), cap, replace=False)
        return X[idx], y[idx]
    return X, y

def _to_binary(y_enc, classes):
    normal_idx = [i for i,c in enumerate(classes) if c.lower()=='normal']
    return np.where(np.isin(y_enc, normal_idx), 0, 1)

# ── LOADERS ─────────────────────────────────────────────────────────
def load_nslkdd():
    p1 = os.path.join(DATASET_DIR,"nslkdd","KDDTrain+.txt")
    p2 = os.path.join(DATASET_DIR,"nslkdd","nsl-kdd","KDDTrain+.txt")
    p  = p1 if os.path.exists(p1) else p2
    if not os.path.exists(p):
        print("  [SKIP] NSL-KDD"); return None,None,None,None
    t1 = os.path.join(DATASET_DIR,"nslkdd","KDDTest+.txt")
    t2 = os.path.join(DATASET_DIR,"nslkdd","nsl-kdd","KDDTest+.txt")
    tp = t1 if os.path.exists(t1) else t2
    tr = pd.read_csv(p,  header=None, names=_NSLKDD_COLS)
    te = pd.read_csv(tp, header=None, names=_NSLKDD_COLS)
    df = pd.concat([tr,te], ignore_index=True)
    les = {}
    for c in ['protocol_type','service','flag']:
        le_cat = LabelEncoder()
        df[c] = le_cat.fit_transform(df[c].astype(str))
        les[c] = le_cat
    feat = [c for c in df.select_dtypes(include=[np.number]).columns if c not in ['label','difficulty']]
    X = _clean(df[feat]).values
    le = LabelEncoder(); y = le.fit_transform(df['label'].apply(_lbl_kdd))
    print(f"  NSL-KDD  : {len(X):>7,} rows | classes: {list(le.classes_)}")
    Xr,sc,pca = _pca_reduce(X); Xr,y = _cap(Xr,y)
    return Xr, y, le, {'sc':sc,'pca':pca,'feat':feat, 'les':les}

def load_unsw():
    tp = os.path.join(DATASET_DIR,"UNSW_NB15_training-set.csv")
    vp = os.path.join(DATASET_DIR,"UNSW_NB15_testing-set.csv")
    if not os.path.exists(tp):
        print("  [SKIP] UNSW-NB15"); return None,None,None,None
    df = pd.concat([pd.read_csv(tp), pd.read_csv(vp)], ignore_index=True)
    df.columns = df.columns.str.strip().str.replace('\ufeff','')
    les = {}
    for c in ['proto','service','state']:
        if c in df.columns:
            le_cat = LabelEncoder()
            df[c] = le_cat.fit_transform(df[c].astype(str))
            les[c] = le_cat
    feat = [c for c in df.select_dtypes(include=[np.number]).columns if c not in ['id','attack_cat','label']]
    X = _clean(df[feat]).values
    le = LabelEncoder(); y = le.fit_transform(df['attack_cat'].fillna('Normal').apply(_lbl_unsw))
    print(f"  UNSW-NB15: {len(X):>7,} rows | classes: {list(le.classes_)}")
    Xr,sc,pca = _pca_reduce(X); Xr,y = _cap(Xr,y)
    return Xr, y, le, {'sc':sc,'pca':pca,'feat':feat, 'les':les}

def load_cicids():
    seen, files = set(), []
    for fp in glob.glob(os.path.join(DATASET_DIR,"network_intrusion","*.csv")):
        bn = os.path.basename(fp)
        if bn not in seen: seen.add(bn); files.append(fp)
    for fname in ['Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv',
                  'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv',
                  'Friday-WorkingHours-Morning.pcap_ISCX.csv',
                  'Monday-WorkingHours.pcap_ISCX.csv']:
        fp = os.path.join(BASE_DIR, fname)
        if os.path.exists(fp) and fname not in seen:
            seen.add(fname); files.append(fp)
    if not files:
        print("  [SKIP] CIC-IDS2017"); return None,None,None,None
    chunks = []
    for fp in sorted(files):
        try:
            tmp = pd.read_csv(fp, low_memory=False, nrows=MAX_ROWS_FILE)
            tmp.columns = tmp.columns.str.strip()
            chunks.append(tmp)
        except Exception as e:
            print(f"    [WARN] {os.path.basename(fp)}: {e}")
    df = pd.concat(chunks, ignore_index=True)
    lc = next((c for c in df.columns if c.strip().lower()=='label'), None)
    if lc is None:
        print("  [SKIP] CIC-IDS no label"); return None,None,None,None
    feat = [c for c in df.select_dtypes(include=[np.number]).columns if c != lc]
    X = _clean(df[feat]).values
    le = LabelEncoder(); y = le.fit_transform(df[lc].apply(_lbl_cic))
    print(f"  CIC-IDS  : {len(X):>7,} rows | classes: {list(le.classes_)}")
    Xr,sc,pca = _pca_reduce(X); Xr,y = _cap(Xr,y)
    return Xr, y, le, {'sc':sc,'pca':pca,'feat':feat}

def load_darknet():
    fp = os.path.join(DATASET_DIR,"Darknet.CSV")
    if not os.path.exists(fp):
        print("  [SKIP] Darknet"); return None,None,None,None
    df = pd.read_csv(fp, low_memory=False, on_bad_lines='skip', nrows=80_000)
    df.columns = df.columns.str.strip()
    df = df.drop(columns=[c for c in ['Flow ID','Src IP','Dst IP','Timestamp'] if c in df.columns], errors='ignore')
    lbls = [c for c in df.columns if c.strip().lower()=='label']
    if not lbls:
        print("  [SKIP] Darknet no label"); return None,None,None,None
    lc = lbls[0]
    feat = [c for c in df.select_dtypes(include=[np.number]).columns if c not in lbls]
    X = _clean(df[feat]).values
    le = LabelEncoder(); y = le.fit_transform(df[lc].apply(_lbl_darknet))
    print(f"  Darknet  : {len(X):>7,} rows | classes: {list(le.classes_)}")
    Xr,sc,pca = _pca_reduce(X); Xr,y = _cap(Xr,y)
    return Xr, y, le, {'sc':sc,'pca':pca,'feat':feat}

# ── MAIN ────────────────────────────────────────────────────────────
def train():
    t0 = datetime.now()
    print("="*60)
    print("  SIEM MULTI-DATASET TRAINER  (FAST — target 95%+)")
    print("="*60)

    print("\n[1/4] Loading all datasets...")
    loaders = [("NSL-KDD",load_nslkdd),("UNSW-NB15",load_unsw),
               ("CIC-IDS2017",load_cicids),("Darknet",load_darknet)]
    datasets, pipelines = [], {}
    for name, fn in loaders:
        Xr, y, le, pipe = fn()
        if Xr is None: continue
        yb = _to_binary(y, list(le.classes_))
        datasets.append((name, Xr, yb))
        pipelines[name] = pipe
        n_pct = 100*(yb==0).mean(); a_pct = 100*(yb==1).mean()
        print(f"    {name}: {len(Xr):,} samples | Normal={n_pct:.1f}% Attack={a_pct:.1f}%")

    X = np.vstack([d[1] for d in datasets])
    y = np.hstack([d[2] for d in datasets])
    print(f"\n  COMBINED: {len(X):,} samples x {X.shape[1]} features")

    print("\n[2/4] Train/test split 80/20...")
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2,
                                               random_state=RANDOM_STATE, stratify=y)
    sc = StandardScaler()
    X_tr = sc.fit_transform(X_tr)
    X_te = sc.transform(X_te)

    print(f"\n[3/4] Training RandomForest ({N_TREES} trees, all CPU cores)...")
    model = RandomForestClassifier(
        n_estimators=N_TREES, max_depth=20, min_samples_split=5,
        n_jobs=-1, random_state=RANDOM_STATE, class_weight='balanced')
    model.fit(X_tr, y_tr)

    y_pred = model.predict(X_te)
    acc = accuracy_score(y_te, y_pred)
    print(f"\n[4/4] Saving...")

    # save all artifacts
    pickle.dump(model,          open(MODEL_PATH,   'wb'))
    pickle.dump(sc,             open(SCALER_PATH,  'wb'))
    pickle.dump({'binary':True, 'cat_cols':{},
                 'cat_encoder': LabelEncoder().fit(['Normal','Attack'])},
                open(ENCODER_PATH, 'wb'))
    pickle.dump(MITRE_MAPPING,  open(MITRE_PATH,   'wb'))
    pickle.dump([f"pca_f{i}" for i in range(X.shape[1])], open(FEATURE_PATH, 'wb'))
    pickle.dump({'pipelines': pipelines, 'final_scaler': sc}, open(PIPELINE_PATH, 'wb'))

    elapsed = (datetime.now()-t0).seconds
    print("\n" + "="*60)
    print(f"  ACCURACY  : {acc*100:.2f}%   {'[TARGET MET]' if acc>=0.95 else '[below target]'}")
    print(f"  Samples   : {len(X):,}  (train={len(X_tr):,} test={len(X_te):,})")
    print(f"  Datasets  : {[d[0] for d in datasets]}")
    print(f"  Time      : {elapsed}s")
    print("="*60)
    print("\n  Per-class Report:")
    print(classification_report(y_te, y_pred, target_names=['Normal','Attack']))
    print(f"\n[DONE] Model saved -> {MODEL_PATH}")

    return {"accuracy": round(acc,4), "target_met": acc>=0.95,
            "n_samples": len(X), "elapsed_sec": elapsed,
            "datasets": [d[0] for d in datasets]}

if __name__ == "__main__":
    r = train()
    print(f"\nFinal accuracy: {r['accuracy']*100:.2f}%")
