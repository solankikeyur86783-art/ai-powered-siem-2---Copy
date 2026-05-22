"""
AI & ML API — Anomaly detection, model management, deep analysis
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from datetime import datetime
from app.services.anomaly_detector import anomaly_detector
from app.services.advanced_ai import advanced_ai
from app.core.auth_middleware import get_current_user
from app.database.db import col
from ml_model.predictor import get_model_info, predict_attack

router = APIRouter(prefix="/api/ai", tags=["AI & ML"])


@router.get("/anomalies")
async def get_anomalies(
    hours: int = Query(24, ge=1, le=168),
    user: dict = Depends(get_current_user)
):
    """Get recent detected anomalies"""
    anomalies = await anomaly_detector.get_recent_anomalies(hours)
    return {"anomalies": anomalies, "total": len(anomalies)}


@router.post("/anomalies/scan")
async def run_anomaly_scan(user: dict = Depends(get_current_user)):
    """Trigger an anomaly scan now — Fixed v5 (Multi-source)"""
    try:
        # Run statistical checks in background
        await anomaly_detector.check_anomalies()

        # ── Pull from ALL sources, not just winlogbeat ──
        cursor = col("raw_logs").find().sort("timestamp", -1).limit(25)
        logs_found = []
        async for doc in cursor:
            # We'll keep the ID for the frontend mapping but pop it from the log itself if needed
            doc["id"] = str(doc.get("_id"))
            logs_found.append(doc)

        if not logs_found:
            return {"status": "ok", "source": "empty_db", "predictions": [], "logs_scanned": 0, "threats_found": 0, "total_predictions": 0}

        SAFE_EVENT_IDS = {4624, 4634, 4648, 4672, 4776, 4797, 5156, 7036, 4800, 4801}

        SUSPICIOUS_FEATURES = {
            4625: {"spkts":80,  "sbytes":3200,  "sttl":62,  "state":"REQ","ct_srv_src":50, "sloss":20, "rate":5000.0},
            4740: {"spkts":200, "sbytes":8000,  "sttl":62,  "state":"INT","ct_srv_src":100,"sloss":50, "rate":20000.0},
            4720: {"spkts":25,  "sbytes":5000,  "sttl":252, "state":"CON","ct_srv_src":10, "ct_dst_src_ltm":12},
            4732: {"spkts":25,  "sbytes":5000,  "sttl":252, "state":"CON","ct_srv_src":10, "ct_dst_src_ltm":8},
            7045: {"spkts":40,  "sbytes":12000, "sttl":252, "state":"CON","ct_srv_src":15, "ct_dst_src_ltm":15,"smean":500},
            5157: {"spkts":30,  "sbytes":1200,  "sttl":62,  "state":"REQ","ct_srv_src":30, "sloss":5},
            4688: {"spkts":20,  "sbytes":6000,  "sttl":252, "state":"CON","ct_srv_src":5,  "smean":300},
            4698: {"spkts":30,  "sbytes":8000,  "sttl":252, "state":"CON","ct_srv_src":8,  "ct_dst_src_ltm":10},
            4657: {"spkts":20,  "sbytes":4500,  "sttl":252, "state":"CON","ct_srv_src":8},
            1:    {"spkts":20,  "sbytes":6000,  "sttl":252, "state":"CON","ct_srv_src":5,  "smean":300},  # Sysmon Process Create
            3:    {"spkts":15,  "sbytes":3000,  "sttl":62,  "state":"CON","ct_srv_src":8},               # Sysmon Network Connect
            5140: {"spkts":15,  "sbytes":4000,  "sttl":128, "state":"CON","ct_srv_src":5},               # Network share access
        }

        predictions = []

        for log in logs_found:
            # ── FIX 1: Extract event_id from ALL possible field formats ──
            winlog = log.get("winlog") if isinstance(log.get("winlog"), dict) else {}
            raw_eid = (
                log.get("event_id") or
                log.get("EventID") or
                log.get("event_code") or
                winlog.get("event_id") or
                0
            )
            # Handle string formats like "EventID 4624"
            if isinstance(raw_eid, str):
                raw_eid = raw_eid.replace("EventID", "").replace("event_id", "").strip()
                try:
                    event_id = int(raw_eid)
                except:
                    event_id = 0
            else:
                try:
                    event_id = int(raw_eid)
                except:
                    event_id = 0

            # ── FIX 2: Extract fields from ALL source formats ──
            log_source = str(log.get("source") or log.get("log_source") or "unknown")

            # IPs — check nested fields too
            src_ip = (
                log.get("source_ip") or log.get("src_ip") or log.get("srcip") or
                log.get("client_ip") or
                winlog.get("event_data", {}).get("IpAddress") or
                (log.get("event_data") if isinstance(log.get("event_data"), dict) else {}).get("IpAddress") or
                (log.get("raw") if isinstance(log.get("raw"), dict) else {}).get("source_ip") or
                "unknown"
            )
            dst_ip = (
                log.get("dest_ip") or log.get("dst_ip") or log.get("destination_ip") or 
                (log.get("raw") if isinstance(log.get("raw"), dict) else {}).get("dest_ip") or
                "unknown"
            )

            src_port = int(log.get("source_port") or log.get("src_port") or 0)
            dst_port = int(log.get("dest_port")   or log.get("dst_port") or 0)
            hostname = (
                log.get("hostname") or log.get("host") or log.get("computer_name") or
                winlog.get("computer_name") or "unknown"
            )
            message  = str(log.get("message") or log.get("msg") or "")
            log_level = str(log.get("log_level") or log.get("level") or log.get("severity") or "INFO").upper()

            # Shared metadata
            meta = {
                "id":          log.get("id"),
                "source_ip":   src_ip,
                "dest_ip":     dst_ip,
                "source_port": src_port,
                "dest_port":   dst_port,
                "event_id":    event_id,
                "hostname":    str(hostname),
                "message":     message[:300],
                "timestamp":   str(log.get("timestamp", "")),
                "log_source":  log_source,
            }

            # PATH A — Known safe → skip ML
            if event_id in SAFE_EVENT_IDS:
                predictions.append({
                    "attack_type":     "Normal",
                    "confidence":      0.95,
                    "severity":        "INFO",
                    "mitre_tactic":    "None",
                    "mitre_technique": "None",
                    "technique_id":    "None",
                    "description":     "Normal system activity — no threat detected.",
                    "risk_level":      "normal",
                    **meta
                })
                continue

            # PATH B — Suspicious → run ML
            override = SUSPICIOUS_FEATURES.get(event_id, {})
            if not override:
                if log_level in ["CRITICAL", "ERROR"]:
                    override = {"spkts":60,"sbytes":5000,"sttl":62,"state":"INT","sloss":8,"ct_srv_src":10}
                elif log_level == "WARNING":
                    override = {"spkts":20,"sbytes":2000,"sttl":62,"state":"CON","ct_srv_src":5}
                else:
                    predictions.append({
                        "attack_type":     "Normal",
                        "confidence":      0.80,
                        "severity":        "INFO",
                        "mitre_tactic":    "None",
                        "mitre_technique": "None",
                        "technique_id":    "None",
                        "description":     "Normal activity detected from log source.",
                        "risk_level":      "normal",
                        **meta
                    })
                    continue

            # Build ML features
            PORT_SERVICE = {21:"ftp",22:"ssh",23:"telnet",25:"smtp",53:"dns",
                           80:"http",443:"https",445:"smb",3306:"mysql",3389:"rdp"}
            service = PORT_SERVICE.get(dst_port, "-")
            proto   = "udp" if dst_port in [53,67,68,123,161] else "tcp"

            features = {
                "dur":0.0,"proto":proto,"service":service,
                "state":override.get("state","FIN"),
                "spkts":override.get("spkts",5),"dpkts":3,
                "sbytes":override.get("sbytes",500),"dbytes":300,
                "rate":override.get("rate",100.0),
                "sttl":override.get("sttl",62),"dttl":62,
                "sload":0.0,"dload":0.0,
                "sloss":override.get("sloss",0),"dloss":0,
                "sinpkt":0.0,"dinpkt":0.0,"sjit":0.0,"djit":0.0,
                "swin":255,"dwin":255,"stcpb":0,"dtcpb":0,
                "tcprtt":0.0,"synack":0.0,"ackdat":0.0,
                "smean":override.get("smean",100),"dmean":80,
                "trans_depth":0,"response_body_len":0,
                "ct_srv_src":override.get("ct_srv_src",1),
                "ct_state_ttl":2,"ct_dst_ltm":1,
                "ct_src_dport_ltm":1,"ct_dst_sport_ltm":1,
                "ct_dst_src_ltm":override.get("ct_dst_src_ltm",1),
                "ct_src_ltm":1,"ct_srv_dst":1,
                "is_ftp_login":1 if dst_port==21 else 0,
                "ct_ftp_cmd":3 if dst_port==21 else 0,
                "ct_flw_http_mthd":1 if dst_port in [80,8080] else 0,
                "is_sm_ips_ports":0,
            }

            result = predict_attack(features)
            result["risk_level"] = "high"
            predictions.append({**result, **meta})

        # Sort by severity
        sev_order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
        predictions.sort(key=lambda x: sev_order.get(x.get("severity","INFO"), 5))

        real_threats = [p for p in predictions if p["attack_type"] != "Normal" and p["confidence"] >= 0.25]

        return {
            "status":            "ok",
            "source":            "live_db",
            "logs_scanned":      len(logs_found),
            "threats_found":     len(real_threats),
            "total_predictions": len(predictions),
            "predictions":       predictions,
        }

    except Exception as e:
        import traceback
        raise HTTPException(status_code=500, detail={"error": str(e), "trace": traceback.format_exc()})


@router.post("/anomalies/{anomaly_id}/resolve")
async def resolve_anomaly(anomaly_id: str, user: dict = Depends(get_current_user)):
    await anomaly_detector.resolve_anomaly(anomaly_id)
    return {"success": True}


@router.delete("/anomalies/{anomaly_id}")
async def dismiss_anomaly(anomaly_id: str, user: dict = Depends(get_current_user)):
    """Permanently delete an anomaly"""
    await anomaly_detector.delete_anomaly(anomaly_id)
    return {"success": True}


@router.get("/model/status")
async def model_status(user: dict = Depends(get_current_user)):
    """Get ML model status"""
    info = get_model_info()
    if not info:
        return {
            "status": "not_trained",
            "message": "Model not found. Run training first."
        }
    # Get model version history
    versions = []
    cursor = col("model_versions").find().sort("trained_at", -1).limit(10)
    async for doc in cursor:
        doc["id"] = str(doc.pop("_id"))
        versions.append(doc)

    return {
        "status": "active",
        "current_model": info,
        "versions": versions,
    }


@router.post("/model/retrain")
async def retrain_model(user: dict = Depends(get_current_user)):
    """Trigger ML model retraining"""
    try:
        import asyncio
        import os
        from pathlib import Path
        from ml_model.train_model import train

        # train() uses relative paths from project root, not backend/
        project_root = str(Path(__file__).resolve().parents[3])

        def run_training():
            old_cwd = os.getcwd()
            try:
                os.chdir(project_root)
                return train()
            finally:
                os.chdir(old_cwd)

        # Run training in executor to not block event loop
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, run_training)

        if not result or "error" in result:
            raise HTTPException(500, f"Training returned error: {result}")

        # Save version
        version = {
            "trained_at": datetime.utcnow(),
            "accuracy": result.get("accuracy"),
            "n_samples": result.get("n_samples"),
            "triggered_by": user.get("username", "system"),
        }
        await col("model_versions").insert_one(version)

        return {"success": True, "model": {
            "accuracy": result.get("accuracy"),
            "n_samples": result.get("n_samples"),
            "trained_at": datetime.utcnow().isoformat(),
        }}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Retraining failed: {str(e)}")


@router.post("/analyze/deep/{alert_id}")
async def deep_analysis(alert_id: str, user: dict = Depends(get_current_user)):
    """Deep AI analysis of an alert"""
    result = await advanced_ai.deep_analyze(alert_id)
    if "error" in result:
        raise HTTPException(404, result["error"])
    return result


@router.get("/risk-scores")
async def get_risk_scores(
    hours: int = Query(24, ge=1, le=168),
    user: dict = Depends(get_current_user)
):
    """Get risk scores for recent alerts"""
    scores = await advanced_ai.get_risk_scores(hours)
    return {"scores": scores, "total": len(scores)}
