"""
AI-Powered SIEM Platform v3.0 — Main Entry Point
"""
import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from loguru import logger
import json
from datetime import datetime

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # project root
from ml_model.predictor import predict_attack

from app.config import get_settings
from app.database.db import connect_db, disconnect_db
from app.database.indices import create_indices
from app.pipeline.ingestion_pipeline import pipeline
from app.core.log_receiver import receiver, syslog_receiver
from app.core.correlator import correlator
from app.core.auth_middleware import create_default_admin
from app.api import logs, alerts, agents, response
from app.api import auth, notification_api, intel_api, report_api, rules_api
from app.api import ai_api, honeypot_api, forensics_api, hunt_api
from app.api import tor_api
from app.database.db import col

settings = get_settings()

# ── WebSocket Manager ────────────────────────────────────
class WSManager:
    def __init__(self):
        self.connections: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.connections.append(ws)
        logger.info(f"WS client connected (total: {len(self.connections)})")

    def disconnect(self, ws: WebSocket):
        self.connections.remove(ws)
        logger.info(f"WS client disconnected (total: {len(self.connections)})")

    async def broadcast(self, data: dict):
        dead = []
        for ws in self.connections:
            try:
                await ws.send_text(json.dumps(data, default=str))
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.connections.remove(ws)

ws_manager = WSManager()


# ── Background Tasks ─────────────────────────────────────
async def live_stats_broadcaster():
    """Broadcast live stats to all WebSocket clients every 3 seconds"""
    while True:
        try:
            if ws_manager.connections:
                now = datetime.utcnow()
                from datetime import timedelta
                since = now - timedelta(hours=24)

                total_logs = await col("raw_logs").count_documents({"timestamp": {"$gte": since}})
                open_alerts = await col("alerts").count_documents({"status": "open"})
                threats_today = await col("threat_logs").count_documents({"timestamp": {"$gte": since}})
                critical = await col("alerts").count_documents({"severity": "critical", "status": "open"})

                # Latest alert
                latest_cursor = col("alerts").find().sort("created_at", -1).limit(1)
                latest = None
                async for doc in latest_cursor:
                    doc["id"] = str(doc.pop("_id", ""))
                    latest = doc

                await ws_manager.broadcast({
                    "type": "live_stats",
                    "data": {
                        "total_logs_today": total_logs,
                        "open_alerts": open_alerts,
                        "threats_today": threats_today,
                        "critical_alerts": critical,
                        "pipeline": pipeline.get_stats(),
                        "latest_alert": latest,
                        "timestamp": now.isoformat()
                    }
                })
        except Exception as e:
            logger.error(f"Stats broadcast error: {e}")
        await asyncio.sleep(3)


async def correlator_cleanup():
    """Clean up old correlator state every 10 minutes"""
    while True:
        await asyncio.sleep(600)
        correlator.cleanup()


async def anomaly_scanner():
    """Run anomaly detection every 15 minutes"""
    await asyncio.sleep(60)  # Wait 1 min after startup
    while True:
        try:
            from app.services.anomaly_detector import anomaly_detector
            anomalies = await anomaly_detector.check_anomalies()
            if anomalies:
                logger.warning(f"🔍 {len(anomalies)} anomalies detected")
                # Notify via WebSocket
                await ws_manager.broadcast({
                    "type": "anomaly_alert",
                    "data": {"count": len(anomalies), "anomalies": anomalies}
                })
        except Exception as e:
            logger.error(f"Anomaly scan error: {e}")
        await asyncio.sleep(900)  # Every 15 minutes


# ── App Lifecycle ────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🔥 Starting AI-Powered SIEM Platform v3.0...")
    await connect_db()
    await create_indices()
    await create_default_admin()
    await pipeline.start()
    await receiver.start()
    await syslog_receiver.start()
    asyncio.create_task(live_stats_broadcaster())
    asyncio.create_task(correlator_cleanup())
    asyncio.create_task(anomaly_scanner())
    # Tor detection — start feed refresh loop
    from app.services.tor_detection import tor_detection
    asyncio.create_task(tor_detection.auto_refresh_loop())
    logger.info("🧅 Tor exit-node feed refresh task started")
    logger.success("✅ SIEM Platform v3.0 fully operational")
    yield
    logger.info("Shutting down SIEM Platform...")
    # Stop honeypots if running
    try:
        from app.services.honeypot import honeypot_service
        await honeypot_service.stop_all()
    except Exception:
        pass
    await pipeline.stop()
    await receiver.stop()
    await syslog_receiver.stop()
    await disconnect_db()


# ── FastAPI App ──────────────────────────────────────────
app = FastAPI(
    title="AI-Powered SIEM Platform",
    description="Security Information and Event Management with AI/LLM threat detection",
    version="3.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173", "http://127.0.0.1:3000", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ──────────────────────────────────────────────
# Existing
app.include_router(logs.router)
app.include_router(alerts.router)
app.include_router(agents.router)
app.include_router(response.router)

# v3.0 — New routers
app.include_router(auth.router)
app.include_router(notification_api.router)
app.include_router(intel_api.router)
app.include_router(report_api.router)
app.include_router(rules_api.router)
app.include_router(ai_api.router)
app.include_router(honeypot_api.router)
app.include_router(forensics_api.router)
app.include_router(hunt_api.router)
app.include_router(tor_api.router)


# ── WebSocket ────────────────────────────────────────────
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Handle client messages if needed
            msg = json.loads(data)
            if msg.get("type") == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)



# ── Health & Dashboard ───────────────────────────────────
@app.get("/health")
async def health():
    return {
        "status": "operational",
        "version": "3.0.0",
        "pipeline": pipeline.get_stats(),
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/api/dashboard")
async def dashboard_stats(hours: int = 24, severity: str = None):
    from datetime import timedelta
    now = datetime.utcnow()
    since_24h = now - timedelta(hours=hours)
    since_1h = now - timedelta(hours=1)

    # Counts
    total_logs = await col("raw_logs").count_documents({"timestamp": {"$gte": since_24h}})
    threats_today = await col("threat_logs").count_documents({"timestamp": {"$gte": since_24h}})
    open_alerts = await col("alerts").count_documents({"status": "open"})
    critical = await col("alerts").count_documents({"severity": "critical", "status": "open"})
    high = await col("alerts").count_documents({"severity": "high", "status": "open"})
    medium = await col("alerts").count_documents({"severity": "medium", "status": "open"})
    low = await col("alerts").count_documents({"severity": "low", "status": "open"})
    logs_last_hour = await col("raw_logs").count_documents({"timestamp": {"$gte": since_1h}})

    # Hourly log trend — include full date+hour so different days don't merge
    hourly_agg = [
        {"$match": {"timestamp": {"$gte": since_24h}}},
        {"$group": {
            "_id": {"$dateToString": {"format": "%Y-%m-%d %H:00", "date": "$timestamp"}},
            "count": {"$sum": 1}
        }},
        {"$sort": {"_id": 1}}
    ]
    hourly = [{"hour": d["_id"], "count": d["count"]}
              async for d in col("raw_logs").aggregate(hourly_agg)]

    # Threat distribution
    threat_agg = [
        {"$match": {"timestamp": {"$gte": since_24h}}},
        {"$group": {"_id": "$threat_type", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]
    threat_dist = [{"type": d["_id"], "count": d["count"]}
                   async for d in col("threat_logs").aggregate(threat_agg)]

    # Top attacking IPs — optionally filter by severity
    ip_match = {"timestamp": {"$gte": since_24h}, "source_ip": {"$ne": None}}
    if severity and severity.lower() not in ('all', ''):
        ip_match["severity"] = severity.lower()
    ip_agg = [
        {"$match": ip_match},
        {"$group": {"_id": "$source_ip", "count": {"$sum": 1}, "severity": {"$max": "$severity"}}},
        {"$sort": {"count": -1}},
        {"$limit": 10}
    ]
    top_ips = [{"ip": d["_id"], "count": d["count"], "severity": d["severity"]}
               async for d in col("threat_logs").aggregate(ip_agg)]

    # Recent alerts
    recent_cursor = col("alerts").find().sort("created_at", -1).limit(10)
    recent_alerts = []
    async for doc in recent_cursor:
        doc["id"] = str(doc.pop("_id", ""))
        recent_alerts.append(doc)

    # Recent agent actions
    agent_cursor = col("agent_actions").find().sort("timestamp", -1).limit(5)
    recent_actions = []
    async for doc in agent_cursor:
        doc["id"] = str(doc.pop("_id", ""))
        recent_actions.append(doc)

    # v3.0 — Anomaly count
    anomaly_count = await col("anomalies").count_documents({
        "detected_at": {"$gte": since_24h}, "resolved": False
    })

    # v3.0 — Honeypot captures
    honeypot_count = await col("honeypot_captures").count_documents({
        "timestamp": {"$gte": since_24h}
    })

    return {
        "counts": {
            "total_logs_today": total_logs,
            "threats_today": threats_today,
            "open_alerts": open_alerts,
            "critical_alerts": critical,
            "high_alerts": high,
            "medium_alerts": medium,
            "low_alerts": low,
            "logs_last_hour": logs_last_hour,
            "anomalies": anomaly_count,
            "honeypot_captures": honeypot_count,
        },
        "hourly_logs": hourly,
        "threat_distribution": threat_dist,
        "top_attacking_ips": top_ips,
        "recent_alerts": recent_alerts,
        "recent_agent_actions": recent_actions,
        "pipeline_stats": pipeline.get_stats(),
        "generated_at": now.isoformat()
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        log_level="info"
    )
