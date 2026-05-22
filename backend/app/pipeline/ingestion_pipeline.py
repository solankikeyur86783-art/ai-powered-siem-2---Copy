"""
Ingestion Pipeline — the heart of the SIEM.
Flow: Raw Log → Parse → Rules → Correlate → ML Score → LLM Analyze → Store → Alert
"""
import asyncio
from datetime import datetime
from typing import Dict, Any, Optional
from loguru import logger
from bson import ObjectId

from app.database.db import col
from app.core.log_parser import auto_parse
from app.core.rule_engine import run_rules
from app.core.correlator import correlator
from app.services.llm_service import llm_service
from app.services.threat_intel import threat_intel
from ml_model.predictor import predict_attack


class IngestionPipeline:
    def __init__(self):
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=10000)
        self._running = False
        self._stats = {"processed": 0, "threats": 0, "alerts": 0, "errors": 0}

    async def ingest(self, raw_data: Dict[str, Any]) -> str:
        """Add a log to the processing queue. Returns log_id."""
        await self._queue.put(raw_data)
        return "queued"

    async def ingest_sync(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process a log synchronously and return result immediately."""
        return await self._process_log(raw_data)

    async def start(self):
        """Start the background processing loop"""
        self._running = True
        logger.info("🚀 Ingestion pipeline started")
        asyncio.create_task(self._process_loop())

    async def stop(self):
        self._running = False
        logger.info("Ingestion pipeline stopped")

    async def _process_loop(self):
        while self._running:
            try:
                raw = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                await self._process_log(raw)
                self._queue.task_done()
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Pipeline error: {e}")
                self._stats["errors"] += 1

    async def _process_log(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        result = {"log_id": None, "threat_id": None, "alert_id": None, "threat_detected": False}
        try:
            # ── Step 1: Parse ────────────────────────────────
            parsed = auto_parse(raw_data)
            if not parsed:
                return result

            # ── Step 2: Store raw log ────────────────────────
            log_doc = {**parsed, "ingested_at": datetime.utcnow()}
            insert = await col("raw_logs").insert_one(log_doc)
            log_id = str(insert.inserted_id)
            result["log_id"] = log_id
            self._stats["processed"] += 1

            # ── Step 3: Rule Engine ──────────────────────────
            rule_match = run_rules(parsed)

            # ── Step 4: Correlator ───────────────────────────
            correlation = correlator.process(parsed)

            # ── Step 4.5: ML Anomaly Detection ───────────────
            ml_result = None
            try:
                # Only run ML on network-like data or if it has required fields
                if "proto" in parsed or "service" in parsed:
                    ml_result = predict_attack(parsed)
            except Exception as ml_err:
                logger.debug(f"ML prediction skipped: {ml_err}")

            # ── Step 5: If threat detected (Rule, Correlation, or ML) ────
            if rule_match or correlation or (ml_result and ml_result.get("attack_type") != "Normal" and ml_result.get("confidence", 0) >= 0.25):
                threat_data = rule_match or correlation or {
                    "threat_type": ml_result["attack_type"],
                    "severity": ml_result["severity"].lower(),
                    "mitre_tactic": ml_result["mitre_tactic"],
                    "mitre_technique": ml_result["mitre_technique"],
                    "description": f"AI Detected {ml_result['attack_type']}: {ml_result['description']}",
                    "confidence": ml_result["confidence"]
                }
                severity = threat_data.get("severity", "medium")

                # LLM analysis (only for high/critical to save API calls)
                llm_result = None
                if severity in ["high", "critical"]:
                    try:
                        llm_result = await asyncio.wait_for(
                            llm_service.analyze_threat(parsed, str(threat_data)),
                            timeout=10.0
                        )
                        # Upgrade severity if LLM says so
                        if llm_result.get("severity") in ["high", "critical"]:
                            severity = llm_result["severity"]
                    except asyncio.TimeoutError:
                        logger.warning("LLM analysis timed out — using rule-based result")

                # Enrich with GeoIP for Threat Map
                geo = {}
                if parsed.get("source_ip"):
                    try:
                        geo = await threat_intel.get_geoip(parsed["source_ip"])
                    except Exception as geo_err:
                        logger.debug(f"GeoIP enrichment failed: {geo_err}")

                # Store threat log
                threat_doc = {
                    "timestamp": parsed["timestamp"],
                    "raw_log_id": log_id,
                    "source_ip": parsed.get("source_ip"),
                    "dest_ip": parsed.get("dest_ip"),
                    "hostname": parsed.get("hostname", "unknown"),
                    "threat_type": threat_data.get("threat_type", "unknown"),
                    "severity": severity,
                    "ml_score": ml_result.get("confidence") if ml_result else (llm_result.get("confidence", 0.0) if llm_result else 0.5),
                    "rule_matched": threat_data.get("rule_name") or threat_data.get("correlation_type") or "ml_model_prediction",
                    "description": threat_data.get("description", ""),
                    "llm_analysis": llm_result.get("summary") if llm_result else None,
                    "status": "open",
                    "mitre_tactic": threat_data.get("mitre_tactic"),
                    "mitre_technique": threat_data.get("mitre_technique"),
                    "created_at": datetime.utcnow(),
                    "country": geo.get("country", "Unknown"),
                    "country_code": geo.get("country_code", ""),
                    "lat": geo.get("lat"),
                    "lon": geo.get("lon"),
                }
                threat_insert = await col("threat_logs").insert_one(threat_doc)
                threat_id = str(threat_insert.inserted_id)
                result["threat_id"] = threat_id
                result["threat_detected"] = True
                self._stats["threats"] += 1

                # ── Step 6: Create Alert ─────────────────────
                alert_doc = {
                    "created_at": datetime.utcnow(),
                    "updated_at": datetime.utcnow(),
                    "title": _make_alert_title(threat_data),
                    "description": threat_data.get("description", ""),
                    "severity": severity,
                    "status": "open",
                    "rule_id": threat_data.get("rule_name") or threat_data.get("correlation_type"),
                    "threat_log_id": threat_id,
                    "source_ip": parsed.get("source_ip"),
                    "hostname": parsed.get("hostname", "unknown"),
                    "llm_summary": llm_result.get("summary") if llm_result else None,
                    "recommended_actions": llm_result.get("recommended_actions", []) if llm_result else [],
                    "tags": [threat_data.get("threat_type", "unknown"), severity]
                }
                alert_insert = await col("alerts").insert_one(alert_doc)
                result["alert_id"] = str(alert_insert.inserted_id)
                self._stats["alerts"] += 1

                logger.warning(
                    f"🚨 [{severity.upper()}] {threat_data.get('threat_type')} "
                    f"from {parsed.get('source_ip', 'unknown')} on {parsed.get('hostname', 'unknown')}"
                )

                # ── Step 7: Send Notifications ──────────────
                try:
                    from app.services.notifications import notification_manager
                    asyncio.create_task(notification_manager.notify(alert_doc))
                except Exception as notify_err:
                    logger.debug(f"Notification skipped: {notify_err}")

                # ── Step 8: Auto-Trigger AI Agents (Background) ──
                try:
                    agent_alert = {**alert_doc, "id": result["alert_id"]}
                    # Remove non-serializable fields
                    agent_alert.pop("_id", None)
                    asyncio.create_task(self._run_agents_background(agent_alert))
                    logger.info(f"🤖 Agents auto-triggered for alert {result['alert_id']}")
                except Exception as agent_err:
                    logger.debug(f"Agent auto-trigger skipped: {agent_err}")

        except Exception as e:
            logger.error(f"Log processing error: {e}")
            self._stats["errors"] += 1

        return result

    async def _run_agents_background(self, alert: Dict[str, Any]):
        """Run the agent pipeline in the background without blocking ingestion."""
        try:
            from agents.agent_manager import agent_manager
            await agent_manager.handle_alert(alert)
        except Exception as e:
            logger.error(f"Background agent pipeline error: {e}")

    def get_stats(self) -> Dict[str, Any]:
        return {**self._stats, "queue_size": self._queue.qsize()}


def _make_alert_title(threat_data: Dict) -> str:
    t = threat_data.get("threat_type", "Unknown Threat")
    titles = {
        "brute_force": "Brute Force Attack Detected",
        "port_scan": "Port Scan Activity Detected",
        "malware": "Malware Indicator Detected",
        "privilege_escalation": "Privilege Escalation Detected",
        "data_exfiltration": "Potential Data Exfiltration",
        "lateral_movement": "Lateral Movement Detected",
        "anomaly": "Anomalous Behavior Detected",
    }
    return titles.get(t, f"Security Threat: {t.replace('_', ' ').title()}")


# Singleton
pipeline = IngestionPipeline()
