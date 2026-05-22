"""
Anomaly Detection Service — Statistical + ML-based anomaly detection
"""
import asyncio
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, Any, List
from loguru import logger
from app.database.db import col


class AnomalyDetector:
    """Detect anomalies in log patterns using statistical methods"""

    def __init__(self):
        self._baselines = {}
        self._last_update = None

    async def check_anomalies(self) -> List[Dict[str, Any]]:
        """Run all anomaly checks and return detected anomalies"""
        anomalies = []

        # Check 1: Log volume spike
        vol_anomaly = await self._check_volume_spike()
        if vol_anomaly:
            anomalies.append(vol_anomaly)

        # Check 2: Unusual event IDs
        event_anomaly = await self._check_unusual_events()
        if event_anomaly:
            anomalies.append(event_anomaly)

        # Check 3: New source IPs (never seen before)
        ip_anomaly = await self._check_new_ips()
        if ip_anomaly:
            anomalies.append(ip_anomaly)

        # Check 4: Off-hours activity
        hours_anomaly = await self._check_off_hours()
        if hours_anomaly:
            anomalies.append(hours_anomaly)

        # Check 5: Threat rate spike
        threat_anomaly = await self._check_threat_rate()
        if threat_anomaly:
            anomalies.append(threat_anomaly)

        # Store anomalies
        if anomalies:
            for a in anomalies:
                a["detected_at"] = datetime.utcnow()
                a["resolved"] = False
            
            try:
                await col("anomalies").insert_many(anomalies)
                # Convert ObjectIds to strings for API response compatibility
                for a in anomalies:
                    if "_id" in a:
                        a["id"] = str(a.pop("_id"))
            except Exception as e:
                logger.error(f"Failed to store anomalies: {e}")

        return anomalies

    async def _check_volume_spike(self) -> Dict[str, Any] | None:
        """Detect unusual log volume compared to baseline"""
        now = datetime.utcnow()
        current_hour = await col("raw_logs").count_documents({
            "timestamp": {"$gte": now - timedelta(hours=1)}
        })

        # Get baseline (avg of last 7 days same hour)
        baselines = []
        for day in range(1, 8):
            start = now - timedelta(days=day, hours=1)
            end = now - timedelta(days=day)
            count = await col("raw_logs").count_documents({
                "timestamp": {"$gte": start, "$lt": end}
            })
            baselines.append(count)

        if not baselines or max(baselines) == 0:
            return None

        avg = np.mean(baselines)
        std = np.std(baselines) or 1
        z_score = (current_hour - avg) / std

        if abs(z_score) > 2:
            direction = "spike" if z_score > 0 else "drop"
            return {
                "type": f"volume_{direction}",
                "severity": "high" if abs(z_score) > 3 else "medium",
                "title": f"Log Volume {'Spike' if z_score > 0 else 'Drop'} Detected",
                "description": f"Current hour: {current_hour} logs (baseline avg: {avg:.0f}, z-score: {z_score:.1f})",
                "current_value": int(current_hour),
                "baseline_avg": float(round(avg, 1)),
                "z_score": float(round(z_score, 2)),
                "metric": "log_volume_per_hour",
            }
        return None

    async def _check_unusual_events(self) -> Dict[str, Any] | None:
        """Detect event IDs not seen in baseline period"""
        now = datetime.utcnow()

        # Current hour event IDs
        current_agg = [
            {"$match": {"timestamp": {"$gte": now - timedelta(hours=1)}, "event_id": {"$ne": None}}},
            {"$group": {"_id": "$event_id", "count": {"$sum": 1}}},
        ]
        current_events = {doc["_id"]: doc["count"] async for doc in col("raw_logs").aggregate(current_agg)}

        # Baseline event IDs (7 days)
        baseline_agg = [
            {"$match": {"timestamp": {"$gte": now - timedelta(days=7), "$lt": now - timedelta(hours=1)}, "event_id": {"$ne": None}}},
            {"$group": {"_id": "$event_id"}},
        ]
        baseline_events = {doc["_id"] async for doc in col("raw_logs").aggregate(baseline_agg)}

        new_events = {eid: c for eid, c in current_events.items() if eid not in baseline_events}

        if new_events and len(new_events) >= 2:
            return {
                "type": "unusual_events",
                "severity": "medium",
                "title": "Unusual Event IDs Detected",
                "description": f"{len(new_events)} event IDs not seen in baseline: {list(new_events.keys())[:5]}",
                "new_event_ids": list(new_events.keys())[:10],
                "metric": "new_event_ids",
            }
        return None

    async def _check_new_ips(self) -> Dict[str, Any] | None:
        """Detect new source IPs not previously seen"""
        now = datetime.utcnow()

        current_agg = [
            {"$match": {"timestamp": {"$gte": now - timedelta(hours=1)}, "source_ip": {"$ne": None}}},
            {"$group": {"_id": "$source_ip", "count": {"$sum": 1}}},
        ]
        current_ips = {doc["_id"]: doc["count"] async for doc in col("raw_logs").aggregate(current_agg)}

        baseline_agg = [
            {"$match": {"timestamp": {"$gte": now - timedelta(days=7), "$lt": now - timedelta(hours=1)}, "source_ip": {"$ne": None}}},
            {"$group": {"_id": "$source_ip"}},
        ]
        baseline_ips = {doc["_id"] async for doc in col("raw_logs").aggregate(baseline_agg)}

        new_ips = {ip: c for ip, c in current_ips.items() if ip not in baseline_ips}

        if len(new_ips) >= 3:
            return {
                "type": "new_source_ips",
                "severity": "medium",
                "title": f"{len(new_ips)} New Source IPs Detected",
                "description": f"IPs not seen in past 7 days: {list(new_ips.keys())[:5]}",
                "new_ips": list(new_ips.keys())[:10],
                "metric": "new_ips",
            }
        return None

    async def _check_off_hours(self) -> Dict[str, Any] | None:
        """Detect high activity during off-hours (10PM - 6AM)"""
        now = datetime.utcnow()
        hour = now.hour

        if hour >= 22 or hour < 6:
            count = await col("raw_logs").count_documents({
                "timestamp": {"$gte": now - timedelta(hours=1)}
            })

            # Get average off-hours from baseline
            baselines = []
            for day in range(1, 8):
                start = now - timedelta(days=day, hours=1)
                end = now - timedelta(days=day)
                c = await col("raw_logs").count_documents({
                    "timestamp": {"$gte": start, "$lt": end}
                })
                baselines.append(c)

            avg = np.mean(baselines) if baselines else 0
            if count > max(avg * 2, 20):
                return {
                    "type": "off_hours_activity",
                    "severity": "high",
                    "title": "Unusual Off-Hours Activity",
                    "description": f"{count} events in the last hour (avg off-hours: {avg:.0f}). Possible unauthorized access.",
                    "current_value": int(count),
                    "baseline_avg": float(round(avg, 1)),
                    "metric": "off_hours_logs",
                }
        return None

    async def _check_threat_rate(self) -> Dict[str, Any] | None:
        """Detect spike in threat detection rate"""
        now = datetime.utcnow()
        total = await col("raw_logs").count_documents({"timestamp": {"$gte": now - timedelta(hours=1)}})
        threats = await col("threat_logs").count_documents({"timestamp": {"$gte": now - timedelta(hours=1)}})

        if total == 0:
            return None

        rate = threats / total * 100

        # Baseline rate
        baseline_total = await col("raw_logs").count_documents({
            "timestamp": {"$gte": now - timedelta(days=7), "$lt": now - timedelta(hours=1)}
        })
        baseline_threats = await col("threat_logs").count_documents({
            "timestamp": {"$gte": now - timedelta(days=7), "$lt": now - timedelta(hours=1)}
        })
        baseline_rate = (baseline_threats / baseline_total * 100) if baseline_total > 0 else 0

        if rate > max(baseline_rate * 2, 10):
            return {
                "type": "threat_rate_spike",
                "severity": "high",
                "title": "Threat Detection Rate Spike",
                "description": f"Current threat rate: {rate:.1f}% (baseline: {baseline_rate:.1f}%). Possible active attack.",
                "current_rate": float(round(rate, 2)),
                "baseline_rate": float(round(baseline_rate, 2)),
                "metric": "threat_rate",
            }
        return None

    async def get_recent_anomalies(self, hours: int = 24) -> list:
        since = datetime.utcnow() - timedelta(hours=hours)
        cursor = col("anomalies").find(
            {"detected_at": {"$gte": since}}
        ).sort("detected_at", -1).limit(50)
        docs = []
        async for doc in cursor:
            doc["id"] = str(doc.pop("_id"))
            docs.append(doc)
        return docs

    async def resolve_anomaly(self, anomaly_id: str):
        from bson import ObjectId
        await col("anomalies").update_one(
            {"_id": ObjectId(anomaly_id)},
            {"$set": {"resolved": True, "resolved_at": datetime.utcnow()}}
        )

    async def delete_anomaly(self, anomaly_id: str):
        from bson import ObjectId
        await col("anomalies").delete_one({"_id": ObjectId(anomaly_id)})


anomaly_detector = AnomalyDetector()
