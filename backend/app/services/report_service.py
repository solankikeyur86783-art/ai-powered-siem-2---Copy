"""
Report Service — PDF report generation
"""
import io
import os
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from loguru import logger
from app.database.db import col
from app.services.llm_service import llm_service


class ReportService:
    """Generate security report data (PDF generation done on-demand)"""

    async def generate_report(self, report_type: str = "executive",
                               hours: int = 24, generated_by: str = "system") -> Dict[str, Any]:
        """Generate report data and store metadata"""
        since = datetime.utcnow() - timedelta(hours=hours)
        period = f"Last {hours} hours"

        # Gather data
        stats = await self._gather_stats(since)
        alerts = await self._gather_alerts(since)
        threats = await self._gather_threats(since)
        top_ips = await self._gather_top_ips(since)

        # LLM summary
        try:
            narrative = await llm_service.daily_summary({
                "total_logs": stats["total_logs"],
                "threats": stats["total_threats"],
                "critical": stats["critical"],
                "high": stats["high"],
                "top_ips": top_ips[:5],
                "threat_types": threats[:5],
            })
            executive_summary = narrative.get("summary") or narrative.get("analysis")
            
            if not executive_summary:
                # Fallback: Rule-based local summary
                res_rate = round(stats['resolved'] / stats['total_alerts'] * 100, 1) if stats['total_alerts'] > 0 else 100
                top_threat = threats[0]['type'] if threats else "general traffic"
                executive_summary = (
                    f"SYSTEM GEN: Secure posture analysis for {period} completed. "
                    f"A total of {stats['total_threats']} threats were detected, primarily consisting of {top_threat}. "
                    f"The current incident resolution rate is {res_rate}%. "
                    f"Critical focus is required on {stats['critical']} alerts and {len(top_ips)} attacking IPs."
                )
        except Exception as e:
            logger.error(f"Report AI summary failed: {e}")
            executive_summary = f"Rule-based summary for {period}. Total threats: {stats['total_threats']}."

        report = {
            "created_at": datetime.utcnow(),
            "report_type": report_type,
            "period": period,
            "period_hours": hours,
            "generated_by": generated_by,
            "status": "completed",
            "executive_summary": executive_summary,
            "stats": stats,
            "alerts_summary": {
                "total": len(alerts),
                "by_severity": {
                    "critical": sum(1 for a in alerts if a.get("severity") == "critical"),
                    "high": sum(1 for a in alerts if a.get("severity") == "high"),
                    "medium": sum(1 for a in alerts if a.get("severity") == "medium"),
                    "low": sum(1 for a in alerts if a.get("severity") == "low"),
                },
                "recent": alerts[:10],
            },
            "threat_breakdown": threats,
            "top_attacking_ips": top_ips,
            "key_metrics": {
                "total_events": stats["total_logs"],
                "security_incidents": stats["total_threats"],
                "critical_alerts": stats["critical"],
                "resolution_rate": f"{round(stats['resolved'] / stats['total_alerts'] * 100, 1) if stats['total_alerts'] > 0 else 100}%",
                "threat_rate": f"{stats['threat_rate']}%"
            },
            "recommendations": [
                "Review and investigate all critical alerts immediately",
                "Block top attacking IPs at the firewall level",
                "Update detection rules based on new threat patterns",
                "Ensure all systems have latest security patches",
                "Review user access logs for unauthorized activity"
            ],
        }

        # Store report metadata in DB
        result = await col("reports").insert_one(report)
        report["id"] = str(result.inserted_id)
        report.pop("_id", None)

        return report

    async def _gather_stats(self, since: datetime) -> Dict:
        total_logs = await col("raw_logs").count_documents({"timestamp": {"$gte": since}})
        total_threats = await col("threat_logs").count_documents({"timestamp": {"$gte": since}})
        total_alerts = await col("alerts").count_documents({"created_at": {"$gte": since}})
        critical = await col("alerts").count_documents({"created_at": {"$gte": since}, "severity": "critical"})
        high = await col("alerts").count_documents({"created_at": {"$gte": since}, "severity": "high"})
        medium = await col("alerts").count_documents({"created_at": {"$gte": since}, "severity": "medium"})
        low = await col("alerts").count_documents({"created_at": {"$gte": since}, "severity": "low"})
        resolved = await col("alerts").count_documents({"created_at": {"$gte": since}, "status": "resolved"})

        return {
            "total_logs": total_logs,
            "total_threats": total_threats,
            "total_alerts": total_alerts,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "resolved": resolved,
            "threat_rate": round(total_threats / total_logs * 100, 2) if total_logs > 0 else 0,
        }

    async def _gather_alerts(self, since: datetime) -> list:
        cursor = col("alerts").find(
            {"created_at": {"$gte": since}},
            {"_id": 0, "title": 1, "severity": 1, "status": 1, "source_ip": 1,
             "hostname": 1, "created_at": 1, "rule_id": 1}
        ).sort("created_at", -1).limit(50)
        return [doc async for doc in cursor]

    async def _gather_threats(self, since: datetime) -> list:
        pipeline = [
            {"$match": {"timestamp": {"$gte": since}}},
            {"$group": {"_id": "$threat_type", "count": {"$sum": 1},
                        "max_severity": {"$max": "$severity"}}},
            {"$sort": {"count": -1}}
        ]
        return [{"type": d["_id"], "count": d["count"], "severity": d["max_severity"]}
                async for d in col("threat_logs").aggregate(pipeline)]

    async def _gather_top_ips(self, since: datetime) -> list:
        pipeline = [
            {"$match": {"timestamp": {"$gte": since}, "source_ip": {"$ne": None}}},
            {"$group": {"_id": "$source_ip", "count": {"$sum": 1},
                        "severity": {"$max": "$severity"},
                        "threats": {"$addToSet": "$threat_type"}}},
            {"$sort": {"count": -1}},
            {"$limit": 15}
        ]
        return [{"ip": d["_id"], "count": d["count"], "severity": d["severity"],
                 "threats": d["threats"]}
                async for d in col("threat_logs").aggregate(pipeline)]

    async def list_reports(self, limit: int = 20) -> list:
        cursor = col("reports").find(
            {}
        ).sort("created_at", -1).limit(limit)
        docs = []
        async for doc in cursor:
            doc["id"] = str(doc.pop("_id"))
            docs.append(doc)
        return docs

    async def get_report(self, report_id: str) -> Optional[Dict]:
        from bson import ObjectId
        doc = await col("reports").find_one({"_id": ObjectId(report_id)})
        if doc:
            doc["id"] = str(doc.pop("_id"))
        return doc


report_service = ReportService()
