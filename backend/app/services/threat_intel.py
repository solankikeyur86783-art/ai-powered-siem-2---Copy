"""
Threat Intelligence Service — AbuseIPDB + IP reputation (demo/mock mode)
"""
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from loguru import logger
from app.config import get_settings
from app.database.db import col

settings = get_settings()


class AbuseIPDBClient:
    """Check IP reputation via AbuseIPDB API (mock mode if no key)"""

    def __init__(self):
        self.api_key = getattr(settings, 'abuseipdb_api_key', None) or ""
        self.enabled = bool(self.api_key)
        self.base_url = "https://api.abuseipdb.com/api/v2"

    async def check_ip(self, ip: str) -> Dict[str, Any]:
        # Check cache first (24hr TTL)
        cached = await col("ip_intel_cache").find_one({
            "ip": ip,
            "source": "abuseipdb",
            "cached_at": {"$gte": datetime.utcnow() - timedelta(hours=24)}
        })
        if cached:
            cached.pop("_id", None)
            return cached.get("data", {})

        if self.enabled:
            try:
                import httpx
                async with httpx.AsyncClient() as client:
                    resp = await client.get(
                        f"{self.base_url}/check",
                        params={"ipAddress": ip, "maxAgeInDays": 90},
                        headers={"Key": self.api_key, "Accept": "application/json"},
                        timeout=10
                    )
                    data = resp.json().get("data", {})
                    result = {
                        "ip": ip,
                        "abuse_score": data.get("abuseConfidenceScore", 0),
                        "country": data.get("countryCode", ""),
                        "isp": data.get("isp", ""),
                        "domain": data.get("domain", ""),
                        "total_reports": data.get("totalReports", 0),
                        "last_reported": data.get("lastReportedAt", ""),
                        "is_tor": data.get("isTor", False),
                        "is_whitelisted": data.get("isWhitelisted", False),
                        "usage_type": data.get("usageType", ""),
                    }
            except Exception as e:
                logger.error(f"AbuseIPDB check failed: {e}")
                result = self._mock_result(ip)
        else:
            result = self._mock_result(ip)

        # Cache result
        await col("ip_intel_cache").update_one(
            {"ip": ip, "source": "abuseipdb"},
            {"$set": {"data": result, "cached_at": datetime.utcnow()}},
            upsert=True
        )
        return result

    def _mock_result(self, ip: str) -> Dict[str, Any]:
        """Generate realistic mock data for demo purposes"""
        import hashlib
        # Use IP hash to generate consistent mock data
        h = int(hashlib.md5(ip.encode()).hexdigest()[:8], 16)
        score = h % 100
        countries = ["US", "CN", "RU", "DE", "BR", "IN", "GB", "FR", "KR", "NL"]
        isps = ["DigitalOcean", "Amazon AWS", "OVH", "Hetzner", "Alibaba Cloud",
                "Google Cloud", "Microsoft Azure", "Linode", "Vultr", "Cloudflare"]

        return {
            "ip": ip,
            "abuse_score": score,
            "country": countries[h % len(countries)],
            "isp": isps[h % len(isps)],
            "domain": f"host-{ip.replace('.', '-')}.example.com",
            "total_reports": (h % 50),
            "last_reported": (datetime.utcnow() - timedelta(days=h % 30)).isoformat() if score > 30 else "",
            "is_tor": h % 20 == 0,
            "is_whitelisted": score < 5,
            "usage_type": "Data Center/Web Hosting/Transit" if score > 50 else "ISP",
            "mock": True,
        }


class ThreatIntelService:
    def __init__(self):
        self.abuseipdb = AbuseIPDBClient()

    async def enrich_ip(self, ip: str) -> Dict[str, Any]:
        """Get full intelligence for an IP"""
        abuse = await self.abuseipdb.check_ip(ip)
        geo = await self.get_geoip(ip)
        return {
            "ip": ip,
            "abuse": abuse,
            "geo": geo,
            "risk_level": self._calculate_risk(abuse, geo),
            "enriched_at": datetime.utcnow().isoformat(),
        }

    async def get_geoip(self, ip: str) -> Dict[str, Any]:
        """Get GeoIP data using free ip-api.com"""
        # Check cache
        cached = await col("ip_intel_cache").find_one({
            "ip": ip,
            "source": "geoip",
            "cached_at": {"$gte": datetime.utcnow() - timedelta(hours=72)}
        })
        if cached:
            cached.pop("_id", None)
            return cached.get("data", {})

        # Private IPs get mock data
        if ip.startswith(("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                          "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                          "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                          "172.30.", "172.31.", "192.168.", "127.")):
            result = self._mock_geoip(ip)
        else:
            try:
                import httpx
                async with httpx.AsyncClient() as client:
                    resp = await client.get(
                        f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as",
                        timeout=5
                    )
                    data = resp.json()
                    if data.get("status") == "success":
                        result = {
                            "ip": ip,
                            "country": data.get("country", ""),
                            "country_code": data.get("countryCode", ""),
                            "region": data.get("regionName", ""),
                            "city": data.get("city", ""),
                            "lat": data.get("lat", 0),
                            "lon": data.get("lon", 0),
                            "timezone": data.get("timezone", ""),
                            "isp": data.get("isp", ""),
                            "org": data.get("org", ""),
                            "as": data.get("as", ""),
                        }
                    else:
                        result = self._mock_geoip(ip)
            except Exception as e:
                logger.warning(f"GeoIP lookup failed for {ip}: {e}")
                result = self._mock_geoip(ip)

        # Cache
        await col("ip_intel_cache").update_one(
            {"ip": ip, "source": "geoip"},
            {"$set": {"data": result, "cached_at": datetime.utcnow()}},
            upsert=True
        )
        return result

    def _mock_geoip(self, ip: str) -> Dict[str, Any]:
        """Generate realistic mock geo data"""
        import hashlib
        h = int(hashlib.md5(ip.encode()).hexdigest()[:8], 16)
        locations = [
            {"country": "United States", "country_code": "US", "city": "New York", "lat": 40.7128, "lon": -74.0060},
            {"country": "China", "country_code": "CN", "city": "Beijing", "lat": 39.9042, "lon": 116.4074},
            {"country": "Russia", "country_code": "RU", "city": "Moscow", "lat": 55.7558, "lon": 37.6173},
            {"country": "Germany", "country_code": "DE", "city": "Frankfurt", "lat": 50.1109, "lon": 8.6821},
            {"country": "Brazil", "country_code": "BR", "city": "São Paulo", "lat": -23.5505, "lon": -46.6333},
            {"country": "India", "country_code": "IN", "city": "Mumbai", "lat": 19.0760, "lon": 72.8777},
            {"country": "United Kingdom", "country_code": "GB", "city": "London", "lat": 51.5074, "lon": -0.1278},
            {"country": "Japan", "country_code": "JP", "city": "Tokyo", "lat": 35.6762, "lon": 139.6503},
            {"country": "South Korea", "country_code": "KR", "city": "Seoul", "lat": 37.5665, "lon": 126.9780},
            {"country": "Netherlands", "country_code": "NL", "city": "Amsterdam", "lat": 52.3676, "lon": 4.9041},
            {"country": "France", "country_code": "FR", "city": "Paris", "lat": 48.8566, "lon": 2.3522},
            {"country": "Australia", "country_code": "AU", "city": "Sydney", "lat": -33.8688, "lon": 151.2093},
        ]
        loc = locations[h % len(locations)]
        # Add slight randomization to coordinates
        lat_offset = ((h % 100) - 50) * 0.05
        lon_offset = ((h % 200) - 100) * 0.05
        return {
            "ip": ip,
            **loc,
            "lat": loc["lat"] + lat_offset,
            "lon": loc["lon"] + lon_offset,
            "region": loc["city"],
            "timezone": "UTC",
            "isp": "Mock ISP",
            "org": "Demo Organization",
            "as": "AS0000 Demo",
            "mock": True,
        }

    def _calculate_risk(self, abuse: Dict, geo: Dict) -> str:
        score = abuse.get("abuse_score", 0)
        if score >= 80:
            return "critical"
        elif score >= 50:
            return "high"
        elif score >= 25:
            return "medium"
        return "low"

    async def get_map_data(self, hours: int = 24) -> list:
        """Get all threat IPs with geo coordinates for map visualization"""
        since = datetime.utcnow() - timedelta(hours=hours)
        pipeline = [
            {"$match": {"timestamp": {"$gte": since}, "source_ip": {"$ne": None}}},
            {"$group": {
                "_id": "$source_ip",
                "count": {"$sum": 1},
                "severity": {"$max": "$severity"},
                "threat_types": {"$addToSet": "$threat_type"},
                "last_seen": {"$max": "$timestamp"},
            }},
            {"$sort": {"count": -1}},
            {"$limit": 100}
        ]

        threat_ips = []
        async for doc in col("threat_logs").aggregate(pipeline):
            ip = doc["_id"]
            geo = await self.get_geoip(ip)
            abuse = await self.abuseipdb.check_ip(ip)
            threat_ips.append({
                "ip": ip,
                "count": doc["count"],
                "severity": doc["severity"],
                "threat_types": doc["threat_types"],
                "last_seen": doc["last_seen"].isoformat() if doc.get("last_seen") else "",
                "lat": geo.get("lat", 0),
                "lon": geo.get("lon", 0),
                "country": geo.get("country", ""),
                "city": geo.get("city", ""),
                "abuse_score": abuse.get("abuse_score", 0),
                "isp": geo.get("isp") or abuse.get("isp", ""),
            })

        return threat_ips


threat_intel = ThreatIntelService()
