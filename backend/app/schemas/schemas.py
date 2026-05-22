from pydantic import BaseModel, Field
from typing import Optional, List, Any, Dict
from datetime import datetime
from enum import Enum


class SeverityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class ThreatType(str, Enum):
    BRUTE_FORCE = "brute_force"
    PORT_SCAN = "port_scan"
    MALWARE = "malware"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    LATERAL_MOVEMENT = "lateral_movement"
    ANOMALY = "anomaly"
    UNKNOWN = "unknown"


# ── Raw Log ──────────────────────────────────────────────
class RawLog(BaseModel):
    id: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source: str = "unknown"           # winlogbeat | syslog | manual
    hostname: str = "unknown"
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    source_port: Optional[int] = None
    dest_port: Optional[int] = None
    event_id: Optional[int] = None
    log_level: str = "INFO"
    message: str = ""
    raw: Optional[Dict[str, Any]] = None


class RawLogCreate(BaseModel):
    source: str = "manual"
    hostname: str = "unknown"
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    event_id: Optional[int] = None
    log_level: str = "INFO"
    message: str


# ── Threat Log ───────────────────────────────────────────
class ThreatLog(BaseModel):
    id: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    raw_log_id: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    hostname: str = "unknown"
    threat_type: ThreatType = ThreatType.UNKNOWN
    severity: SeverityLevel = SeverityLevel.LOW
    ml_score: float = 0.0
    rule_matched: Optional[str] = None
    description: str = ""
    llm_analysis: Optional[str] = None
    status: AlertStatus = AlertStatus.OPEN
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None


# ── Alert ────────────────────────────────────────────────
class Alert(BaseModel):
    id: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    title: str
    description: str
    severity: SeverityLevel
    status: AlertStatus = AlertStatus.OPEN
    rule_id: Optional[str] = None
    threat_log_id: Optional[str] = None
    source_ip: Optional[str] = None
    hostname: str = "unknown"
    assigned_to: Optional[str] = None
    llm_summary: Optional[str] = None
    recommended_actions: List[str] = []
    tags: List[str] = []


class AlertUpdate(BaseModel):
    status: Optional[AlertStatus] = None
    assigned_to: Optional[str] = None
    notes: Optional[str] = None


# ── Agent Action ─────────────────────────────────────────
class AgentAction(BaseModel):
    id: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    agent_type: str           # soc | analyst | responder
    alert_id: Optional[str] = None
    action: str
    result: str
    success: bool = True
    details: Optional[Dict[str, Any]] = None


# ── Dashboard Stats ───────────────────────────────────────
class DashboardStats(BaseModel):
    total_logs_today: int = 0
    total_threats_today: int = 0
    open_alerts: int = 0
    critical_alerts: int = 0
    high_alerts: int = 0
    medium_alerts: int = 0
    low_alerts: int = 0
    logs_per_hour: List[Dict] = []
    top_source_ips: List[Dict] = []
    threat_distribution: List[Dict] = []
    recent_alerts: List[Dict] = []
    system_health: Dict = {}


# ── LLM Request ──────────────────────────────────────────
class LLMAnalysisRequest(BaseModel):
    log_data: Dict[str, Any]
    context: Optional[str] = None


class LLMAnalysisResponse(BaseModel):
    threat_detected: bool
    severity: SeverityLevel
    threat_type: ThreatType
    summary: str
    recommended_actions: List[str]
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    confidence: float = 0.0


# ── Winlogbeat Ingest ────────────────────────────────────
class WinlogbeatEvent(BaseModel):
    timestamp: Optional[str] = None
    winlog: Optional[Dict[str, Any]] = None
    host: Optional[Dict[str, Any]] = None
    event: Optional[Dict[str, Any]] = None
    message: Optional[str] = None
    source_ip: Optional[str] = None
