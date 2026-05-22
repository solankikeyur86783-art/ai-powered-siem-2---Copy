from pydantic_settings import BaseSettings
from functools import lru_cache
from typing import Optional
import os


class Settings(BaseSettings):
    # MongoDB
    mongodb_url: str = "mongodb://localhost:27017"
    mongodb_db_name: str = "siem_db"

    # API Keys
    openai_api_key: Optional[str] = None
    groq_api_key: Optional[str] = None
    abuseipdb_api_key: Optional[str] = None

    # LLM
    llm_provider: str = "groq"
    llm_model: str = "llama-3.3-70b-versatile"
    llm_fallback: str = "none"

    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = True
    secret_key: str = "cortex-siem-v3-super-secret-key-2024-change-me"

    # JWT
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 1440  # 24 hours

    # SIEM
    log_retention_days: int = 90
    alert_threshold_high: int = 80
    alert_threshold_critical: int = 95
    max_logs_per_page: int = 100
    winlogbeat_port: int = 5044
    syslog_port: int = 514

    # ML
    model_path: str = "../ml_model/siem_rf_model.pkl"
    scaler_path: str = "../ml_model/scaler.pkl"
    encoder_path: str = "../ml_model/label_encoders.pkl"
    mitre_path: str = "../ml_model/mitre_mapping.pkl"
    retrain_interval_hours: int = 24

    # Notifications (optional)
    slack_webhook_url: Optional[str] = None

    model_config = {
        "env_file": os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env"),
        "case_sensitive": False,
        "protected_namespaces": ("settings_",),
    }


@lru_cache()
def get_settings() -> Settings:
    return Settings()
