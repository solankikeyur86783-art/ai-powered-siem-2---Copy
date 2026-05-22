from loguru import logger
from app.config import get_settings
from app.llm.groq_client import GroqClient

settings = get_settings()
groq_client = GroqClient()


async def llm_analyze(system_prompt: str, user_prompt: str) -> dict:
    try:
        logger.debug("Using Groq")
        return await groq_client.analyze(system_prompt, user_prompt)
    except Exception as e:
        logger.warning(f"Groq failed: {e} — using mock response")
        return _mock_response()


def _mock_response() -> dict:
    return {
        "threat_detected": False,
        "severity": "low",
        "threat_type": "unknown",
        "summary": "LLM unavailable — configure GROQ_API_KEY in .env",
        "recommended_actions": ["Configure GROQ_API_KEY"],
        "mitre_tactic": None,
        "mitre_technique": None,
        "confidence": 0.0
    }