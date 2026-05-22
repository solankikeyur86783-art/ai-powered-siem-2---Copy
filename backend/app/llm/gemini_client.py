import json
import google.generativeai as genai
from loguru import logger
from app.config import get_settings

settings = get_settings()


class GeminiClient:
    def __init__(self):
        self.model = None

    def _get_model(self):
        if self.model is None:
            if not settings.gemini_api_key:
                raise ValueError("GEMINI_API_KEY not set in .env")
            genai.configure(api_key=settings.gemini_api_key)
            self.model = genai.GenerativeModel(settings.gemini_model)
        return self.model

    async def analyze(self, system_prompt: str, user_prompt: str) -> dict:
        try:
            model = self._get_model()
            full_prompt = f"{system_prompt}\n\n{user_prompt}"
            response = model.generate_content(full_prompt)
            text = response.text.strip()
            # Strip markdown if present
            if text.startswith("```"):
                text = text.split("```")[1]
                if text.startswith("json"):
                    text = text[4:]
            return json.loads(text.strip())
        except Exception as e:
            logger.error(f"Gemini error: {e}")
            raise

    async def is_available(self) -> bool:
        try:
            self._get_model()
            return bool(settings.gemini_api_key)
        except Exception:
            return False
