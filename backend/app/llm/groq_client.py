import json
import asyncio
from groq import AsyncGroq
from loguru import logger
from app.config import get_settings

settings = get_settings()

class GroqClient:
    def __init__(self):
        self.client = None
        self.model = "llama-3.1-8b-instant"
        self._semaphore = asyncio.Semaphore(2)  # max 2 concurrent calls
        self._last_call = 0

    def _get_client(self):
        if self.client is None:
            if not settings.groq_api_key:
                raise ValueError("GROQ_API_KEY not set in .env")
            self.client = AsyncGroq(api_key=settings.groq_api_key)
        return self.client

    async def analyze(self, system_prompt: str, user_prompt: str) -> dict:
        async with self._semaphore:
            await asyncio.sleep(1)  # 1 second delay between calls
            try:
                client = self._get_client()
                response = await client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    temperature=0.1,
                    max_tokens=500,
                )
                content = response.choices[0].message.content
                content = content.strip()
                if content.startswith("```"):
                    content = content.split("```")[1]
                    if content.startswith("json"):
                        content = content[4:]
                return json.loads(content.strip())
            except Exception as e:
                logger.error(f"Groq error: {e}")
                raise

    async def is_available(self) -> bool:
        try:
            self._get_client()
            return bool(settings.groq_api_key)
        except Exception:
            return False