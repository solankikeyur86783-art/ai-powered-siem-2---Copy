import json
from openai import AsyncOpenAI
from loguru import logger
from app.config import get_settings

settings = get_settings()


class OpenAIClient:
    def __init__(self):
        self.client = None
        self.model = settings.llm_model

    def _get_client(self):
        if self.client is None:
            if not settings.openai_api_key:
                raise ValueError("OPENAI_API_KEY not set in .env")
            self.client = AsyncOpenAI(api_key=settings.openai_api_key)
        return self.client

    async def analyze(self, system_prompt: str, user_prompt: str) -> dict:
        try:
            client = self._get_client()
            response = await client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.1,
                max_tokens=1000,
                response_format={"type": "json_object"}
            )
            content = response.choices[0].message.content
            return json.loads(content)
        except Exception as e:
            logger.error(f"OpenAI error: {e}")
            raise

    async def is_available(self) -> bool:
        try:
            client = self._get_client()
            await client.models.list()
            return True
        except Exception:
            return False
