# models/ollama_client.py
# Async HTTP client for Ollama's local LLM API.
# Used by SemanticLayer, ContextLayer, and AlignmentCheck
# to run inference on local models without external API calls.

import httpx


class OllamaClient:
    # Wraps Ollama's REST API (runs at http://localhost:11434 by default).

    def __init__(self, base_url: str = "http://localhost:11434"):
        self.base_url = base_url
        self.client = httpx.AsyncClient(timeout=30)

    async def generate(self, model: str, prompt: str) -> str:
        # Simple generate endpoint — send prompt, get text response.
        resp = await self.client.post(
            f"{self.base_url}/api/generate",
            json={"model": model, "prompt": prompt, "stream": False},
        )
        resp.raise_for_status()
        return resp.json().get("response", "")

    async def chat(self, model: str, messages: list) -> str:
        # Chat endpoint for structured multi-turn conversations.
        resp = await self.client.post(
            f"{self.base_url}/api/chat",
            json={"model": model, "messages": messages, "stream": False},
        )
        resp.raise_for_status()
        return resp.json().get("message", {}).get("content", "")

    async def close(self):
        await self.client.aclose()
