import pytest

from aanf.models.ollama_client import OllamaClient


class TestOllamaClient:
    def test_init_default_url(self):
        client = OllamaClient()
        assert client.base_url == "http://localhost:11434"

    def test_init_custom_url(self):
        client = OllamaClient(base_url="http://custom:8080")
        assert client.base_url == "http://custom:8080"

    @pytest.mark.asyncio
    async def test_generate_connection_error(self):
        client = OllamaClient(base_url="http://localhost:1")
        with pytest.raises(Exception):
            await client.generate("test-model", "test prompt")

    @pytest.mark.asyncio
    async def test_chat_connection_error(self):
        client = OllamaClient(base_url="http://localhost:1")
        with pytest.raises(Exception):
            await client.chat("test-model", [{"role": "user", "content": "hi"}])

    @pytest.mark.asyncio
    async def test_close(self):
        client = OllamaClient()
        await client.close()
