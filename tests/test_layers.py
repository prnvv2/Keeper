from unittest.mock import AsyncMock, patch

import pytest

from aanf.core.engine import Action
from aanf.core.pipeline import RequestContext


@pytest.fixture
def mock_ollama():
    with patch("aanf.models.ollama_client.OllamaClient.generate", new_callable=AsyncMock) as mock:
        mock.return_value = "0.0"
        yield mock


class TestNetworkLayer:
    @pytest.mark.asyncio
    async def test_allows_normal_request(self):
        from aanf.layers.network import NetworkLayer
        layer = NetworkLayer()
        ctx = RequestContext(prompt="hello", ip="10.0.0.1")
        config = {"enabled": True, "rate_limit": "100/min", "block_ips": []}
        result = await layer.analyze(ctx, config)
        assert result.action == Action.ALLOW

    @pytest.mark.asyncio
    async def test_blocks_banned_ip(self):
        from aanf.layers.network import NetworkLayer
        layer = NetworkLayer()
        ctx = RequestContext(prompt="hello", ip="1.2.3.4")
        config = {"enabled": True, "rate_limit": "100/min", "block_ips": ["1.2.3.4"]}
        result = await layer.analyze(ctx, config)
        assert result.action == Action.BLOCK
        assert "blocked IP" in result.violations[0]

    @pytest.mark.asyncio
    async def test_rate_limit_exceeded(self):
        from aanf.layers.network import NetworkLayer
        layer = NetworkLayer()
        config = {"enabled": True, "rate_limit": "1/min", "block_ips": []}
        ctx1 = RequestContext(prompt="hello", ip="10.0.0.1")
        await layer.analyze(ctx1, config)
        ctx2 = RequestContext(prompt="hello2", ip="10.0.0.1")
        result = await layer.analyze(ctx2, config)
        assert result.action == Action.BLOCK
        assert "rate limit exceeded" in result.violations[0]

    @pytest.mark.asyncio
    async def test_separate_ip_buckets(self):
        from aanf.layers.network import NetworkLayer
        layer = NetworkLayer()
        config = {"enabled": True, "rate_limit": "1/min", "block_ips": []}
        ctx1 = RequestContext(prompt="hello", ip="10.0.0.1")
        await layer.analyze(ctx1, config)
        ctx2 = RequestContext(prompt="hello", ip="10.0.0.2")
        result = await layer.analyze(ctx2, config)
        assert result.action == Action.ALLOW


class TestSyntacticLayer:
    @pytest.mark.asyncio
    async def test_allows_benign_text(self):
        from aanf.layers.syntactic import SyntacticLayer
        layer = SyntacticLayer()
        ctx = RequestContext(prompt="What is the capital of France?")
        config = {"enabled": True, "max_prompt_length": 4096, "block_escape_seq": True}
        result = await layer.analyze(ctx, config)
        assert result.action == Action.ALLOW

    @pytest.mark.asyncio
    async def test_blocks_sql_injection(self):
        from aanf.layers.syntactic import SyntacticLayer
        layer = SyntacticLayer()
        ctx = RequestContext(prompt="SELECT * FROM users WHERE id = 1")
        config = {"enabled": True, "max_prompt_length": 4096, "block_escape_seq": True}
        result = await layer.analyze(ctx, config)
        assert result.action == Action.BLOCK

    @pytest.mark.asyncio
    async def test_blocks_xss(self):
        from aanf.layers.syntactic import SyntacticLayer
        layer = SyntacticLayer()
        ctx = RequestContext(prompt='<script>alert("xss")</script>')
        config = {"enabled": True, "max_prompt_length": 4096, "block_escape_seq": True}
        result = await layer.analyze(ctx, config)
        assert result.action == Action.BLOCK

    @pytest.mark.asyncio
    async def test_blocks_escape_sequences(self):
        from aanf.layers.syntactic import SyntacticLayer
        layer = SyntacticLayer()
        ctx = RequestContext(prompt="test\\x48\\x65\\x6c")
        config = {"enabled": True, "max_prompt_length": 4096, "block_escape_seq": True}
        result = await layer.analyze(ctx, config)
        assert result.action == Action.BLOCK

    @pytest.mark.asyncio
    async def test_blocks_overflow(self):
        from aanf.layers.syntactic import SyntacticLayer
        layer = SyntacticLayer()
        ctx = RequestContext(prompt="a" * 5000)
        config = {"enabled": True, "max_prompt_length": 4096, "block_escape_seq": True}
        result = await layer.analyze(ctx, config)
        assert result.action == Action.BLOCK
        assert "exceeds" in result.violations[0]

    @pytest.mark.asyncio
    async def test_drop_table(self):
        from aanf.layers.syntactic import SyntacticLayer
        layer = SyntacticLayer()
        ctx = RequestContext(prompt="DROP TABLE users;")
        config = {"enabled": True, "max_prompt_length": 4096, "block_escape_seq": True}
        result = await layer.analyze(ctx, config)
        assert result.action == Action.BLOCK


class TestSemanticLayer:
    @pytest.mark.asyncio
    async def test_fail_open_when_ollama_down(self, mock_ollama):
        from aanf.layers.semantic import SemanticLayer
        layer = SemanticLayer()
        ctx = RequestContext(prompt="test")
        config = {"enabled": True, "threshold": 0.75, "model": "llama3.2"}
        result = await layer.analyze(ctx, config)
        assert result.risk_score == 0.0
        assert result.action == Action.ALLOW

    @pytest.mark.asyncio
    async def test_blocks_high_score(self, mock_ollama):
        mock_ollama.return_value = "0.95"
        from aanf.layers.semantic import SemanticLayer
        layer = SemanticLayer()
        ctx = RequestContext(prompt="malicious prompt")
        config = {"enabled": True, "threshold": 0.75, "model": "llama3.2"}
        result = await layer.analyze(ctx, config)
        assert result.risk_score == 0.95
        assert result.action == Action.BLOCK

    @pytest.mark.asyncio
    async def test_allows_low_score(self, mock_ollama):
        mock_ollama.return_value = "0.1"
        from aanf.layers.semantic import SemanticLayer
        layer = SemanticLayer()
        ctx = RequestContext(prompt="benign prompt")
        config = {"enabled": True, "threshold": 0.75, "model": "llama3.2"}
        result = await layer.analyze(ctx, config)
        assert result.risk_score == 0.1
        assert result.action == Action.ALLOW

    @pytest.mark.asyncio
    async def test_handles_non_numeric_response(self, mock_ollama):
        mock_ollama.return_value = "I think this is safe"
        from aanf.layers.semantic import SemanticLayer
        layer = SemanticLayer()
        ctx = RequestContext(prompt="test")
        config = {"enabled": True, "threshold": 0.75, "model": "llama3.2"}
        result = await layer.analyze(ctx, config)
        assert result.risk_score == 0.0
        assert result.action == Action.ALLOW


class TestContextLayer:
    @pytest.mark.asyncio
    async def test_first_turn_no_drift_check(self):
        from aanf.layers.context import ContextLayer
        layer = ContextLayer()
        ctx = RequestContext(prompt="first message", session_id="s1")
        config = {"enabled": True, "drift_threshold": 0.6, "max_history": 20, "model": "llama3.2"}
        result = await layer.analyze(ctx, config)
        assert result.action == Action.ALLOW
        assert "s1" in layer.sessions

    @pytest.mark.asyncio
    async def test_two_turns_no_drift_check(self):
        from aanf.layers.context import ContextLayer
        layer = ContextLayer()
        config = {"enabled": True, "drift_threshold": 0.6, "max_history": 20, "model": "llama3.2"}
        ctx1 = RequestContext(prompt="first", session_id="s1")
        await layer.analyze(ctx1, config)
        ctx2 = RequestContext(prompt="second", session_id="s1")
        result = await layer.analyze(ctx2, config)
        assert result.action == Action.ALLOW

    @pytest.mark.asyncio
    async def test_separate_sessions(self):
        from aanf.layers.context import ContextLayer
        layer = ContextLayer()
        config = {"enabled": True, "drift_threshold": 0.6, "max_history": 20, "model": "llama3.2"}
        ctx1 = RequestContext(prompt="first", session_id="s1")
        await layer.analyze(ctx1, config)
        ctx2 = RequestContext(prompt="first", session_id="s2")
        result = await layer.analyze(ctx2, config)
        assert result.action == Action.ALLOW

    @pytest.mark.asyncio
    async def test_drift_detection(self, mock_ollama):
        mock_ollama.return_value = "0.9"
        from aanf.layers.context import ContextLayer
        layer = ContextLayer()
        config = {"enabled": True, "drift_threshold": 0.6, "max_history": 20, "model": "llama3.2"}
        ctx1 = RequestContext(prompt="original request", session_id="drift-s1")
        await layer.analyze(ctx1, config)
        ctx2 = RequestContext(prompt="second msg", session_id="drift-s1")
        await layer.analyze(ctx2, config)
        ctx3 = RequestContext(prompt="completely unrelated topic", session_id="drift-s1")
        result = await layer.analyze(ctx3, config)
        assert result.action == Action.BLOCK
        assert "context drift" in result.violations[0]
