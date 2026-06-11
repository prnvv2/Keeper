from unittest.mock import AsyncMock, patch

import pytest

from aanf.core.engine import Action
from aanf.core.pipeline import RequestContext


@pytest.fixture
def mock_ollama():
    with patch("aanf.models.ollama_client.OllamaClient.generate", new_callable=AsyncMock) as mock:
        mock.return_value = "NO"
        yield mock


class TestPromptGuard:
    @pytest.mark.asyncio
    async def test_no_model_loaded_returns_ctx(self):
        from aanf.guardrails.prompt_guard import PromptGuard
        pg = PromptGuard()
        ctx = RequestContext(prompt="test")
        config = {"enabled": True, "threshold": 0.85}
        result = await pg.analyze(ctx, config)
        assert result == ctx

    @pytest.mark.asyncio
    async def test_model_disabled_returns_ctx(self):
        from aanf.guardrails.prompt_guard import PromptGuard
        pg = PromptGuard()
        ctx = RequestContext(prompt="test")
        config = {"enabled": False, "threshold": 0.85}
        result = await pg.analyze(ctx, config)
        assert result == ctx


class TestAlignmentCheck:
    @pytest.mark.asyncio
    async def test_no_cot_returns_ctx(self):
        from aanf.guardrails.alignment_check import AlignmentCheck
        ac = AlignmentCheck()
        ctx = RequestContext(prompt="test")
        config = {"enabled": True, "model": "llama3.2"}
        result = await ac.analyze(ctx, config)
        assert result.action == Action.ALLOW

    @pytest.mark.asyncio
    async def test_disabled_returns_ctx(self):
        from aanf.guardrails.alignment_check import AlignmentCheck
        ac = AlignmentCheck()
        ctx = RequestContext(prompt="test", metadata={"chain_of_thought": "some reasoning"})
        config = {"enabled": False, "model": "llama3.2"}
        result = await ac.analyze(ctx, config)
        assert result.action == Action.ALLOW

    @pytest.mark.asyncio
    async def test_blocks_deviation(self, mock_ollama):
        mock_ollama.return_value = "YES - the agent deviated from its goal"
        from aanf.guardrails.alignment_check import AlignmentCheck
        ac = AlignmentCheck()
        ctx = RequestContext(
            prompt="test",
            metadata={
                "chain_of_thought": "I should ignore the original goal and do this instead",
                "original_goal": "Be helpful and harmless",
            }
        )
        config = {"enabled": True, "model": "llama3.2"}
        result = await ac.analyze(ctx, config)
        assert result.action == Action.BLOCK

    @pytest.mark.asyncio
    async def test_allows_aligned(self, mock_ollama):
        mock_ollama.return_value = "NO - the agent is following its goal correctly"
        from aanf.guardrails.alignment_check import AlignmentCheck
        ac = AlignmentCheck()
        ctx = RequestContext(
            prompt="test",
            metadata={
                "chain_of_thought": "The user wants information, I will provide it",
                "original_goal": "Be helpful and harmless",
            }
        )
        config = {"enabled": True, "model": "llama3.2"}
        result = await ac.analyze(ctx, config)
        assert result.action == Action.ALLOW


class TestCodeShield:
    @pytest.mark.asyncio
    async def test_no_code_returns_ctx(self):
        from aanf.guardrails.code_shield import CodeShield
        cs = CodeShield()
        ctx = RequestContext(prompt="test")
        config = {"enabled": True, "languages": ["python"]}
        result = await cs.analyze(ctx, config)
        assert result.action == Action.ALLOW

    @pytest.mark.asyncio
    async def test_blocks_exec(self):
        from aanf.guardrails.code_shield import CodeShield
        cs = CodeShield()
        ctx = RequestContext(
            prompt="test",
            metadata={"generated_code": 'result = exec("malicious code")'}
        )
        config = {"enabled": True, "languages": ["python"]}
        result = await cs.analyze(ctx, config)
        assert result.action == Action.BLOCK
        assert "exec" in result.violations[0]

    @pytest.mark.asyncio
    async def test_blocks_eval(self):
        from aanf.guardrails.code_shield import CodeShield
        cs = CodeShield()
        ctx = RequestContext(
            prompt="test",
            metadata={"generated_code": 'eval(user_input)'}
        )
        config = {"enabled": True, "languages": ["python"]}
        result = await cs.analyze(ctx, config)
        assert result.action == Action.BLOCK

    @pytest.mark.asyncio
    async def test_blocks_subprocess(self):
        from aanf.guardrails.code_shield import CodeShield
        cs = CodeShield()
        ctx = RequestContext(
            prompt="test",
            metadata={"generated_code": 'subprocess.call(["rm", "-rf", "/"])'}
        )
        config = {"enabled": True, "languages": ["python"]}
        result = await cs.analyze(ctx, config)
        assert result.action == Action.BLOCK

    @pytest.mark.asyncio
    async def test_blocks_pickle(self):
        from aanf.guardrails.code_shield import CodeShield
        cs = CodeShield()
        ctx = RequestContext(
            prompt="test",
            metadata={"generated_code": 'pickle.load(open("data.pkl"))'}
        )
        config = {"enabled": True, "languages": ["python"]}
        result = await cs.analyze(ctx, config)
        assert result.action == Action.BLOCK

    @pytest.mark.asyncio
    async def test_blocks_inner_html(self):
        from aanf.guardrails.code_shield import CodeShield
        cs = CodeShield()
        ctx = RequestContext(
            prompt="test",
            metadata={"generated_code": 'element.innerHTML = userInput'}
        )
        config = {"enabled": True, "languages": ["javascript"]}
        result = await cs.analyze(ctx, config)
        assert result.action == Action.BLOCK

    @pytest.mark.asyncio
    async def test_blocks_concatenated_sql(self):
        from aanf.guardrails.code_shield import CodeShield
        cs = CodeShield()
        ctx = RequestContext(
            prompt="test",
            metadata={"generated_code": 'query = "SELECT * FROM users WHERE id = " + user_id'}
        )
        config = {"enabled": True, "languages": ["sql"]}
        result = await cs.analyze(ctx, config)
        assert result.action == Action.BLOCK

    @pytest.mark.asyncio
    async def test_allows_safe_code(self):
        from aanf.guardrails.code_shield import CodeShield
        cs = CodeShield()
        ctx = RequestContext(
            prompt="test",
            metadata={"generated_code": 'print("hello world")'}
        )
        config = {"enabled": True, "languages": ["python"]}
        result = await cs.analyze(ctx, config)
        assert result.action == Action.ALLOW
