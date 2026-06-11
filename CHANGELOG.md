# Changelog

## v0.2.0 (Unreleased)

- Refactored into production-ready package structure
- Added `pyproject.toml` with modern Python packaging
- Added comprehensive exception hierarchy
- Added plugin discovery via entry points
- Added comprehensive test suite (80+ tests)
- Added CI/CD workflows (GitHub Actions)
- Added complete documentation suite
- Added `BaseGuardrail` abstract base class
- Improved `Pipeline` with `unregister()`, `get_layer()`, `to_dict()`
- Improved `PolicyEngine` with `reload()` support
- Improved `RequestContext` with proper defaults
- Fixed internal imports to use `aanf.` prefix for installed-package compatibility

## v0.1.0 (Initial)

- 7-layer defense pipeline
- BERT jailbreak detection (PromptGuard)
- Ollama-based semantic analysis
- CoT alignment auditing
- Code security scanning (CodeShield)
- Multi-turn drift detection
- Agent sandbox and tool monitor
- FastAPI, LiteLLM, LangChain, MCP integrations
- Rust high-performance token scanner
- Benchmark evaluation
