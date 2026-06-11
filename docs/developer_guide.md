# Developer Guide

## Project Setup

```bash
git clone https://github.com/anomalyco/keeper.git
cd keeper
pip install -e ".[dev]"
```

## Development Commands

```bash
# Run tests
pytest tests/ --asyncio-mode=auto -v

# Run tests with coverage
pytest tests/ --asyncio-mode=auto --cov=keeper --cov-report=term-missing

# Lint
ruff check keeper/

# Format
black keeper/

# Type check
mypy keeper/ --ignore-missing-imports
```

## Project Structure

```
keeper/
├── core/           # Pipeline orchestration and policy
├── layers/         # Security layers
├── guardrails/     # Pluggable guardrails
├── agents/         # Agent security tools
├── models/         # Data models and clients
├── integration/    # Framework adapters
├── scanner/        # Rust high-performance scanner
├── plugins/        # Plugin discovery
├── config/         # Default configuration
└── tests/          # Test suite
```

## Adding a New Layer

1. Create a class that extends `BaseLayer`
2. Implement `async analyze(self, ctx, config) -> RequestContext`
3. Set a unique `name` class attribute
4. Register it in `build_pipeline()` or via plugins

```python
from keeper import BaseLayer, RequestContext
from keeper.core.engine import Action

class MyLayer(BaseLayer):
    name = "my_layer"

    async def analyze(self, ctx: RequestContext, config: dict) -> RequestContext:
        if "bad" in ctx.prompt:
            ctx.action = Action.BLOCK
            ctx.violations.append("my_layer: bad detected")
        return ctx
```

## Adding a New Guardrail

```python
from keeper import BaseGuardrail, RequestContext
from keeper.core.engine import Action

class MyGuardrail(BaseGuardrail):
    name = "my_guardrail"

    async def analyze(self, ctx: RequestContext, config: dict) -> RequestContext:
        return ctx
```

## Publishing to PyPI

```bash
# Build
python -m build

# Check
twine check dist/*

# Upload to test PyPI
twine upload --repository testpypi dist/*

# Upload to PyPI
twine upload dist/*
```

## Release Process

1. Update version in `version.py`
2. Update `CHANGELOG.md` (if maintained)
3. Create a GitHub Release with tag `v<version>`
4. CI/CD automatically publishes to PyPI

## CI/CD

The project includes GitHub Actions workflows:

- **test.yml** — runs on push/PR to main: lint, format check, type check, test (3 OS × 3 Python versions)
- **lint.yml** — runs on push/PR: lint + format + type check
- **publish.yml** — runs on release: builds and publishes to PyPI

## Versioning

keeper follows [Semantic Versioning](https://semver.org/):

- **MAJOR** (x.0.0): Breaking API changes
- **MINOR** (0.x.0): New features, backward compatible
- **PATCH** (0.0.x): Bug fixes, backward compatible
