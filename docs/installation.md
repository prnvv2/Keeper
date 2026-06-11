# Installation Guide

## Prerequisites

- Python 3.10 or higher
- [Ollama](https://ollama.com) (required for semantic analysis, context drift detection, and alignment auditing)
  - Start: `ollama serve`
  - Pull a model: `ollama pull llama3.2`

## Install from PyPI

```bash
pip install aanf
```

This installs the core framework with all required dependencies.

## Install with Optional Features

```bash
# LangChain integration
pip install aanf[langchain]

# LiteLLM proxy support
pip install aanf[litellm]

# Semgrep code analysis
pip install aanf[semgrep]

# All optional integrations
pip install aanf[all]

# Development tools
pip install aanf[dev]
```

## Install from Source

```bash
git clone https://github.com/anomalyco/aanf.git
cd aanf
pip install -e ".[dev]"
```

## Verify Installation

```bash
python -c "import aanf; print(aanf.__version__)"
```

## Build Rust Scanner (Optional)

For high-performance token scanning:

```bash
cd scanner
cargo build --release
```

Or install as a Python module via PyO3:

```bash
pip install maturin
cd scanner
maturin develop --release
```

## Docker (Coming Soon)

```dockerfile
FROM python:3.11-slim
RUN pip install aanf
CMD ["aanf", "--server"]
```
