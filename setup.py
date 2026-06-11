from setuptools import setup, find_packages
from pathlib import Path

version_path = Path(__file__).parent / "version.py"
with open(version_path) as f:
    exec(f.read())

setup(
    name="keeper",
    version=locals().get("__version__", "0.2.0"),
    description="AI Agentic Native Firewall — Multi-layer security for LLM applications",
    long_description=(Path(__file__).parent / "README.md").read_text(),
    long_description_content_type="text/markdown",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "keeper": ["config/policies.yaml", "py.typed"],
    },
    install_requires=[
        "fastapi>=0.110.0",
        "uvicorn>=0.27.0",
        "pyyaml>=6.0",
        "httpx>=0.27.0",
        "transformers>=4.38.0",
        "torch>=2.2.0",
        "datasets>=2.18.0",
        "pydantic>=2.5.0",
    ],
    extras_require={
        "semgrep": ["semgrep>=1.60.0"],
        "langchain": ["langchain>=0.2.0"],
        "litellm": ["litellm>=1.30.0"],
        "rust": ["maturin>=1.5.0"],
        "dev": ["pytest>=7.0", "pytest-asyncio>=0.23.0", "ruff>=0.3.0", "black>=24.0"],
    },
    entry_points={
        "console_scripts": [
            "keeper=keeper.main:entry_point",
        ],
    },
    python_requires=">=3.10",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
    ],
)
