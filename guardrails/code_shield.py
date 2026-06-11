# guardrails/code_shield.py
# Static analysis engine for LLM-generated code.
# Uses regex patterns (fast) and Semgrep (deep) to detect
# insecure coding patterns across 8+ programming languages.

import re
import tempfile
import subprocess
from pathlib import Path
from aanf.core.pipeline import RequestContext
from aanf.core.engine import Action


# Quick regex patterns for common insecure practices per language
INSECURE_PATTERNS = {
    "python": [
        (re.compile(r"exec\(.*\)"), "exec() usage"),
        (re.compile(r"eval\(.*\)"), "eval() usage"),
        (re.compile(r"subprocess\.call"), "subprocess call"),
        (re.compile(r"pickle\.load"), "pickle deserialization"),
    ],
    "sql": [
        (re.compile(r"SELECT .* FROM .* WHERE .*\+"), "concatenated SQL"),
        (re.compile(r"EXEC\s*\("), "dynamic SQL execution"),
    ],
    "javascript": [
        (re.compile(r"eval\(.*\)"), "eval() usage"),
        (re.compile(r"innerHTML\s*="), "innerHTML assignment"),
    ],
}


class CodeShield:
    # Two-stage detection: regex pre-filter then optional Semgrep scan.
    name = "code_shield"

    def __init__(self):
        self.semgrep_available = self._check_semgrep()

    def _check_semgrep(self) -> bool:
        # Check if semgrep CLI is installed on the system.
        try:
            subprocess.run(["semgrep", "--version"], capture_output=True, timeout=5)
            return True
        except Exception:
            return False

    async def analyze(self, ctx: RequestContext, config: dict) -> RequestContext:
        # 1) Quick regex check against insecure patterns
        # 2) If available, run Semgrep for deeper syntax-aware analysis
        code = ctx.metadata.get("generated_code", "")
        if not code:
            return ctx

        languages = config.get("languages", ["python"])

        for lang in languages:
            patterns = INSECURE_PATTERNS.get(lang, [])
            for pat, desc in patterns:
                if pat.search(code):
                    ctx.action = Action.BLOCK
                    ctx.violations.append(f"code_shield [{lang}]: {desc}")
                    return ctx

        if self.semgrep_available and languages:
            with tempfile.NamedTemporaryFile(suffix=f".{languages[0]}", delete=False, mode="w") as f:
                f.write(code)
                tmp = f.name
            try:
                result = subprocess.run(
                    ["semgrep", "--quiet", "--json", tmp],
                    capture_output=True, timeout=30
                )
                if result.returncode != 0 and result.stdout:
                    import json
                    data = json.loads(result.stdout)
                    if data.get("results"):
                        ctx.action = Action.BLOCK
                        ctx.violations.append(f"code_shield semgrep: {len(data['results'])} issues")
            finally:
                Path(tmp).unlink(missing_ok=True)

        return ctx
