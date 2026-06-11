# layers/syntactic.py
# Inspects the structure of inputs/outputs for classic web attacks
# (SQL injection, XSS) and obfuscated tokens (escape sequences).
# This is the "syntax" layer — it checks how things are encoded,
# not what they mean.

import re
from aanf.layers.base import BaseLayer
from aanf.core.pipeline import RequestContext
from aanf.core.engine import Action


# Regex patterns for common syntactic attacks
SQL_PATTERNS = [
    re.compile(r"(\bSELECT\b.*\bFROM\b)", re.I),
    re.compile(r"(\bDROP\b.*\bTABLE\b)", re.I),
]

XSS_PATTERNS = [
    re.compile(r"<script[^>]*>", re.I),
    re.compile(r"javascript:", re.I),
]

# Hex/unicode escape sequences used to smuggle tokens
ESCAPE_SEQ = re.compile(r"\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\\0[0-7]{2}")


class SyntacticLayer(BaseLayer):
    name = "syntactic"

    async def analyze(self, ctx: RequestContext, config: dict) -> RequestContext:
        # 1) Enforce max prompt length
        # 2) Block escape sequences (obfuscation)
        # 3) Regex-match SQL injection and XSS patterns
        text = ctx.prompt
        max_len = config.get("max_prompt_length", 4096)

        if len(text) > max_len:
            ctx.action = Action.BLOCK
            ctx.violations.append(f"prompt exceeds {max_len} chars")
            return ctx

        if config.get("block_escape_seq", True):
            if ESCAPE_SEQ.search(text):
                ctx.action = Action.BLOCK
                ctx.violations.append("escape sequence detected")
                return ctx

        for pat in SQL_PATTERNS + XSS_PATTERNS:
            if pat.search(text):
                ctx.action = Action.BLOCK
                ctx.violations.append(f"syntactic violation: {pat.pattern[:40]}")
                return ctx

        return ctx
