# agents/tool_monitor.py
# Inspects tool outputs for indirect prompt injection.
# Attackers can poison web pages, documents, or API responses
# with hidden instructions — this catches those before they
# reach the agent's next reasoning step.

import re
from keeper.core.pipeline import RequestContext
from keeper.core.engine import Action


# Regex patterns for common injection phrases in tool outputs
INJECTION_PATTERNS = [
    re.compile(r"forget\s+(all\s+)?(prior|previous)\s+instructions?", re.I),
    re.compile(r"ignore\s+(all\s+)?(prior|previous)\s+instructions?", re.I),
    re.compile(r"new\s+goal\s+is", re.I),
    re.compile(r"system:\s*override", re.I),
]


class ToolMonitor:
    # Scans tool output text for instruction-override patterns.

    async def inspect_output(self, ctx: RequestContext, tool_output: str) -> RequestContext:
        for pat in INJECTION_PATTERNS:
            if pat.search(tool_output):
                ctx.action = Action.BLOCK
                ctx.violations.append(f"tool_monitor: injection pattern in tool output")
                return ctx
        return ctx
