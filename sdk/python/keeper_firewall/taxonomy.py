"""Threat taxonomy: every finding is named in the frameworks a security team reports against.

A detector says *what it saw* ("prompt_injection", "credential_exposure"). A
CISO asks *which risk that is*: "how many LLM01 events did we block this
week?", "do we have any coverage for ASI06?". This module is the translation
between the two, and it is the reason every Keeper audit event carries a
``threats`` list of framework identifiers.

Three OWASP GenAI Security Project lists are mapped, plus MITRE ATLAS
techniques as cross-references:

* **OWASP Top 10 for LLM Applications 2025** — ``LLM01`` … ``LLM10``
* **OWASP Top 10 for Agentic Applications 2026** — ``ASI01`` … ``ASI10``
* **OWASP MCP Top 10 2025** — ``MCP01`` … ``MCP10``
* **MITRE ATLAS** — ``AML.Txxxx`` technique ids, attached to each threat

Mapping is *stage aware*. The same ``prompt_injection`` finding is LLM01 when a
user types it, LLM01 + LLM08 when it arrives inside a retrieved RAG chunk,
LLM01 + MCP06 when a tool/MCP result carries it, and LLM01 + ASI06 when it is
being written into agent memory. The boundary it crossed is part of which risk
it is.

``base_impact`` (1-5) is each threat's default impact on the risk matrix
(:mod:`keeper_firewall.risk`). Organisations override it per threat in policy;
the defaults are deliberately conservative guesses, not measurements.

Threats Keeper cannot address at runtime (training-data poisoning, model supply
chain) are still listed, with ``coverage`` saying so honestly. A coverage report
that only lists what a product is good at is marketing, not a control mapping.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .types import Finding, Stage

OWASP_LLM = "owasp-llm-2025"
OWASP_AGENTIC = "owasp-agentic-2026"
OWASP_MCP = "owasp-mcp-2025"
FRAMEWORKS: tuple[str, ...] = (OWASP_LLM, OWASP_AGENTIC, OWASP_MCP)

#: Coverage levels used by :func:`coverage_report`.
COVERED = "covered"          # runtime detection + enforcement
PARTIAL = "partial"          # some attack paths enforced, others out of reach
OBSERVED = "observed"        # telemetry only: Keeper records, does not prevent
OUT_OF_SCOPE = "out_of_scope"  # not addressable from the request path
DISABLED = "disabled"        # Keeper has a detector for it, and it is switched off


@dataclass(frozen=True, slots=True)
class Threat:
    """One entry in a published threat list."""

    id: str
    framework: str
    title: str
    summary: str
    base_impact: int
    atlas: tuple[str, ...] = ()
    #: Keeper detectors whose findings map to this threat.
    detectors: tuple[str, ...] = ()
    #: Non-detector controls (RBAC, rate limits, memory provenance, …).
    controls: tuple[str, ...] = ()
    coverage: str = COVERED
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "framework": self.framework,
            "title": self.title,
            "summary": self.summary,
            "base_impact": self.base_impact,
            "atlas": list(self.atlas),
            "detectors": list(self.detectors),
            "controls": list(self.controls),
            "coverage": self.coverage,
            "note": self.note,
        }


#: MITRE ATLAS techniques referenced below. Technique names drift between
#: ATLAS releases; the ids are the stable part.
ATLAS: Mapping[str, str] = {
    "AML.T0051": "LLM Prompt Injection",
    "AML.T0051.000": "LLM Prompt Injection: Direct",
    "AML.T0051.001": "LLM Prompt Injection: Indirect",
    "AML.T0054": "LLM Jailbreak",
    "AML.T0056": "Extract LLM System Prompt",
    "AML.T0057": "LLM Data Leakage",
    "AML.T0053": "AI Agent Tool Invocation",
    "AML.T0070": "RAG Poisoning",
    "AML.T0080": "AI Agent Context Poisoning",
    "AML.T0048": "External Harms",
    "AML.T0029": "Denial of AI Service",
    "AML.T0034": "Cost Harvesting",
    "AML.T0024": "Exfiltration via AI Inference API",
    "AML.T0010": "AI Supply Chain Compromise",
    "AML.T0020": "Poison Training Data",
}


def _t(id_: str, fw: str, title: str, summary: str, impact: int, **kw: Any) -> Threat:
    return Threat(id_, fw, title, summary, impact, **kw)


_THREATS: tuple[Threat, ...] = (
    # ------------------------------------------------------------------ LLM
    _t("LLM01", OWASP_LLM, "Prompt Injection",
       "User or third-party content alters the model's behaviour against the operator's intent.", 4,
       atlas=("AML.T0051", "AML.T0054"),
       detectors=("prompt_injection", "llm_classifier", "trajectory", "authority_claim"),
       note="Direct, indirect (RAG/tool/memory), encoded and multi-turn variants."),
    _t("LLM02", OWASP_LLM, "Sensitive Information Disclosure",
       "PII, credentials or confidential data exposed in prompts or responses.", 4,
       atlas=("AML.T0057", "AML.T0024"),
       detectors=("pii", "secrets", "secret_leakage"),
       controls=("redaction",)),
    _t("LLM03", OWASP_LLM, "Supply Chain",
       "Compromised models, datasets, adapters or plugins.", 4,
       atlas=("AML.T0010",), detectors=("tool_poisoning",), controls=("model_allowlist",),
       coverage=PARTIAL,
       note="Keeper governs which models may be called and pins tool definitions; it cannot vet model weights."),
    _t("LLM04", OWASP_LLM, "Data and Model Poisoning",
       "Training, fine-tuning or embedding data manipulated to implant behaviour.", 4,
       atlas=("AML.T0020", "AML.T0070"), detectors=("prompt_injection",),
       coverage=PARTIAL,
       note="Poisoned retrieval content is screened at the retrieval boundary; training-time poisoning is out of reach."),
    _t("LLM05", OWASP_LLM, "Improper Output Handling",
       "Model output passed to downstream systems without validation (XSS, SQLi, shell, markdown exfiltration).", 4,
       atlas=("AML.T0024",), detectors=("unsafe_output",)),
    _t("LLM06", OWASP_LLM, "Excessive Agency",
       "The model is given more functionality, permission or autonomy than the task needs.", 4,
       atlas=("AML.T0053",), detectors=("token_flow",),
       controls=("tool_rbac", "tool_risk_tiers", "human_confirmation")),
    _t("LLM07", OWASP_LLM, "System Prompt Leakage",
       "Instructions, secrets or business logic in the system prompt revealed to users.", 3,
       atlas=("AML.T0056",), detectors=("system_prompt_leakage", "prompt_injection")),
    _t("LLM08", OWASP_LLM, "Vector and Embedding Weaknesses",
       "RAG pipelines ingest or return content that injects, leaks across tenants, or poisons context.", 3,
       atlas=("AML.T0070",), detectors=("prompt_injection", "pii", "secrets"),
       coverage=PARTIAL,
       note="Retrieved chunks are screened before entering context; vector-store access control is the store's job."),
    _t("LLM09", OWASP_LLM, "Misinformation",
       "Confident, ungrounded or fabricated output relied on by users.", 2,
       detectors=("groundedness",), coverage=PARTIAL,
       note="Lexical groundedness screen; flags, never blocks."),
    _t("LLM10", OWASP_LLM, "Unbounded Consumption",
       "Excessive or adversarial usage causing denial of service, cost blow-up or model extraction.", 3,
       atlas=("AML.T0029", "AML.T0034"), detectors=("resource_abuse",),
       controls=("rate_limits", "token_budgets")),
    # -------------------------------------------------------------- Agentic
    _t("ASI01", OWASP_AGENTIC, "Agent Goal Hijack",
       "Injected content redirects an agent's objectives, plans or decision path.", 4,
       atlas=("AML.T0051.001",), detectors=("prompt_injection", "trajectory", "token_flow")),
    _t("ASI02", OWASP_AGENTIC, "Tool Misuse & Exploitation",
       "An agent uses legitimate tools unsafely: wrong arguments, wrong sink, chained exfiltration.", 4,
       atlas=("AML.T0053",), detectors=("token_flow", "code_execution"),
       controls=("tool_rbac", "tool_risk_tiers")),
    _t("ASI03", OWASP_AGENTIC, "Identity & Privilege Abuse",
       "Agents inherit, escalate or are tricked into using privileges they should not.", 4,
       detectors=("authority_claim",), controls=("authentication", "rbac", "tool_rbac")),
    _t("ASI04", OWASP_AGENTIC, "Agentic Supply Chain Vulnerabilities",
       "Compromised tools, MCP servers, prompts or agents loaded at runtime.", 4,
       atlas=("AML.T0010",), detectors=("tool_poisoning",), controls=("tool_definition_pinning",),
       coverage=PARTIAL),
    _t("ASI05", OWASP_AGENTIC, "Unexpected Code Execution (RCE)",
       "Agent-generated or injected code/commands executed without sandboxing.", 5,
       detectors=("code_execution", "unsafe_output")),
    _t("ASI06", OWASP_AGENTIC, "Memory & Context Poisoning",
       "Persistent memory or long context corrupted so future decisions are manipulated.", 4,
       atlas=("AML.T0080", "AML.T0070"), detectors=("prompt_injection", "token_flow"),
       controls=("memory_provenance",)),
    _t("ASI07", OWASP_AGENTIC, "Insecure Inter-Agent Communication",
       "Messages between agents spoofed, tampered or used to smuggle instructions.", 3,
       detectors=("prompt_injection", "authority_claim"), controls=("trust_levels",),
       coverage=PARTIAL,
       note="Peer-agent messages are screened as tool-trust content; message signing is out of scope."),
    _t("ASI08", OWASP_AGENTIC, "Cascading Failures",
       "One faulty or compromised step propagates through a multi-agent workflow.", 3,
       controls=("kill_switch", "fail_modes"), coverage=PARTIAL,
       note="Per-run kill switch halts every later stage of a correlation once tripped."),
    _t("ASI09", OWASP_AGENTIC, "Human-Agent Trust Exploitation",
       "Agents manipulate humans into approving harmful actions, or humans over-trust agent output.", 3,
       detectors=("authority_claim", "groundedness"), controls=("human_confirmation",),
       coverage=PARTIAL),
    _t("ASI10", OWASP_AGENTIC, "Rogue Agents",
       "Agents acting outside intended scope through drift, compromise or emergent behaviour.", 4,
       detectors=("trajectory", "token_flow"), controls=("kill_switch", "anomaly_detection"),
       coverage=PARTIAL),
    # ------------------------------------------------------------------ MCP
    _t("MCP01", OWASP_MCP, "Token Mismanagement & Secret Exposure",
       "Credentials held by or passed through MCP servers leak into context, logs or output.", 5,
       atlas=("AML.T0057",), detectors=("secrets", "secret_leakage"), controls=("redaction",)),
    _t("MCP02", OWASP_MCP, "Privilege Escalation via Scope Creep",
       "Tools or servers accumulate permissions beyond what the task requires.", 4,
       controls=("tool_rbac", "tool_risk_tiers"), detectors=("token_flow",)),
    _t("MCP03", OWASP_MCP, "Tool Poisoning",
       "Malicious instructions hidden in tool names, descriptions or schemas; rug-pull redefinition.", 4,
       atlas=("AML.T0051.001",), detectors=("tool_poisoning",), controls=("tool_definition_pinning",)),
    _t("MCP04", OWASP_MCP, "Software Supply Chain Attacks & Dependency Tampering",
       "Compromised MCP server packages or dependencies.", 4,
       atlas=("AML.T0010",), controls=("tool_definition_pinning",), coverage=PARTIAL,
       note="Definition pinning catches behavioural change; package provenance belongs in your build pipeline."),
    _t("MCP05", OWASP_MCP, "Command Injection & Execution",
       "Tool arguments reach a shell, interpreter or query engine unsanitised.", 5,
       detectors=("code_execution",)),
    _t("MCP06", OWASP_MCP, "Prompt Injection via Contextual Payloads",
       "Instructions smuggled in tool results, resources or fetched content.", 4,
       atlas=("AML.T0051.001",), detectors=("prompt_injection",)),
    _t("MCP07", OWASP_MCP, "Insufficient Authentication & Authorization",
       "MCP clients or servers accept unauthenticated or over-authorised calls.", 4,
       controls=("authentication", "rbac", "tool_rbac"), coverage=PARTIAL),
    _t("MCP08", OWASP_MCP, "Lack of Audit and Telemetry",
       "Tool invocations and context changes are not logged or monitored.", 3,
       controls=("audit_events", "metrics", "tracing", "siem_export")),
    _t("MCP09", OWASP_MCP, "Shadow MCP Servers",
       "Unapproved MCP servers used outside governance.", 3,
       controls=("tool_registry", "fleet_inventory"), coverage=OBSERVED,
       note="Unregistered tools are refused when a tool registry is configured, and surfaced in the fleet view."),
    _t("MCP10", OWASP_MCP, "Context Injection & Over-Sharing",
       "More context than necessary (other users' data, secrets) is shared with tools or models.", 3,
       detectors=("pii", "secrets"), controls=("redaction",)),
)

THREATS: Mapping[str, Threat] = {t.id: t for t in _THREATS}


# ---------------------------------------------------------------------------
# Finding -> threat mapping
# ---------------------------------------------------------------------------

#: Base mapping from a finding's ``category`` to threat ids, before stage rules.
CATEGORY_THREATS: Mapping[str, tuple[str, ...]] = {
    "prompt_injection": ("LLM01", "ASI01"),
    "authority_manipulation": ("LLM01", "ASI03", "ASI09"),
    "multi_turn_attack": ("LLM01", "ASI01"),
    "credential_exposure": ("LLM02", "MCP01"),
    "data_leakage": ("LLM02", "MCP01"),
    "sensitive_data": ("LLM02", "MCP10"),
    "content_policy": (),
    "hallucination": ("LLM09",),
    "unsafe_flow": ("LLM06", "ASI02", "ASI01"),
    "excessive_agency": ("LLM06", "ASI02", "MCP02"),
    "memory_provenance_laundering": ("ASI06",),
    "access_control": ("ASI03", "MCP07"),
    "rate_limit": ("LLM10",),
    "system_prompt_leakage": ("LLM07",),
    "improper_output": ("LLM05",),
    "code_execution": ("ASI05", "MCP05"),
    "tool_poisoning": ("MCP03", "ASI04", "LLM03"),
    "unbounded_consumption": ("LLM10",),
}

#: Extra threats implied by *where* a finding of a given category was raised.
STAGE_THREATS: Mapping[tuple[str, Stage], tuple[str, ...]] = {
    ("prompt_injection", Stage.RETRIEVAL): ("LLM08", "LLM04"),
    ("prompt_injection", Stage.TOOL_RESULT): ("MCP06",),
    ("prompt_injection", Stage.MEMORY_WRITE): ("ASI06",),
    ("prompt_injection", Stage.MEMORY_READ): ("ASI06",),
    ("prompt_injection", Stage.OUTPUT): ("LLM05",),
    ("prompt_injection", Stage.TOOL_DEFINITION): ("MCP03", "ASI04"),
    ("sensitive_data", Stage.RETRIEVAL): ("LLM08",),
    ("credential_exposure", Stage.TOOL_CALL): ("ASI02",),
    ("authority_manipulation", Stage.TOOL_RESULT): ("ASI07",),
}

#: Stage rules that *replace* the category mapping rather than extend it. A
#: flow finding on a memory write is about what gets persisted, not about a
#: tool being misused, so naming it LLM06/ASI02 would inflate both reports.
STAGE_OVERRIDES: Mapping[tuple[str, Stage], tuple[str, ...]] = {
    ("unsafe_flow", Stage.MEMORY_WRITE): ("ASI06",),
    ("unsafe_flow", Stage.MEMORY_READ): ("ASI06",),
}

#: Categories that never map to a threat (internal plumbing).
_INTERNAL = frozenset({"firewall_internal", "policy", "unspecified"})


def threats_for(finding: Finding, stage: Stage) -> tuple[str, ...]:
    """Threat ids for one fired finding at one stage, in stable order.

    A detector can name its threats explicitly with ``evidence["threats"]``;
    that list is used *in addition to* the category mapping, so a custom
    detector can be precise without having to re-declare the obvious.
    """
    if not finding.detected or finding.category in _INTERNAL:
        return ()
    key = (finding.category, stage)
    if key in STAGE_OVERRIDES:
        ids: list[str] = list(STAGE_OVERRIDES[key])
    else:
        ids = list(CATEGORY_THREATS.get(finding.category, ()))
        ids.extend(STAGE_THREATS.get(key, ()))
    explicit = finding.evidence.get("threats") if isinstance(finding.evidence, Mapping) else None
    if isinstance(explicit, list | tuple):
        ids.extend(str(x) for x in explicit)
    return tuple(dict.fromkeys(i for i in ids if i in THREATS))


def annotate(findings: Iterable[Finding], stage: Stage) -> tuple[Finding, ...]:
    """Stamp ``threats`` onto every fired finding. Returns the same objects."""
    out = tuple(findings)
    for f in out:
        f.threats = threats_for(f, stage)
    return out


def threat_ids(findings: Iterable[Finding]) -> tuple[str, ...]:
    """The union of threat ids across findings, in framework order."""
    seen: set[str] = set()
    for f in findings:
        seen.update(f.threats)
    return tuple(t for t in THREATS if t in seen)


def atlas_for(ids: Iterable[str]) -> tuple[str, ...]:
    out: dict[str, None] = {}
    for i in ids:
        threat = THREATS.get(i)
        if threat:
            out.update(dict.fromkeys(threat.atlas))
    return tuple(out)


# ---------------------------------------------------------------------------
# Coverage
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class CoverageRow:
    threat: Threat
    active_detectors: tuple[str, ...]
    missing_detectors: tuple[str, ...]
    status: str
    hits: int = 0

    def to_dict(self) -> dict[str, Any]:
        d = self.threat.to_dict()
        d.update(
            active_detectors=list(self.active_detectors),
            missing_detectors=list(self.missing_detectors),
            status=self.status,
            hits=self.hits,
        )
        return d


def coverage_report(
    enabled_detectors: Sequence[str] | None = None,
    *,
    frameworks: Sequence[str] = FRAMEWORKS,
    hits: Mapping[str, int] | None = None,
) -> list[CoverageRow]:
    """Which threats this deployment actually covers, given what is switched on.

    A threat mapped to detectors that are all disabled drops from its
    declared coverage to ``observed`` (if non-detector controls remain) or
    ``disabled``: switching a detector off must show up in the report.
    """
    enabled = set(enabled_detectors) if enabled_detectors is not None else None
    rows: list[CoverageRow] = []
    for threat in _THREATS:
        if threat.framework not in frameworks:
            continue
        active: tuple[str, ...]
        missing: tuple[str, ...]
        if enabled is None:
            active, missing = threat.detectors, ()
        else:
            active = tuple(d for d in threat.detectors if d in enabled)
            missing = tuple(d for d in threat.detectors if d not in enabled)
        status = threat.coverage
        if threat.detectors and not active:
            status = OBSERVED if threat.controls else DISABLED
        elif missing and status == COVERED:
            status = PARTIAL
        rows.append(CoverageRow(threat, active, missing, status, (hits or {}).get(threat.id, 0)))
    return rows


__all__ = [
    "ATLAS",
    "CATEGORY_THREATS",
    "COVERED",
    "DISABLED",
    "FRAMEWORKS",
    "OBSERVED",
    "OUT_OF_SCOPE",
    "OWASP_AGENTIC",
    "OWASP_LLM",
    "OWASP_MCP",
    "PARTIAL",
    "STAGE_OVERRIDES",
    "STAGE_THREATS",
    "THREATS",
    "CoverageRow",
    "Threat",
    "annotate",
    "atlas_for",
    "coverage_report",
    "threat_ids",
    "threats_for",
]
