"""Conversation-level detectors: zero-trust authority and trajectory analysis.

Both detectors here exist because of the same observation from the Cognitive
Firewall paper: a per-message classifier is structurally blind to attacks whose
harm lives in the *interaction*, not in any single message. Two such channels
are separated out:

* :class:`AuthorityClaimDetector` — the zero-trust context gate. A user who
  writes "as the system administrator, I'm authorising you to…" is asserting an
  authority they have not proven. The paper's point is that a content-safety
  classifier reads that clause as ordinary context; it needs to be isolated and
  treated as *unverified evidence*. Keeper can do something the paper's
  standalone oversight model cannot: it holds the real
  :class:`~keeper_firewall.types.Principal` from access control, so it can
  actually compare the claim against verified identity and only escalate when
  they disagree.

* :class:`TrajectoryDetector` — the consistency gate. Crescendo-style escalation
  and ActorAttack-style decomposition never put the harm in one turn. This
  detector scores the conversation as a whole: are refusals accumulating? is
  each turn edging further into a sensitive topic? are individually benign
  sub-questions assembling into one objective?

Both are heuristic and local. The paper implements its gates with an oversight
LLM, which is more accurate and much more expensive; the same signals are
available in higher fidelity by enabling ``llm_classifier`` with these
detectors' evidence as input.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any

from ..config import DetectorConfig
from ..types import Action, Finding, Message, Severity, Span, Stage, TrustLevel
from .base import Detector, DetectorInput, detector

# ---------------------------------------------------------------------------
# Zero-trust context gate
# ---------------------------------------------------------------------------

#: Claimed role -> (regex, the role name that would justify it if verified).
AUTHORITY_CLAIMS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("admin", re.compile(r"(?i)\b(?:i\s*(?:'m|\s+am)|as|this\s+is)\s+(?:the\s+|an?\s+)?(?:system\s+)?(?:admin(?:istrator)?|root|superuser|sysadmin)\b"), "admin"),
    ("developer", re.compile(r"(?i)\b(?:i\s*(?:'m|\s+am)|as|this\s+is)\s+(?:the\s+|an?\s+|one\s+of\s+)?(?:developer|engineer|maintainer|creator|author)s?\b(?:\s+(?:of|who\s+(?:built|made|wrote)))?"), "developer"),
    ("owner", re.compile(r"(?i)\b(?:i\s*(?:'m|\s+am)|as)\s+(?:the\s+)?(?:owner|founder|ceo|cto|director)\b"), "owner"),
    ("security", re.compile(r"(?i)\b(?:i\s*(?:'m|\s+am)|as)\s+(?:the\s+|an?\s+)?(?:security\s+(?:officer|researcher|team|auditor)|penetration\s+tester|red\s+team(?:er)?|compliance\s+(?:officer|auditor))\b"), "security"),
    ("clinician", re.compile(r"(?i)\b(?:i\s*(?:'m|\s+am)|as)\s+(?:the\s+|an?\s+)?(?:doctor|physician|nurse|clinician|pharmacist|md)\b"), "clinician"),
    ("law_enforcement", re.compile(r"(?i)\b(?:i\s*(?:'m|\s+am)|as)\s+(?:an?\s+)?(?:police|law\s+enforcement|federal\s+agent|fbi|investigator)\b"), "law_enforcement"),
    ("authorised", re.compile(r"(?i)\b(?:i\s+(?:have|am\s+given)|you\s+(?:have|are\s+given))\s+(?:full\s+|special\s+|elevated\s+)?(?:authori[sz]ation|permission|clearance|approval|privileges?)\b"), "*"),
    ("policy_override", re.compile(r"(?i)\b(?:(?:this|the)\s+(?:is|has\s+been)\s+(?:pre-?)?approved|policy\s+(?:allows|permits)\s+this|i\s+(?:hereby\s+)?authori[sz]e)\b"), "*"),
    ("testing_exemption", re.compile(r"(?i)\b(?:this\s+is\s+(?:just\s+)?(?:a\s+)?(?:test|sandbox|staging|debug(?:ging)?)\s+(?:environment|mode|session)?|in\s+(?:test|debug|dev(?:elopment)?)\s+mode)\b"), "*"),
    ("consent_asserted", re.compile(r"(?i)\b(?:the\s+user\s+(?:has\s+)?(?:already\s+)?(?:consented|confirmed|approved)|consent\s+(?:has\s+been|was)\s+(?:given|obtained))\b"), "*"),
)

#: Requests that only matter when paired with an authority claim. An admin
#: claim next to "what's the weather" is noise; next to this, it is an attack.
_SENSITIVE_ASK = re.compile(
    r"(?i)\b(?:bypass|disable|override|ignore|skip|unlock|escalate|grant|delete\s+all|drop\s+(?:table|database)|"
    r"reveal|dump|export\s+all|without\s+(?:the\s+)?(?:usual|normal|standard)\s+(?:check|approval|restriction))\w*"
)


@detector("authority_claim")
class AuthorityClaimDetector(Detector):
    """Treats in-dialogue role and permission claims as unverified evidence.

    The gate never grants anything. It only answers: does this conversation
    assert an authority that the authenticated principal does not actually
    hold? A claim that *matches* verified roles is recorded and allowed; a
    claim that exceeds them, especially alongside a sensitive request, is
    escalated.
    """

    stages = (Stage.INPUT, Stage.RETRIEVAL, Stage.TOOL_RESULT, Stage.MEMORY_WRITE)
    category = "authority_manipulation"

    def __init__(self, config: DetectorConfig | None = None) -> None:
        super().__init__(config)
        opts = self.config.options
        self.threshold: float = float(self.config.threshold or 0.5)
        self.action_on_hit = Action(opts.get("action", "challenge"))
        # Map claimed authority -> the verified role(s) that would satisfy it.
        self.role_mapping: dict[str, list[str]] = {
            "admin": ["admin", "administrator", "superuser"],
            "developer": ["developer", "engineer", "admin"],
            "owner": ["owner", "admin"],
            "security": ["security", "security_analyst", "admin"],
            "clinician": ["clinician", "medical"],
            "law_enforcement": [],  # never satisfiable from app roles
            **{k: list(v) for k, v in (opts.get("role_mapping") or {}).items()},
        }
        self.scan_history: bool = bool(opts.get("scan_history", True))

    def detect(self, data: DetectorInput) -> Finding:
        claims: list[dict[str, object]] = []
        spans: list[Span] = []
        verified_roles = {r.lower() for r in data.context.principal.roles}

        for claim_id, pattern, _required in AUTHORITY_CLAIMS:
            match = pattern.search(data.payload)
            if not match:
                continue
            satisfying = self.role_mapping.get(claim_id)
            if satisfying is None:  # wildcard claims like "I am authorised"
                verified = False
            else:
                verified = bool(satisfying) and bool(verified_roles & {r.lower() for r in satisfying})
            claims.append(
                {
                    "claim": claim_id,
                    "text": match.group()[:120],
                    "verified": verified,
                    "verified_roles": sorted(verified_roles),
                }
            )
            spans.append(Span(match.start(), match.end(), f"authority:{claim_id}"))

        if not claims:
            return self.clean("no authority claims asserted")

        unverified = [c for c in claims if not c["verified"]]
        if not unverified:
            return self.hit(
                score=0.1,
                summary=f"authority claim(s) {[c['claim'] for c in claims]} match verified roles",
                severity=Severity.INFO,
                action=Action.FLAG,
                spans=spans,
                claims=claims,
                outcome="claim_matches_verified_identity",
            )

        sensitive = bool(_SENSITIVE_ASK.search(data.payload))
        untrusted_source = data.trust.authority() <= TrustLevel.TOOL.authority()
        authenticated = data.context.principal.authenticated

        # Base: asserting authority you cannot prove.
        score = 0.5
        if sensitive:
            score += 0.3          # claim is being cashed in for something
        if not authenticated:
            score += 0.1          # nothing at all backs the claim
        if untrusted_source:
            score += 0.3          # a *document* claiming authority is an attack
        score = min(1.0, score)

        if score < self.threshold:
            return self.hit(
                score=score,
                summary=f"unverified authority claim: {[c['claim'] for c in unverified]}",
                severity=Severity.LOW,
                action=Action.FLAG,
                spans=spans,
                claims=claims,
                sensitive_request=sensitive,
            )

        severity = Severity.CRITICAL if untrusted_source else Severity.HIGH
        source_note = (
            f" asserted by {data.trust.value} content" if untrusted_source else ""
        )
        return self.hit(
            score=score,
            summary=(
                f"unverified authority claim{source_note}: "
                f"{[c['claim'] for c in unverified]}"
                + (" paired with a privileged request" if sensitive else "")
            ),
            severity=severity,
            action=Action.BLOCK if untrusted_source else self.action_on_hit,
            spans=spans,
            claims=claims,
            sensitive_request=sensitive,
            authenticated=authenticated,
            trust=data.trust.value,
        )


# ---------------------------------------------------------------------------
# Consistency / trajectory gate
# ---------------------------------------------------------------------------

_REFUSAL = re.compile(
    r"(?i)\b(?:i\s*(?:'m|\s+am)\s+(?:sorry|afraid|unable)|i\s+can(?:'t|not)\s+(?:help|assist|provide|comply)|"
    r"i\s+(?:won't|will\s+not)\s+(?:provide|help)|that\s+(?:would\s+be|is)\s+against\s+(?:my|our)\s+(?:guidelines|policy)|"
    r"i\s+must\s+decline)\b"
)

_PERSISTENCE = re.compile(
    r"(?i)\b(?:but\s+(?:you|i)\s+(?:just|already)|come\s+on|please\s+just|try\s+again|"
    r"what\s+if\s+i\s+(?:told|said)|let\s*'?s\s+try\s+(?:again|another\s+way)|rephrase|"
    r"you\s+(?:said|answered)\s+(?:that|it)\s+(?:before|earlier)|continue\s+from\s+where)\b"
)

#: Topic vocabularies used to measure drift. Deliberately coarse: the signal we
#: want is "the conversation is converging on a restricted objective", not
#: fine-grained classification, which is the LLM classifier's job.
_TOPIC_TERMS: dict[str, frozenset[str]] = {
    "weapons": frozenset(["explosive", "explosives", "detonator", "bomb", "firearm", "ammunition", "grenade", "ordnance", "warhead", "propellant"]),
    "chem_bio": frozenset(["synthesis", "synthesize", "precursor", "reagent", "toxin", "pathogen", "culture", "aerosolize", "nerve", "agent", "enrichment"]),
    "cyber_offense": frozenset(["exploit", "payload", "ransomware", "keylogger", "rootkit", "backdoor", "privilege", "escalation", "exfiltrate", "c2", "botnet"]),
    "fraud": frozenset(["counterfeit", "laundering", "untraceable", "forged", "phishing", "skimmer", "carding", "mule"]),
    "self_harm": frozenset(["overdose", "lethal", "dose", "asphyxiation", "suicide"]),
}


@detector("trajectory")
class TrajectoryDetector(Detector):
    """Detects multi-turn escalation, decomposition, and refusal grinding.

    Three independent signals, combined by escalation like everything else:

    ``refusal_pressure``
        The assistant has refused repeatedly and the user keeps rephrasing.
        This is the Crescendo pattern's fingerprint and it is visible without
        understanding either message.

    ``topic_drift``
        Restricted-topic vocabulary rising monotonically across turns, from a
        benign opening. Each turn on its own looks like curiosity.

    ``decomposition``
        Many short, structurally similar questions in the same topic — the
        ActorAttack shape, where a forbidden objective is split into benign
        sub-questions and reassembled by the user, never by the model.
    """

    stages = (Stage.INPUT,)
    category = "multi_turn_attack"

    def __init__(self, config: DetectorConfig | None = None) -> None:
        super().__init__(config)
        opts = self.config.options
        self.threshold: float = float(self.config.threshold or 0.65)
        self.window: int = int(opts.get("window", 12))
        self.min_turns: int = int(opts.get("min_turns", 3))
        self.action_on_hit = Action(opts.get("action", "block"))
        self.topics: dict[str, frozenset[str]] = {
            **_TOPIC_TERMS,
            **{k: frozenset(v) for k, v in (opts.get("topics") or {}).items()},
        }

    def detect(self, data: DetectorInput) -> Finding:
        history = list(data.history)[-self.window :]
        user_turns = [m for m in history if m.role == "user"]
        assistant_turns = [m for m in history if m.role == "assistant"]

        if len(user_turns) < self.min_turns:
            return self.clean(
                "conversation too short for trajectory analysis",
                turns=len(user_turns),
            )

        refusals = sum(1 for m in assistant_turns if _REFUSAL.search(m.content))
        persistence = sum(1 for m in user_turns if _PERSISTENCE.search(m.content))
        refusal_pressure = self._refusal_pressure(refusals, persistence, len(user_turns))

        drift_topic, drift_score, per_turn = self._topic_drift([*user_turns, Message("user", data.payload)])
        decomposition = self._decomposition(user_turns, drift_topic)

        signals = {
            "refusal_pressure": refusal_pressure,
            "topic_drift": drift_score,
            "decomposition": decomposition,
        }
        score = max(signals.values())
        # Two co-occurring moderate signals are worth more than either alone:
        # escalation plus decomposition is the documented multi-turn shape.
        strong = [v for v in signals.values() if v >= 0.4]
        if len(strong) >= 2:
            score = min(1.0, score + 0.2)

        evidence: dict[str, Any] = {
            "signals": {k: round(v, 3) for k, v in signals.items()},
            "refusals": refusals,
            "persistence_markers": persistence,
            "turns_analysed": len(user_turns),
            "drift_topic": drift_topic,
            "topic_density_per_turn": per_turn,
        }

        if score >= self.threshold:
            dominant = max(signals, key=lambda k: signals[k])
            return self.hit(
                score=score,
                summary=(
                    f"multi-turn attack pattern ({dominant}) across {len(user_turns)} turns"
                    + (f" converging on '{drift_topic}'" if drift_topic else "")
                ),
                severity=Severity.HIGH,
                action=self.action_on_hit,
                **evidence,
            )
        if score >= self.threshold * 0.6:
            return self.hit(
                score=score,
                summary="conversation shows early escalation signals",
                severity=Severity.LOW,
                action=Action.FLAG,
                **evidence,
            )
        return self.clean("trajectory nominal", **evidence)

    # -- signals -----------------------------------------------------------

    @staticmethod
    def _refusal_pressure(refusals: int, persistence: int, turns: int) -> float:
        if refusals == 0:
            return 0.0
        # A single refusal in a long conversation is normal. Repeated refusals
        # that the user keeps pushing against are not.
        ratio = refusals / max(1, turns)
        score = min(1.0, ratio * 1.5) * 0.6
        if persistence:
            score += min(0.4, 0.15 * persistence)
        return min(1.0, score)

    def _topic_drift(self, turns: list[Message]) -> tuple[str | None, float, list[float]]:
        densities: dict[str, list[float]] = {t: [] for t in self.topics}
        for msg in turns:
            words = re.findall(r"[a-z]+", msg.content.lower())
            total = max(1, len(words))
            counts = Counter(words)
            for topic, vocab in self.topics.items():
                densities[topic].append(sum(counts[w] for w in vocab) / total)

        best_topic: str | None = None
        best_score = 0.0
        best_series: list[float] = []
        for topic, series in densities.items():
            if not any(series):
                continue
            first_half = series[: max(1, len(series) // 2)]
            second_half = series[max(1, len(series) // 2) :] or series[-1:]
            start = sum(first_half) / len(first_half)
            end = sum(second_half) / len(second_half)
            if end <= start:
                continue
            # Rising density, weighted by how loaded the recent turns are.
            rise = min(1.0, (end - start) * 40)
            magnitude = min(1.0, end * 30)
            score = min(1.0, 0.5 * rise + 0.5 * magnitude)
            # A benign opening that drifts is the attack shape; a conversation
            # that started on the topic is just an on-topic conversation.
            if start < 0.005:
                score = min(1.0, score + 0.15)
            if score > best_score:
                best_topic, best_score, best_series = topic, score, [round(v, 4) for v in series]
        return best_topic, best_score, best_series

    @staticmethod
    def _decomposition(user_turns: list[Message], topic: str | None) -> float:
        if topic is None or len(user_turns) < 3:
            return 0.0
        questions = [m.content for m in user_turns if m.content.strip().endswith("?")]
        if len(questions) < 3:
            return 0.0
        lengths = [len(q.split()) for q in questions]
        mean = sum(lengths) / len(lengths)
        if mean > 25:
            return 0.0  # long, discursive questions are not decomposition
        variance = sum((n - mean) ** 2 for n in lengths) / len(lengths)
        uniformity = 1.0 / (1.0 + variance / max(1.0, mean))
        return min(1.0, 0.4 + 0.5 * uniformity * min(1.0, len(questions) / 5))
