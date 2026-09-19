/**
 * Conversation-level detectors: zero-trust authority and trajectory analysis.
 *
 * Both exist because of the same observation from the Cognitive Firewall
 * paper: a per-message classifier is structurally blind to attacks whose harm
 * lives in the interaction rather than in any single message.
 *
 * `authority_claim` isolates the manipulation channel where a user asserts a
 * role they cannot prove. Keeper can do something the paper's standalone
 * oversight model cannot — it holds the real authenticated principal, so it
 * compares the claim against verified identity and escalates only on a
 * mismatch.
 *
 * `trajectory` scores the conversation as a whole: refusal grinding
 * (Crescendo), topic drift from a benign opening, and decomposition of one
 * objective into individually innocuous sub-questions (ActorAttack).
 */

import type { DetectorConfig } from "../config.js";
import type { Action, Finding, Message, Span, Stage } from "../types.js";
import { trustAuthority } from "../types.js";
import { Detector, type DetectorInput, register } from "./base.js";

// ---------------------------------------------------------------------------
// Zero-trust context gate
// ---------------------------------------------------------------------------

/** claimId -> pattern. The role that would satisfy it is in ROLE_MAPPING. */
const AUTHORITY_CLAIMS: [string, RegExp][] = [
  ["admin", /\b(?:i\s*(?:'m|\s+am)|as|this\s+is)\s+(?:the\s+|an?\s+)?(?:system\s+)?(?:admin(?:istrator)?|root|superuser|sysadmin)\b/i],
  ["developer", /\b(?:i\s*(?:'m|\s+am)|as|this\s+is)\s+(?:the\s+|an?\s+|one\s+of\s+)?(?:developer|engineer|maintainer|creator|author)s?\b/i],
  ["owner", /\b(?:i\s*(?:'m|\s+am)|as)\s+(?:the\s+)?(?:owner|founder|ceo|cto|director)\b/i],
  ["security", /\b(?:i\s*(?:'m|\s+am)|as)\s+(?:the\s+|an?\s+)?(?:security\s+(?:officer|researcher|team|auditor)|penetration\s+tester|red\s+team(?:er)?|compliance\s+(?:officer|auditor))\b/i],
  ["clinician", /\b(?:i\s*(?:'m|\s+am)|as)\s+(?:the\s+|an?\s+)?(?:doctor|physician|nurse|clinician|pharmacist|md)\b/i],
  ["law_enforcement", /\b(?:i\s*(?:'m|\s+am)|as)\s+(?:an?\s+)?(?:police|law\s+enforcement|federal\s+agent|fbi|investigator)\b/i],
  ["authorised", /\b(?:i\s+(?:have|am\s+given)|you\s+(?:have|are\s+given))\s+(?:full\s+|special\s+|elevated\s+)?(?:authori[sz]ation|permission|clearance|approval|privileges?)\b/i],
  ["policy_override", /\b(?:(?:this|the)\s+(?:is|has\s+been)\s+(?:pre-?)?approved|policy\s+(?:allows|permits)\s+this|i\s+(?:hereby\s+)?authori[sz]e)\b/i],
  ["testing_exemption", /\b(?:this\s+is\s+(?:just\s+)?(?:a\s+)?(?:test|sandbox|staging|debug(?:ging)?)\s+(?:environment|mode|session)?|in\s+(?:test|debug|dev(?:elopment)?)\s+mode)\b/i],
  ["consent_asserted", /\b(?:the\s+user\s+(?:has\s+)?(?:already\s+)?(?:consented|confirmed|approved)|consent\s+(?:has\s+been|was)\s+(?:given|obtained))\b/i],
];

/** Claimed authority -> verified roles that would satisfy it. */
const ROLE_MAPPING: Record<string, string[]> = {
  admin: ["admin", "administrator", "superuser"],
  developer: ["developer", "engineer", "admin"],
  owner: ["owner", "admin"],
  security: ["security", "security_analyst", "admin"],
  clinician: ["clinician", "medical"],
  law_enforcement: [], // never satisfiable from application roles
};

/** Requests that only matter when paired with an authority claim. */
const SENSITIVE_ASK =
  /\b(?:bypass|disable|override|ignore|skip|unlock|escalate|grant|delete\s+all|drop\s+(?:table|database)|reveal|dump|export\s+all|without\s+(?:the\s+)?(?:usual|normal|standard)\s+(?:check|approval|restriction))\w*/i;

class AuthorityClaimDetector extends Detector {
  readonly name = "authority_claim";
  readonly stages: Stage[] = ["input", "retrieval", "tool_result", "memory_write"];
  override readonly category = "authority_manipulation";

  private readonly threshold: number;
  private readonly roleMapping: Record<string, string[]>;
  private readonly actionOnHit: Action;

  constructor(config: DetectorConfig) {
    super(config);
    this.threshold = config.threshold || 0.5;
    this.roleMapping = { ...ROLE_MAPPING, ...(config.options.roleMapping ?? {}) };
    this.actionOnHit = (config.options.action as Action) ?? "challenge";
  }

  detect(data: DetectorInput): Finding {
    const claims: Record<string, unknown>[] = [];
    const spans: Span[] = [];
    const verifiedRoles = new Set(data.context.principal.roles.map((r) => r.toLowerCase()));

    for (const [claimId, pattern] of AUTHORITY_CLAIMS) {
      const match = pattern.exec(data.payload);
      if (!match) continue;
      const satisfying = this.roleMapping[claimId];
      const verified =
        satisfying !== undefined &&
        satisfying.length > 0 &&
        satisfying.some((role) => verifiedRoles.has(role.toLowerCase()));
      claims.push({ claim: claimId, text: match[0].slice(0, 120), verified, verifiedRoles: [...verifiedRoles] });
      spans.push({ start: match.index, end: match.index + match[0].length, label: `authority:${claimId}` });
    }

    if (!claims.length) return this.clean("no authority claims asserted");

    const unverified = claims.filter((c) => !c.verified);
    if (!unverified.length) {
      return this.hit({
        score: 0.1,
        summary: `authority claim(s) ${claims.map((c) => c.claim).join(", ")} match verified roles`,
        severity: "info",
        action: "flag",
        spans,
        evidence: { claims, outcome: "claim_matches_verified_identity" },
      });
    }

    const sensitive = SENSITIVE_ASK.test(data.payload);
    const untrustedSource = trustAuthority(data.trust) <= trustAuthority("tool");
    const authenticated = data.context.principal.authenticated;

    let score = 0.5; // asserting authority you cannot prove
    if (sensitive) score += 0.3; // being cashed in for something
    if (!authenticated) score += 0.1; // nothing at all backs the claim
    if (untrustedSource) score += 0.3; // a *document* claiming authority is an attack
    score = Math.min(1, score);

    const names = unverified.map((c) => c.claim).join(", ");
    if (score < this.threshold) {
      return this.hit({
        score,
        summary: `unverified authority claim: ${names}`,
        severity: "low",
        action: "flag",
        spans,
        evidence: { claims, sensitiveRequest: sensitive },
      });
    }

    return this.hit({
      score,
      summary:
        `unverified authority claim${untrustedSource ? ` asserted by ${data.trust} content` : ""}: ${names}` +
        (sensitive ? " paired with a privileged request" : ""),
      severity: untrustedSource ? "critical" : "high",
      action: untrustedSource ? "block" : this.actionOnHit,
      spans,
      evidence: { claims, sensitiveRequest: sensitive, authenticated, trust: data.trust },
    });
  }
}

// ---------------------------------------------------------------------------
// Consistency / trajectory gate
// ---------------------------------------------------------------------------

const REFUSAL =
  /\b(?:i\s*(?:'m|\s+am)\s+(?:sorry|afraid|unable)|i\s+can(?:'t|not)\s+(?:help|assist|provide|comply)|i\s+(?:won't|will\s+not)\s+(?:provide|help)|that\s+(?:would\s+be|is)\s+against\s+(?:my|our)\s+(?:guidelines|policy)|i\s+must\s+decline)\b/i;

const PERSISTENCE =
  /\b(?:but\s+(?:you|i)\s+(?:just|already)|come\s+on|please\s+just|try\s+again|what\s+if\s+i\s+(?:told|said)|let\s*'?s\s+try\s+(?:again|another\s+way)|rephrase|you\s+(?:said|answered)\s+(?:that|it)\s+(?:before|earlier)|continue\s+from\s+where)\b/i;

/** Coarse topic vocabularies for measuring drift. */
const TOPIC_TERMS: Record<string, Set<string>> = {
  weapons: new Set("explosive explosives detonator bomb firearm ammunition grenade ordnance warhead propellant".split(" ")),
  chem_bio: new Set("synthesis synthesize precursor reagent toxin pathogen culture aerosolize nerve agent enrichment".split(" ")),
  cyber_offense: new Set("exploit payload ransomware keylogger rootkit backdoor privilege escalation exfiltrate c2 botnet".split(" ")),
  fraud: new Set("counterfeit laundering untraceable forged phishing skimmer carding mule".split(" ")),
  self_harm: new Set("overdose lethal dose asphyxiation suicide".split(" ")),
};

class TrajectoryDetector extends Detector {
  readonly name = "trajectory";
  readonly stages: Stage[] = ["input"];
  override readonly category = "multi_turn_attack";

  private readonly threshold: number;
  private readonly window: number;
  private readonly minTurns: number;
  private readonly actionOnHit: Action;

  constructor(config: DetectorConfig) {
    super(config);
    this.threshold = config.threshold || 0.65;
    this.window = config.options.window ?? 12;
    this.minTurns = config.options.minTurns ?? 3;
    this.actionOnHit = (config.options.action as Action) ?? "block";
  }

  detect(data: DetectorInput): Finding {
    const history = data.history.slice(-this.window);
    const userTurns = history.filter((m) => m.role === "user");
    const assistantTurns = history.filter((m) => m.role === "assistant");

    if (userTurns.length < this.minTurns) {
      return this.clean("conversation too short for trajectory analysis", { turns: userTurns.length });
    }

    const refusals = assistantTurns.filter((m) => REFUSAL.test(m.content)).length;
    const persistence = userTurns.filter((m) => PERSISTENCE.test(m.content)).length;
    const refusalPressure = this.refusalPressure(refusals, persistence, userTurns.length);

    const { topic, score: drift, series } = this.topicDrift([
      ...userTurns,
      { role: "user", content: data.payload } as Message,
    ]);
    const decomposition = this.decomposition(userTurns, topic);

    const signals = { refusal_pressure: refusalPressure, topic_drift: drift, decomposition };
    let score = Math.max(...Object.values(signals));
    // Two co-occurring moderate signals are the documented multi-turn shape.
    if (Object.values(signals).filter((v) => v >= 0.4).length >= 2) score = Math.min(1, score + 0.2);

    const evidence = {
      signals: Object.fromEntries(Object.entries(signals).map(([k, v]) => [k, Number(v.toFixed(3))])),
      refusals,
      persistenceMarkers: persistence,
      turnsAnalysed: userTurns.length,
      driftTopic: topic,
      topicDensityPerTurn: series,
    };

    if (score >= this.threshold) {
      const dominant = (Object.keys(signals) as (keyof typeof signals)[]).reduce((a, b) =>
        signals[a] >= signals[b] ? a : b,
      );
      return this.hit({
        score,
        summary:
          `multi-turn attack pattern (${dominant}) across ${userTurns.length} turns` +
          (topic ? ` converging on '${topic}'` : ""),
        severity: "high",
        action: this.actionOnHit,
        evidence,
      });
    }
    if (score >= this.threshold * 0.6) {
      return this.hit({
        score,
        summary: "conversation shows early escalation signals",
        severity: "low",
        action: "flag",
        evidence,
      });
    }
    return this.clean("trajectory nominal", evidence);
  }

  /** A single refusal is normal; repeated refusals the user pushes against are not. */
  private refusalPressure(refusals: number, persistence: number, turns: number): number {
    if (!refusals) return 0;
    let score = Math.min(1, (refusals / Math.max(1, turns)) * 1.5) * 0.6;
    if (persistence) score += Math.min(0.4, 0.15 * persistence);
    return Math.min(1, score);
  }

  private topicDrift(turns: Message[]): { topic: string | null; score: number; series: number[] } {
    const densities: Record<string, number[]> = {};
    for (const name of Object.keys(TOPIC_TERMS)) densities[name] = [];

    for (const message of turns) {
      const words = message.content.toLowerCase().match(/[a-z]+/g) ?? [];
      const total = Math.max(1, words.length);
      for (const [name, vocab] of Object.entries(TOPIC_TERMS)) {
        densities[name].push(words.filter((w) => vocab.has(w)).length / total);
      }
    }

    let bestTopic: string | null = null;
    let bestScore = 0;
    let bestSeries: number[] = [];

    for (const [topic, series] of Object.entries(densities)) {
      if (!series.some((v) => v > 0)) continue;
      const half = Math.max(1, Math.floor(series.length / 2));
      const firstHalf = series.slice(0, half);
      const secondHalf = series.slice(half).length ? series.slice(half) : series.slice(-1);
      const start = firstHalf.reduce((a, b) => a + b, 0) / firstHalf.length;
      const end = secondHalf.reduce((a, b) => a + b, 0) / secondHalf.length;
      if (end <= start) continue;

      const rise = Math.min(1, (end - start) * 40);
      const magnitude = Math.min(1, end * 30);
      let score = Math.min(1, 0.5 * rise + 0.5 * magnitude);
      // A benign opening that drifts is the attack shape; starting on the
      // topic is just an on-topic conversation.
      if (start < 0.005) score = Math.min(1, score + 0.15);

      if (score > bestScore) {
        bestTopic = topic;
        bestScore = score;
        bestSeries = series.map((v) => Number(v.toFixed(4)));
      }
    }
    return { topic: bestTopic, score: bestScore, series: bestSeries };
  }

  private decomposition(userTurns: Message[], topic: string | null): number {
    if (!topic || userTurns.length < 3) return 0;
    const questions = userTurns.map((m) => m.content).filter((c) => c.trim().endsWith("?"));
    if (questions.length < 3) return 0;
    const lengths = questions.map((q) => q.split(/\s+/).length);
    const mean = lengths.reduce((a, b) => a + b, 0) / lengths.length;
    if (mean > 25) return 0; // long discursive questions are not decomposition
    const variance = lengths.reduce((acc, n) => acc + (n - mean) ** 2, 0) / lengths.length;
    const uniformity = 1 / (1 + variance / Math.max(1, mean));
    return Math.min(1, 0.4 + 0.5 * uniformity * Math.min(1, questions.length / 5));
  }
}

register("authority_claim", (config) => new AuthorityClaimDetector(config));
register("trajectory", (config) => new TrajectoryDetector(config));
export { AuthorityClaimDetector, TrajectoryDetector };
