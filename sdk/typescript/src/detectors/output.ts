/**
 * Output-side detectors: leaked secrets, banned content, groundedness.
 *
 * Output filtering asks a different question from input filtering. On the way
 * in: is this trying to subvert the model? On the way out: does this disclose
 * something it should not, or assert something the context does not support?
 */

import type { DetectorConfig } from "../config.js";
import type { Action, Finding, Severity, Span, Stage } from "../types.js";
import { Detector, type DetectorInput, register } from "./base.js";
import { VENDOR_PATTERNS } from "./secrets.js";

const SEVERITY_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

/** Drop spans fully contained in another, keeping the outermost. */
function dedupe(spans: Span[]): Span[] {
  const ordered = [...spans].sort((a, b) => a.start - b.start || b.end - a.end);
  const out: Span[] = [];
  for (const span of ordered) {
    const last = out[out.length - 1];
    if (last && span.start >= last.start && span.end <= last.end) continue;
    out.push(span);
  }
  return out;
}

/**
 * Detects known-confidential values echoed in a response.
 *
 * The host application registers what it considers confidential — the system
 * prompt, tenant records, config secrets — and only salted hashes are kept, so
 * the detector never holds a second plaintext copy of anyone's secret.
 *
 * Matching is exact-substring on registered lengths. Semantic leakage (the
 * model *describing* a secret rather than quoting it) is out of scope and
 * documented as such in docs/threat-model.md.
 */
class SecretLeakageDetector extends Detector {
  readonly name = "secret_leakage";
  readonly stages: Stage[] = ["output", "stream", "tool_call"];
  override readonly category = "data_leakage";
  override readonly mutates = true;

  private readonly minLength: number;
  private readonly actionOnHit: Action;
  private readonly salt: string;
  private readonly hashes = new Map<string, string>(); // digest -> label
  private readonly lengths = new Set<number>();

  constructor(config: DetectorConfig) {
    super(config);
    this.minLength = config.options.minLength ?? 8;
    this.actionOnHit = (config.options.action as Action) ?? "block";
    this.salt = config.options.salt ?? "keeper";
    for (const [label, value] of Object.entries((config.options.secrets ?? {}) as Record<string, string>)) {
      this.register(value, label);
    }
  }

  /** Register a confidential value. Only its salted digest is retained. */
  register(value: string, label = "registered_secret"): void {
    const trimmed = value.trim();
    if (trimmed.length < this.minLength) return;
    this.hashes.set(this.digest(trimmed), label);
    this.lengths.add(trimmed.length);
  }

  /**
   * FNV-1a over the salted value. Not a cryptographic commitment — it never
   * leaves the process and only has to make an accidental plaintext copy of a
   * secret impossible in a heap dump.
   */
  private digest(value: string): string {
    const input = this.salt + value;
    let hash = 0x811c9dc5;
    for (let i = 0; i < input.length; i++) {
      hash ^= input.charCodeAt(i);
      hash = Math.imul(hash, 0x01000193) >>> 0;
    }
    return hash.toString(16).padStart(8, "0") + ":" + input.length.toString(16);
  }

  detect(data: DetectorInput): Finding {
    const spans: Span[] = [];
    const payload = data.payload;

    if (this.hashes.size && payload) {
      // Only registered lengths are candidates, so this is
      // O(len(payload) * distinct lengths), not quadratic.
      for (const length of this.lengths) {
        for (let i = 0; i + length <= payload.length; i++) {
          const label = this.hashes.get(this.digest(payload.slice(i, i + length)));
          if (label) spans.push({ start: i, end: i + length, label: `leaked:${label}` });
        }
      }
    }

    // A live-looking credential in model output is always wrong: the model has
    // no legitimate reason to emit one.
    for (const [label, pattern] of VENDOR_PATTERNS) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match: RegExpExecArray | null;
      while ((match = regex.exec(payload)) !== null) {
        const value = match[1] ?? match[0];
        const start = match.index + match[0].indexOf(value);
        spans.push({ start, end: start + value.length, label: `credential:${label}` });
        if (match[0].length === 0) regex.lastIndex += 1;
      }
    }

    if (!spans.length) return this.clean("no known secrets in response");
    const merged = dedupe(spans);
    const labels = [...new Set(merged.map((s) => s.label))].sort();
    return this.hit({
      score: 1,
      summary: `response contains confidential material: ${labels.join(", ")}`,
      severity: "critical",
      action: this.actionOnHit,
      spans: merged,
      evidence: { labels },
    });
  }
}

/**
 * Default categories: intentionally short and generic. This is a starting
 * point an organisation replaces with its own list, not a safety taxonomy.
 */
export const DEFAULT_TERMS: Record<string, { severity: Severity; terms: string[] }> = {
  weapons: { severity: "high", terms: ["pipe bomb", "improvised explosive", "detonator wiring", "nerve agent synthesis"] },
  malware: { severity: "high", terms: ["ransomware payload", "keylogger source", "credential stealer", "reverse shell payload"] },
  self_harm: { severity: "critical", terms: ["lethal dose of", "how to end my life"] },
  fraud: { severity: "medium", terms: ["stolen credit card", "money laundering steps", "how to launder"] },
};

const escapeRegex = (value: string): string => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** Deterministic organisational content policy. */
class BannedTopicsDetector extends Detector {
  readonly name = "banned_topics";
  readonly stages: Stage[] = ["input", "output", "stream"];
  override readonly category = "content_policy";

  private readonly compiled: [string, Severity, RegExp][] = [];
  private readonly actionOnHit: Action;

  constructor(config: DetectorConfig) {
    super(config);
    this.actionOnHit = (config.options.action as Action) ?? "block";
    const categories: Record<string, { severity?: Severity; terms: string[] }> =
      config.options.categories ?? DEFAULT_TERMS;
    for (const [name, spec] of Object.entries(categories)) {
      if (!spec.terms?.length) continue;
      const source = spec.terms.map((t) => `\\b${escapeRegex(t)}\\b`).join("|");
      this.compiled.push([name, spec.severity ?? "medium", new RegExp(source, "gi")]);
    }
    for (const [name, spec] of Object.entries((config.options.rules ?? {}) as Record<string, { severity?: Severity; pattern: string }>)) {
      this.compiled.push([name, spec.severity ?? "medium", new RegExp(spec.pattern, "gi")]);
    }
  }

  detect(data: DetectorInput): Finding {
    const spans: Span[] = [];
    const severities: Severity[] = [];
    const categories: string[] = [];

    for (const [name, severity, pattern] of this.compiled) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match: RegExpExecArray | null;
      while ((match = regex.exec(data.payload)) !== null) {
        spans.push({ start: match.index, end: match.index + match[0].length, label: `banned:${name}` });
        severities.push(severity);
        categories.push(name);
        if (match[0].length === 0) regex.lastIndex += 1;
      }
    }

    if (!spans.length) return this.clean("no banned content");
    const worst = severities.reduce<Severity>((acc, s) => (SEVERITY_RANK[s] > SEVERITY_RANK[acc] ? s : acc), "info");
    const unique = [...new Set(categories)].sort();
    return this.hit({
      score: 1,
      summary: `banned content in category/categories: ${unique.join(", ")}`,
      severity: worst,
      action: this.actionOnHit,
      spans: dedupe(spans),
      evidence: { categories: unique, matches: spans.length },
    });
  }
}

const STOPWORDS = new Set(
  ("a an the and or but if then of to in on at by for with from as is are was were be been being this that these those " +
    "it its you your we our they their he she his her i me my do does did not no can could would should will shall may " +
    "might must have has had there here what which who when where why how all any some each other more most than so such " +
    "only own same too very").split(" "),
);

const contentWords = (text: string): Set<string> =>
  new Set((text.toLowerCase().match(/[a-z0-9]+/g) ?? []).filter((w) => w.length > 2 && !STOPWORDS.has(w)));

/**
 * Screens a RAG answer for claims the retrieved context does not support.
 *
 * Sentence-level lexical overlap: a *screen*, not a hallucination detector. It
 * catches an answer that wandered away from its sources entirely and will miss
 * a fluent fabrication that reuses the source's vocabulary. It defaults to FLAG
 * for exactly that reason — blocking on a lexical heuristic is indefensible.
 */
class GroundednessDetector extends Detector {
  readonly name = "groundedness";
  readonly stages: Stage[] = ["output"];
  override readonly category = "hallucination";

  private readonly minOverlap: number;
  private readonly minSentenceWords: number;
  private readonly maxUnsupportedRatio: number;
  private readonly actionOnHit: Action;

  constructor(config: DetectorConfig) {
    super(config);
    this.minOverlap = config.options.minOverlap ?? 0.3;
    this.minSentenceWords = config.options.minSentenceWords ?? 6;
    this.maxUnsupportedRatio = config.options.maxUnsupportedRatio ?? 0.5;
    this.actionOnHit = (config.options.action as Action) ?? "flag";
  }

  detect(data: DetectorInput): Finding {
    const grounding = data.grounding.length ? data.grounding : data.documents.map((d) => d.content);
    if (!grounding.length) return this.clean("no grounding context supplied; groundedness not evaluated");

    const vocab = contentWords(grounding.join(" "));
    if (!vocab.size) return this.clean("grounding context has no content words");

    const sentences = data.payload.split(/(?<=[.!?])\s+/).filter((s) => s.trim());
    const scored: [string, number][] = [];
    for (const sentence of sentences) {
      const words = contentWords(sentence);
      if (words.size < this.minSentenceWords) continue;
      const overlap = [...words].filter((w) => vocab.has(w)).length / words.size;
      scored.push([sentence.trim(), overlap]);
    }
    if (!scored.length) return this.clean("no substantive sentences to check");

    const unsupported = scored.filter(([, overlap]) => overlap < this.minOverlap);
    const ratio = unsupported.length / scored.length;
    const evidence = {
      sentencesChecked: scored.length,
      unsupportedSentences: unsupported.length,
      unsupportedRatio: Number(ratio.toFixed(3)),
      examples: unsupported.slice(0, 3).map(([s]) => s.slice(0, 160)),
      meanOverlap: Number((scored.reduce((a, [, o]) => a + o, 0) / scored.length).toFixed(3)),
    };

    if (ratio > this.maxUnsupportedRatio) {
      return this.hit({
        score: Math.min(1, ratio),
        summary: `${unsupported.length} of ${scored.length} sentences are not supported by the retrieved context`,
        severity: "medium",
        action: this.actionOnHit,
        evidence,
      });
    }
    return this.clean("response is grounded in the retrieved context", evidence);
  }
}

register("secret_leakage", (config) => new SecretLeakageDetector(config));
register("banned_topics", (config) => new BannedTopicsDetector(config));
register("groundedness", (config) => new GroundednessDetector(config));
export { BannedTopicsDetector, GroundednessDetector, SecretLeakageDetector };
