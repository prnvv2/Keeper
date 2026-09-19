/**
 * PII detection and redaction.
 *
 * Regex plus validators, deliberately: deterministic, explainable in an audit
 * review, microseconds to run, and no model weights to ship. The cost is recall
 * on unstructured PII — swap in a Presidio- or NER-backed detector under the
 * same `pii` name when you need it.
 *
 * Default action is redact, not block: a user pasting their own phone number
 * into a support assistant should still get an answer.
 */

import type { DetectorConfig } from "../config.js";
import type { Action, Finding, Severity, Span, Stage } from "../types.js";
import { Detector, type DetectorInput, register } from "./base.js";

export function luhnValid(digits: string): boolean {
  const nums = [...digits].filter((c) => c >= "0" && c <= "9").map(Number);
  if (nums.length < 13) return false;
  const parity = nums.length % 2;
  let checksum = 0;
  nums.forEach((n, i) => {
    let value = n;
    if (i % 2 === parity) {
      value *= 2;
      if (value > 9) value -= 9;
    }
    checksum += value;
  });
  return checksum % 10 === 0;
}

function validSSN(value: string): boolean {
  const digits = value.replace(/\D/g, "");
  if (digits.length !== 9) return false;
  const [area, group, serial] = [digits.slice(0, 3), digits.slice(3, 5), digits.slice(5)];
  return area !== "000" && area !== "666" && !area.startsWith("9") && group !== "00" && serial !== "0000";
}

function validIBAN(value: string): boolean {
  const cleaned = value.replace(/\s/g, "").toUpperCase();
  if (cleaned.length < 15 || cleaned.length > 34) return false;
  const rearranged = cleaned.slice(4) + cleaned.slice(0, 4);
  const numeric = [...rearranged]
    .map((c) => (/[A-Z]/.test(c) ? String(c.charCodeAt(0) - 55) : c))
    .join("");
  // The IBAN modulus is larger than Number.MAX_SAFE_INTEGER, so reduce in chunks.
  let remainder = 0;
  for (const digit of numeric) remainder = (remainder * 10 + Number(digit)) % 97;
  return remainder === 1;
}

type Entity = { pattern: RegExp; severity: Severity; validate?: (value: string) => boolean };

export const PII_PATTERNS: Record<string, Entity> = {
  email: { pattern: /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}\b/g, severity: "medium" },
  credit_card: { pattern: /\b(?:\d[ -]?){13,19}\b/g, severity: "high", validate: luhnValid },
  us_ssn: { pattern: /\b\d{3}[- ]\d{2}[- ]\d{4}\b/g, severity: "high", validate: validSSN },
  iban: { pattern: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g, severity: "high", validate: validIBAN },
  phone: {
    pattern: /(?<![\w.])(?:\+?\d{1,3}[ .-]?)?(?:\(\d{2,4}\)[ .-]?)?\d{3,4}[ .-]\d{3,4}(?:[ .-]\d{2,4})?(?![\w.])/g,
    severity: "medium",
    validate: (v) => {
      const digits = v.replace(/\D/g, "").length;
      return digits >= 7 && digits <= 15;
    },
  },
  ip_address: {
    pattern: /\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b/g,
    severity: "low",
  },
  date_of_birth: { pattern: /\b(?:dob|date of birth)\b\s*[:=]?\s*\d{1,4}[-/.]\d{1,2}[-/.]\d{1,4}/gi, severity: "high" },
  passport: { pattern: /\bpassport(?:\s+(?:no|number|#))?\s*[:=]?\s*([A-Z0-9]{6,9})\b/gi, severity: "high" },
  medical_record: { pattern: /\b(?:mrn|medical record(?:\s+number)?)\s*[:=#]?\s*([A-Z0-9-]{5,20})\b/gi, severity: "high" },
};

const SEVERITY_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

class PIIDetector extends Detector {
  readonly name = "pii";
  readonly stages: Stage[] = ["input", "output", "tool_call", "tool_result", "memory_write"];
  override readonly category = "sensitive_data";
  override readonly mutates = true;

  private readonly entities: string[];
  private readonly actionOnHit: Action;
  private readonly blockEntities: Set<string>;

  constructor(config: DetectorConfig) {
    super(config);
    this.entities = config.options.entities ?? Object.keys(PII_PATTERNS);
    this.actionOnHit = (config.options.action as Action) ?? "redact";
    this.blockEntities = new Set(config.options.blockEntities ?? []);
  }

  detect(data: DetectorInput): Finding {
    const spans: Span[] = [];
    const taken: [number, number][] = [];

    // High-signal, longest entities first so a card number is not eaten by the
    // phone pattern.
    const order = [...this.entities].sort((a, b) =>
      (["credit_card", "iban", "us_ssn"].includes(a) ? 0 : 1) - (["credit_card", "iban", "us_ssn"].includes(b) ? 0 : 1),
    );

    for (const label of order) {
      const entity = PII_PATTERNS[label];
      if (!entity) continue;
      const regex = new RegExp(entity.pattern.source, entity.pattern.flags);
      let match: RegExpExecArray | null;
      while ((match = regex.exec(data.payload)) !== null) {
        const value = match[1] ?? match[0];
        const start = match.index + match[0].indexOf(value);
        const end = start + value.length;
        if (entity.validate && !entity.validate(value)) continue;
        if (taken.some(([s, e]) => start < e && s < end)) continue;
        taken.push([start, end]);
        spans.push({ start, end, label });
        if (match[0].length === 0) regex.lastIndex += 1;
      }
    }

    if (!spans.length) return this.clean("no PII detected");

    const labels = [...new Set(spans.map((s) => s.label))].sort();
    const worst = labels.reduce<Severity>(
      (acc, label) => (SEVERITY_RANK[PII_PATTERNS[label].severity] > SEVERITY_RANK[acc] ? PII_PATTERNS[label].severity : acc),
      "info",
    );
    const action = labels.some((l) => this.blockEntities.has(l)) ? "block" : this.actionOnHit;

    return this.hit({
      score: 1,
      summary: `${spans.length} PII item(s) detected: ${labels.join(", ")}`,
      severity: worst,
      action,
      spans,
      evidence: {
        labels,
        counts: Object.fromEntries(labels.map((l) => [l, spans.filter((s) => s.label === l).length])),
      },
    });
  }
}

register("pii", (config) => new PIIDetector(config));
export { PIIDetector };
