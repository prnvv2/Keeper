/**
 * Credential and secret detection.
 *
 * Vendor patterns (high precision, justify a block on their own) plus
 * structural entropy on assignment-shaped text (catches vendors we have never
 * heard of, scored lower). Fails closed: if this cannot run, we do not know
 * whether a live credential is about to leave the perimeter.
 */

import type { DetectorConfig } from "../config";
import type { Finding, Severity, Span, Stage } from "../types";
import { Detector, type DetectorInput, register } from "./base";

export const VENDOR_PATTERNS: [string, RegExp, Severity][] = [
  ["aws_access_key_id", /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, "critical"],
  ["aws_secret_access_key", /aws_secret_access_key\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})/gi, "critical"],
  ["github_token", /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g, "critical"],
  ["gitlab_token", /\bglpat-[A-Za-z0-9_-]{20,}\b/g, "critical"],
  ["openai_key", /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b/g, "critical"],
  ["anthropic_key", /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g, "critical"],
  ["google_api_key", /\bAIza[0-9A-Za-z_-]{35}\b/g, "critical"],
  ["slack_token", /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g, "critical"],
  ["stripe_key", /\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}\b/g, "critical"],
  ["twilio_sid", /\bAC[0-9a-fA-F]{32}\b/g, "high"],
  ["sendgrid_key", /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g, "critical"],
  ["npm_token", /\bnpm_[A-Za-z0-9]{36}\b/g, "critical"],
  ["private_key_block", /-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----/g, "critical"],
  ["jwt", /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, "high"],
  ["basic_auth_url", /\b[a-z][a-z0-9+.-]*:\/\/[^\s/:@]+:[^\s/@]{3,}@[^\s/]+/g, "high"],
  ["bearer_header", /\bauthorization\s*:\s*bearer\s+[A-Za-z0-9._-]{16,}/gi, "high"],
];

const ASSIGNMENT =
  /\b([a-z0-9_.-]*(?:secret|token|password|passwd|pwd|api[_-]?key|access[_-]?key|client[_-]?secret|credential)s?)\b\s*[=:]\s*['"]?([^\s'"]{12,})['"]?/gi;

const PLACEHOLDERS = new Set([
  "xxx", "changeme", "your_api_key", "yourapikey", "todo", "redacted",
  "placeholder", "example", "none", "null", "abc123", "secret", "password",
]);

/** Bits of entropy per character. Random base64 lands around 5.5–6.0. */
export function shannonEntropy(value: string): number {
  if (!value) return 0;
  const counts = new Map<string, number>();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  const n = value.length;
  let total = 0;
  for (const count of counts.values()) {
    const p = count / n;
    total -= p * Math.log2(p);
  }
  return total;
}

export function looksLikePlaceholder(value: string): boolean {
  const low = value.trim().replace(/^[<{[]+|[>}\]]+$/g, "").toLowerCase();
  if (PLACEHOLDERS.has(low)) return true;
  return /^(?:[*x•]+|(?:your|my|the|replace|insert)[\w-]*)$/.test(low);
}

const SEVERITY_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

class SecretDetector extends Detector {
  readonly name = "secrets";
  readonly stages: Stage[] = ["input", "output", "tool_call", "tool_result", "memory_write"];
  override readonly category = "credential_exposure";
  override readonly mutates = true;

  private readonly entropyThreshold: number;
  private readonly minEntropyLength: number;
  private readonly entropyEnabled: boolean;

  constructor(config: DetectorConfig) {
    super(config);
    this.entropyThreshold = config.options.entropyThreshold ?? 3.6;
    this.minEntropyLength = config.options.minEntropyLength ?? 16;
    this.entropyEnabled = config.options.entropyEnabled ?? true;
  }

  detect(data: DetectorInput): Finding {
    const spans: Span[] = [];
    let worst: Severity = "info";

    for (const [label, pattern, severity] of VENDOR_PATTERNS) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match: RegExpExecArray | null;
      while ((match = regex.exec(data.payload)) !== null) {
        // Prefer the capture group so we do not redact the surrounding
        // "aws_secret_access_key =" text along with the value.
        const value = match[1] ?? match[0];
        const start = match.index + match[0].indexOf(value);
        spans.push({ start, end: start + value.length, label });
        if (SEVERITY_RANK[severity] > SEVERITY_RANK[worst]) worst = severity;
        if (match[0].length === 0) regex.lastIndex += 1;
      }
    }

    const entropyHits: string[] = [];
    if (this.entropyEnabled) {
      const regex = new RegExp(ASSIGNMENT.source, ASSIGNMENT.flags);
      let match: RegExpExecArray | null;
      while ((match = regex.exec(data.payload)) !== null) {
        const value = match[2];
        if (looksLikePlaceholder(value) || value.length < this.minEntropyLength) continue;
        if (shannonEntropy(value) < this.entropyThreshold) continue;
        const start = match.index + match[0].lastIndexOf(value);
        if (spans.some((s) => s.start <= start && start < s.end)) continue;
        spans.push({ start, end: start + value.length, label: `generic_secret:${match[1].toLowerCase()}` });
        entropyHits.push(match[1]);
        if (SEVERITY_RANK.high > SEVERITY_RANK[worst]) worst = "high";
      }
    }

    if (!spans.length) return this.clean("no credentials detected");

    const labels = [...new Set(spans.map((s) => s.label))].sort();
    const vendorMatches = labels.filter((l) => !l.startsWith("generic_secret")).length;
    return this.hit({
      score: vendorMatches ? 1 : 0.7,
      summary: `credential material detected: ${labels.join(", ")}`,
      severity: worst,
      action: (this.config.options.action as never) ?? "block",
      spans,
      evidence: { labels, vendorMatches, entropyMatches: entropyHits },
    });
  }
}

register("secrets", (config) => new SecretDetector(config));
export { SecretDetector };
