/**
 * The risk matrix: likelihood (1–5) x impact (1–5), per OWASP threat, per
 * decision. Port of `keeper_firewall/risk.py` — same bands, same defaults,
 * same residual-vs-inherent rule, so a decision scores identically in both
 * SDKs. The engine only escalates: its verdict joins the decision as one more
 * policy trace and is combined by escalation like everything else.
 */

import { PolicyError } from "./errors.js";
import { THREATS } from "./taxonomy.js";
import type { Action, Finding, PolicyTrace, RiskTier, Stage, ToolCall } from "./types.js";

export type RiskBand = "none" | "low" | "medium" | "high" | "critical";

const BAND_RANK: Record<RiskBand, number> = { none: 0, low: 1, medium: 2, high: 3, critical: 4 };
export const bandRank = (band: RiskBand): number => BAND_RANK[band] ?? 0;

export function bandFor(score: number): RiskBand {
  if (score <= 0) return "none";
  if (score <= 4) return "low";
  if (score <= 9) return "medium";
  if (score <= 16) return "high";
  return "critical";
}

export const DEFAULT_BAND_ACTIONS: Record<RiskBand, Action> = {
  none: "allow",
  low: "allow",
  medium: "flag",
  high: "block",
  critical: "block",
};

export const DEFAULT_TOOL_IMPACT: Record<RiskTier, number> = { low: 2, medium: 3, high: 4, critical: 5 };
export const DEFAULT_LIKELIHOOD_CUTS: [number, number, number, number] = [0.35, 0.5, 0.65, 0.85];

export interface RiskConfig {
  enforce: boolean;
  actions: Record<RiskBand, Action>;
  impactOverrides: Record<string, number>;
  toolImpact: Record<RiskTier, number>;
  likelihoodCuts: [number, number, number, number];
  applicationImpact: Record<string, number>;
}

export const defaultRiskConfig = (): RiskConfig => ({
  enforce: true,
  actions: { ...DEFAULT_BAND_ACTIONS },
  impactOverrides: {},
  toolImpact: { ...DEFAULT_TOOL_IMPACT },
  likelihoodCuts: [...DEFAULT_LIKELIHOOD_CUTS],
  applicationImpact: {},
});

const BANDS: RiskBand[] = ["none", "low", "medium", "high", "critical"];
const ACTIONS: Action[] = ["allow", "flag", "redact", "challenge", "block"];
const TIERS: RiskTier[] = ["low", "medium", "high", "critical"];

function impactValue(value: unknown, where: string): number {
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1 || n > 5) throw new PolicyError(`risk.${where} must be between 1 and 5, got ${String(value)}`);
  return n;
}

/** Parse and validate the `risk:` section of a policy document. */
export function parseRiskConfig(data: unknown): RiskConfig {
  const config = defaultRiskConfig();
  if (!data) return config;
  if (typeof data !== "object") throw new PolicyError("'risk' must be a mapping");
  const doc = data as Record<string, any>;
  const known = new Set(["enforce", "actions", "impact", "tool_impact", "likelihood_cuts", "application_impact"]);
  const unknown = Object.keys(doc).filter((k) => !known.has(k));
  if (unknown.length) throw new PolicyError(`unknown risk keys: ${unknown.sort().join(", ")}`);

  config.enforce = doc.enforce ?? true;
  for (const [band, action] of Object.entries(doc.actions ?? {})) {
    if (!BANDS.includes(band as RiskBand)) throw new PolicyError(`invalid risk section: unknown band '${band}'`);
    if (!ACTIONS.includes(action as Action)) throw new PolicyError(`invalid risk section: unknown action '${String(action)}'`);
    config.actions[band as RiskBand] = action as Action;
  }
  for (const [id, v] of Object.entries(doc.impact ?? {})) {
    if (!(id in THREATS)) throw new PolicyError(`risk.impact: unknown threat id '${id}'`);
    config.impactOverrides[id] = impactValue(v, `impact.${id}`);
  }
  for (const [tier, v] of Object.entries(doc.tool_impact ?? {})) {
    if (!TIERS.includes(tier as RiskTier)) throw new PolicyError(`invalid risk section: unknown tier '${tier}'`);
    config.toolImpact[tier as RiskTier] = impactValue(v, `tool_impact.${tier}`);
  }
  if (doc.likelihood_cuts) {
    const cuts = (doc.likelihood_cuts as unknown[]).map(Number);
    const sorted = [...cuts].sort((a, b) => a - b);
    if (cuts.length !== 4 || cuts.some((c, i) => c !== sorted[i] || !(c > 0 && c <= 1))) {
      throw new PolicyError("risk.likelihood_cuts must be four ascending values in (0, 1]");
    }
    config.likelihoodCuts = cuts as [number, number, number, number];
  }
  for (const [app, v] of Object.entries(doc.application_impact ?? {})) {
    config.applicationImpact[app] = impactValue(v, `application_impact.${app}`);
  }
  return config;
}

export function serialiseRiskConfig(config: RiskConfig): Record<string, unknown> {
  return {
    enforce: config.enforce,
    actions: { ...config.actions },
    impact: { ...config.impactOverrides },
    tool_impact: { ...config.toolImpact },
    likelihood_cuts: [...config.likelihoodCuts],
    application_impact: { ...config.applicationImpact },
  };
}

export interface ThreatRisk {
  threat: string;
  likelihood: number;
  impact: number;
  residualLikelihood: number;
  detectors: string[];
  mitigated: boolean;
}

export interface RiskAssessment {
  likelihood: number;
  impact: number;
  score: number;
  band: RiskBand;
  inherentScore: number;
  inherentBand: RiskBand;
  primary: string | null;
  threats: ThreatRisk[];
  action: Action;
}

export const noRisk = (): RiskAssessment => ({
  likelihood: 0,
  impact: 0,
  score: 0,
  band: "none",
  inherentScore: 0,
  inherentBand: "none",
  primary: null,
  threats: [],
  action: "allow",
});

export function explainRisk(risk: RiskAssessment): string {
  if (!risk.primary) return "no threats identified";
  const title = THREATS[risk.primary]?.title;
  return `risk ${risk.score}/25 (${risk.band}): likelihood ${risk.likelihood} x impact ${risk.impact} on ${risk.primary}${title ? ` ${title}` : ""}`;
}

/** Wire shape, identical to Python's `RiskAssessment.to_dict()`. */
export function serialiseRisk(risk: RiskAssessment): Record<string, unknown> {
  return {
    likelihood: risk.likelihood,
    impact: risk.impact,
    score: risk.score,
    band: risk.band,
    inherent_score: risk.inherentScore,
    inherent_band: risk.inherentBand,
    primary: risk.primary,
    action: risk.action,
    threats: risk.threats.map((c) => ({
      threat: c.threat,
      title: THREATS[c.threat]?.title ?? c.threat,
      framework: THREATS[c.threat]?.framework ?? null,
      likelihood: c.likelihood,
      impact: c.impact,
      score: c.likelihood * c.impact,
      band: bandFor(c.likelihood * c.impact),
      residual_score: c.residualLikelihood * c.impact,
      residual_band: bandFor(c.residualLikelihood * c.impact),
      mitigated: c.mitigated,
      detectors: c.detectors,
    })),
  };
}

export class RiskEngine {
  constructor(readonly config: RiskConfig = defaultRiskConfig()) {}

  likelihood(score: number): number {
    return 1 + this.config.likelihoodCuts.filter((cut) => score >= cut).length;
  }

  impact(threatId: string, _stage: Stage, toolCall?: ToolCall, application?: string): number {
    let base = this.config.impactOverrides[threatId] ?? THREATS[threatId]?.baseImpact ?? 3;
    if (application && application in this.config.applicationImpact) {
      base = Math.max(base, this.config.applicationImpact[application]);
    }
    if (toolCall?.risk) base = Math.max(base, this.config.toolImpact[toolCall.risk] ?? base);
    return Math.max(1, Math.min(5, base));
  }

  assess(findings: Finding[], stage: Stage, options: { toolCall?: ToolCall; application?: string } = {}): RiskAssessment {
    const byThreat = new Map<string, Finding[]>();
    for (const f of findings) {
      if (!f.detected) continue;
      for (const id of f.threats ?? []) {
        if (!byThreat.has(id)) byThreat.set(id, []);
        byThreat.get(id)!.push(f);
      }
    }
    const cells: ThreatRisk[] = [];
    for (const [threat, fs] of byThreat) {
      let likelihood = this.likelihood(Math.max(...fs.map((f) => f.score)));
      const detectors = [...new Set(fs.map((f) => f.detector))];
      if (detectors.length >= 2) likelihood = Math.min(5, likelihood + 1);
      const mitigated = fs.every((f) => f.action === "redact");
      cells.push({
        threat,
        likelihood,
        impact: this.impact(threat, stage, options.toolCall, options.application),
        residualLikelihood: mitigated ? 1 : likelihood,
        detectors,
        mitigated,
      });
    }
    if (!cells.length) return noRisk();

    // Stable sort: on ties the first-mapped threat stays the headline.
    const ordered = cells
      .map((c, i) => ({ c, i }))
      .sort(
        (a, b) =>
          b.c.residualLikelihood * b.c.impact - a.c.residualLikelihood * a.c.impact ||
          b.c.likelihood * b.c.impact - a.c.likelihood * a.c.impact ||
          a.i - b.i,
      )
      .map((x) => x.c);
    const worst = ordered[0];
    const inherent = ordered.reduce((m, c) => (c.likelihood * c.impact > m.likelihood * m.impact ? c : m), ordered[0]);
    const score = worst.residualLikelihood * worst.impact;
    const band = bandFor(score);
    return {
      likelihood: worst.residualLikelihood,
      impact: worst.impact,
      score,
      band,
      inherentScore: inherent.likelihood * inherent.impact,
      inherentBand: bandFor(inherent.likelihood * inherent.impact),
      primary: worst.threat,
      threats: ordered,
      action: this.config.actions[band] ?? "allow",
    };
  }

  trace(risk: RiskAssessment, policyId: string, policyVersion: string, dryRun = false): PolicyTrace | null {
    if (!this.config.enforce || risk.action === "allow") return null;
    return {
      policyId,
      policyVersion,
      ruleId: `risk-matrix/${risk.band}`,
      matched: true,
      action: dryRun ? "allow" : risk.action,
      elapsedMs: 0,
      note: (dryRun ? `[dry-run: would ${risk.action}] ` : "") + explainRisk(risk),
    };
  }
}

/** Count (likelihood, impact) pairs into a 5x5 grid, `grid[likelihood-1][impact-1]`. */
export function riskMatrix(cells: [number, number][]): number[][] {
  const grid = Array.from({ length: 5 }, () => Array(5).fill(0) as number[]);
  for (const [l, i] of cells) if (l >= 1 && l <= 5 && i >= 1 && i <= 5) grid[l - 1][i - 1] += 1;
  return grid;
}
