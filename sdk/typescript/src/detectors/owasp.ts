/**
 * Detectors that close OWASP coverage gaps. Ports of the Python modules
 * `leakage.py`, `output_handling.py`, `agentic.py` and `consumption.py`;
 * see those for the full reasoning behind each design choice.
 *
 * - `system_prompt_leakage` — LLM07: canary tokens and verbatim system prompt reuse in output.
 * - `unsafe_output`         — LLM05: markdown/HTML exfiltration, active HTML, shell/SQL payloads.
 * - `code_execution`        — ASI05 / MCP05: execution payloads in tool arguments.
 * - `tool_poisoning`        — MCP03 / ASI04: poisoned or silently redefined tool definitions.
 * - `resource_abuse`        — LLM10: oversized, flooded or runaway-generation requests.
 */

import { createHash, randomBytes } from "node:crypto";

import type { DetectorConfig } from "../config.js";
import { argumentText, type Finding, type Span, type Stage } from "../types.js";
import { Detector, type DetectorInput, register } from "./base.js";
import { INVISIBLE, SIGNALS, normalise } from "./injection.js";

function saturate(weights: number[]): number {
  return 1 - weights.reduce((product, w) => product * (1 - Math.max(0, Math.min(1, w))), 1);
}

function span(match: RegExpExecArray, label: string): Span {
  return { start: match.index, end: match.index + match[0].length, label, snippet: match[0].slice(0, 120) };
}

// ---------------------------------------------------------------------------
// LLM07 — system prompt leakage
// ---------------------------------------------------------------------------

function shingles(text: string, n: number): Set<string> {
  const words = text.toLowerCase().match(/[a-z0-9]+/g) ?? [];
  if (words.length < n) return words.length >= Math.max(3, Math.floor(n / 2)) ? new Set([words.join(" ")]) : new Set();
  const out = new Set<string>();
  for (let i = 0; i + n <= words.length; i++) out.add(words.slice(i, i + n).join(" "));
  return out;
}

/** A fresh canary token to embed in a system prompt. */
export const newCanary = (prefix = "KPR"): string => `${prefix}-${randomBytes(8).toString("hex")}`;

export class SystemPromptLeakageDetector extends Detector {
  readonly name = "system_prompt_leakage";
  readonly stages: Stage[] = ["output", "stream"];
  override readonly category = "system_prompt_leakage";
  override readonly mutates = true;
  readonly canaries: Set<string>;
  private readonly threshold: number;
  private readonly ngram: number;
  private readonly minMatches: number;
  private readonly extraPrompts: string[];

  constructor(config: DetectorConfig) {
    super(config);
    this.threshold = config.threshold || 0.6;
    this.ngram = config.options.ngram ?? 6;
    this.minMatches = config.options.minMatches ?? 3;
    this.canaries = new Set(config.options.canaries ?? []);
    this.extraPrompts = config.options.systemPrompts ?? [];
  }

  addCanary(token: string): void {
    this.canaries.add(token);
  }

  detect(data: DetectorInput): Finding {
    const text = data.payload;
    const spans: Span[] = [];
    for (const token of this.canaries) {
      const idx = text.indexOf(token);
      if (idx >= 0) spans.push({ start: idx, end: idx + token.length, label: "canary_token", snippet: token });
    }
    if (spans.length) {
      return this.hit({ score: 1, summary: "system prompt canary token appeared in model output", severity: "critical",
        action: "block", spans, evidence: { method: "canary" } });
    }
    const system = new Set<string>();
    const seen = new Set<unknown>();
    for (const msg of [...data.context.messages, ...data.history]) {
      if ((msg.role === "system" || msg.role === "developer") && !seen.has(msg)) {
        seen.add(msg);
        for (const s of shingles(msg.content, this.ngram)) system.add(s);
      }
    }
    for (const prompt of this.extraPrompts) for (const s of shingles(prompt, this.ngram)) system.add(s);
    if (!system.size) return this.clean("no system prompt in scope", { method: "none" });

    const out = shingles(text, this.ngram);
    let matched = 0;
    for (const s of out) if (system.has(s)) matched++;
    const coverage = matched / system.size;
    const evidence = { method: "shingle_overlap", matchedNgrams: matched, systemNgrams: system.size, coverage: Number(coverage.toFixed(4)) };
    if (matched < this.minMatches && coverage < 0.5) return this.clean("no meaningful overlap with the system prompt", evidence);
    const score = Math.min(1, 0.4 + coverage * 1.5);
    if (score >= this.threshold) {
      return this.hit({ score, summary: `response reproduces ${Math.round(coverage * 100)}% of the system prompt verbatim`,
        severity: "high", action: "block", evidence });
    }
    return this.hit({ score, summary: `response partially overlaps the system prompt (${matched} shared ${this.ngram}-grams)`,
      severity: "low", action: "flag", evidence });
  }
}

// ---------------------------------------------------------------------------
// LLM05 — improper output handling
// ---------------------------------------------------------------------------

const MD_URL = /!?\[[^\]\n]{0,200}\]\(\s*<?(https?:\/\/[^\s)>]{1,2048})>?(?:\s+"[^"\n]{0,200}")?\s*\)/gi;
const HTML_IMG = /<img\b[^<>]{0,512}\bsrc\s*=\s*["']?(https?:\/\/[^\s"'>]{1,2048})/gi;

const ACTIVE_HTML: [string, RegExp, number][] = [
  ["script_tag", /<\s*script\b/i, 0.85],
  ["iframe_tag", /<\s*(?:iframe|object|embed)\b/i, 0.7],
  ["event_handler", /<[^<>]{0,512}\bon(?:error|load|click|mouseover|focus)\s*=/i, 0.8],
  ["javascript_uri", /(?:href|src)\s*=\s*["']?\s*javascript:/i, 0.8],
];
const SHELL: [string, RegExp, number][] = [
  ["rm_root", /\brm\s+-[a-z]{0,8}(?:r[a-z]{0,8}f|f[a-z]{0,8}r)[a-z]{0,8}\s+(?:\/|~|\*|\$HOME)(?:\s|$)/i, 0.6],
  ["pipe_to_shell", /\b(?:curl|wget|iwr|Invoke-WebRequest)\b[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|)sh\b/i, 0.6],
  ["reverse_shell", /(?:\/dev\/tcp\/|\bnc\b[^\n]{0,40}\s-e\s|\bbash\s+-i\s+>&)/i, 0.75],
  ["fork_bomb", /:\(\)\s*\{\s*:\|:&\s*\};:/, 0.6],
  ["disk_wipe", /\b(?:mkfs(?:\.\w+)?\s+\/dev\/|dd\s+if=\/dev\/(?:zero|random)\s+of=\/dev\/)/i, 0.6],
];
const SQL: [string, RegExp, number][] = [
  ["sql_drop", /\b(?:drop\s+(?:table|database|schema)|truncate\s+table)\b/i, 0.45],
  ["sql_tautology", /'\s*(?:or|OR)\s+'?\d+'?\s*=\s*'?\d+|'\s*;\s*--/i, 0.5],
  ["sql_union", /\bunion\s+(?:all\s+)?select\b/i, 0.35],
];

export class UnsafeOutputDetector extends Detector {
  readonly name = "unsafe_output";
  readonly stages: Stage[] = ["output", "stream"];
  override readonly category = "improper_output";
  override readonly mutates = true;
  private readonly threshold: number;
  private readonly allowed: string[];
  private readonly executesOutput: boolean;
  private readonly checkShell: boolean;
  private readonly checkSql: boolean;

  constructor(config: DetectorConfig) {
    super(config);
    this.threshold = config.threshold || 0.6;
    this.allowed = (config.options.allowedDomains ?? []).map((d: string) => d.toLowerCase().replace(/^\./, ""));
    this.executesOutput = Boolean(config.options.executesOutput);
    this.checkShell = config.options.shell ?? true;
    this.checkSql = config.options.sql ?? true;
  }

  private isAllowed(host: string): boolean {
    const h = host.toLowerCase();
    return this.allowed.some((d) => h === d || h.endsWith(`.${d}`));
  }

  detect(data: DetectorInput): Finding {
    const text = data.payload;
    const spans: Span[] = [];
    const signals: Record<string, unknown>[] = [];
    let score = 0;

    for (const regex of [MD_URL, HTML_IMG]) {
      regex.lastIndex = 0;
      for (let m = regex.exec(text); m; m = regex.exec(text)) {
        let url: URL;
        try {
          url = new URL(m[1]);
        } catch {
          continue;
        }
        if (!url.hostname || this.isAllowed(url.hostname)) continue;
        const isImage = m[0].startsWith("!") || m[0].toLowerCase().startsWith("<img");
        const longSegment = url.pathname.split("/").some((seg) => seg.length > 64);
        if (url.search || longSegment) {
          const weight = isImage ? 0.9 : 0.55;
          spans.push({ ...span(m, "markdown_exfil"), snippet: m[1].slice(0, 120) });
          signals.push({ id: "markdown_exfil", weight, host: url.hostname });
          score = Math.max(score, weight);
        }
      }
    }
    for (const [id, regex, weight] of ACTIVE_HTML) {
      const m = regex.exec(text);
      if (m) {
        spans.push(span(m, id));
        signals.push({ id, weight });
        score = Math.max(score, weight);
      }
    }
    // Shell/SQL are inert unless the application executes output: capped below
    // the matrix's second likelihood step, so they are recorded, not escalated.
    const groups = [...(this.checkShell ? SHELL : []), ...(this.checkSql ? SQL : [])];
    for (const [id, regex, weight] of groups) {
      const m = regex.exec(text);
      if (m) {
        const w = this.executesOutput ? Math.min(1, weight + 0.25) : Math.min(weight, 0.34);
        spans.push(span(m, id));
        signals.push({ id, weight: w });
        score = Math.max(score, w);
      }
    }
    if (!signals.length) return this.clean("no unsafe output constructs");
    const ids = [...new Set(signals.map((x) => String(x.id)))].sort().join(", ");
    const evidence: Record<string, unknown> = { signals, executesOutput: this.executesOutput };
    if (this.executesOutput || signals.some((x) => x.id === "reverse_shell" || x.id === "pipe_to_shell")) evidence.threats = ["ASI05"];
    if (score >= this.threshold) {
      return this.hit({ score, summary: `response contains content unsafe for downstream handling (${ids})`,
        severity: score >= 0.8 ? "high" : "medium", action: "block", spans, evidence });
    }
    return this.hit({ score, summary: `response contains potentially unsafe constructs (${ids})`, severity: "low",
      action: "flag", spans, evidence });
  }
}

// ---------------------------------------------------------------------------
// ASI05 / MCP05 — code execution in tool arguments
// ---------------------------------------------------------------------------

const EXEC_TOOL = /(?:^|[._-])(?:shell|bash|exec|execute|run_command|terminal|subprocess|python|code_interpreter|eval|repl)(?:$|[._-])/i;

/** [id, pattern, weight, countsEvenOnExecTools] */
export const EXEC_SIGNALS: [string, RegExp, number, boolean][] = [
  ["rm_rf", /\brm\s+-[a-z]{0,8}(?:r[a-z]{0,8}f|f[a-z]{0,8}r)\w{0,8}\s+(?:\/|~|\*|\$HOME|\.\.)/i, 0.8, true],
  ["pipe_to_shell", /\b(?:curl|wget|iwr|Invoke-WebRequest)\b[^|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|)sh\b/i, 0.85, true],
  ["reverse_shell", /(?:\/dev\/tcp\/|\bnc\b.{0,40}\s-e\s|\bbash\s+-i\s+>&|\bsocat\b.{0,60}exec:)/i, 0.9, true],
  ["encoded_exec", /(?:base64\s+(?:-d|--decode)[^|]{0,80}\|\s*(?:ba|z|)sh|powershell(?:\.exe)?\s+.{0,20}-e(?:nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{16,})/i, 0.85, true],
  ["disk_wipe", /\b(?:mkfs(?:\.\w+)?\s+\/dev\/|dd\s+if=\/dev\/(?:zero|random|urandom)\s+of=\/dev\/|format\s+[a-z]:)/i, 0.85, true],
  ["fork_bomb", /:\(\)\s*\{\s*:\|:&\s*\};:/, 0.85, true],
  ["priv_esc", /\b(?:chmod\s+(?:-R\s+)?(?:777|\+s)|chown\s+root|sudo\s+su\b|visudo|\/etc\/sudoers)/i, 0.6, true],
  ["credential_read", /(?:~|\$HOME|\/root|\/home\/\w+)\/\.(?:ssh|aws|kube|docker|gnupg)\b|\/etc\/(?:shadow|passwd)\b|\bid_(?:rsa|ed25519)\b/i, 0.7, true],
  ["shell_metachar", /(?:;|&&|\|\||\|)\s*(?:rm|curl|wget|nc|bash|sh|python\d?|perl|ruby|php|powershell|cmd|cat|chmod|whoami|id)\b/i, 0.7, false],
  ["command_substitution", /\$\([^)]{1,200}\)|`[^`\n]{1,200}`/, 0.55, false],
  ["interpreter_call", /\b(?:os\.system|subprocess\.(?:run|call|Popen|check_output)|eval\s*\(|exec\s*\(|__import__\s*\(|Runtime\.getRuntime\(\)\.exec|child_process)/i, 0.7, false],
  ["path_traversal", /(?:\.\.\/){2,}|\.\.\\\.\.\\|%2e%2e%2f/i, 0.55, false],
  ["sql_injection", /'\s*(?:or|and)\s+'?\d+'?\s*=\s*'?\d+|'\s*;\s*(?:drop|delete|update|insert)\b|\bunion\s+(?:all\s+)?select\b/i, 0.65, false],
  ["template_injection", /\{\{[^}]{0,80}(?:__class__|__globals__|config|self\.|request\.)[^}]{0,80}\}\}|\$\{jndi:/i, 0.75, false],
];

export class CodeExecutionDetector extends Detector {
  readonly name = "code_execution";
  readonly stages: Stage[] = ["tool_call"];
  override readonly category = "code_execution";
  private readonly threshold: number;
  private readonly execTools: RegExp;

  constructor(config: DetectorConfig) {
    super(config);
    this.threshold = config.threshold || 0.6;
    this.execTools = config.options.execTools ? new RegExp(config.options.execTools, "i") : EXEC_TOOL;
  }

  detect(data: DetectorInput): Finding {
    const call = data.toolCall;
    const text = call ? argumentText(call) : data.payload;
    const tool = call?.name ?? "";
    const execSink = Boolean(tool && this.execTools.test(tool));
    const matched: Record<string, unknown>[] = [];
    const spans: Span[] = [];
    const weights: number[] = [];
    for (const [id, pattern, weight, always] of EXEC_SIGNALS) {
      if (execSink && !always) continue;
      const m = pattern.exec(text);
      if (m) {
        matched.push({ id, weight });
        spans.push(span(m, id));
        weights.push(weight);
      }
    }
    const evidence = { tool, executionSink: execSink, signals: matched };
    if (!weights.length) return this.clean("no execution payload in tool arguments", evidence);
    const score = saturate(weights);
    const ids = matched.map((x) => String(x.id)).sort().join(", ");
    if (score >= this.threshold) {
      return this.hit({ score, summary: `execution payload in arguments to ${tool || "tool"} (${ids})`,
        severity: score >= 0.85 ? "critical" : "high", action: "block", spans, evidence });
    }
    return this.hit({ score, summary: `suspicious constructs in arguments to ${tool || "tool"} (${ids})`,
      severity: "low", action: "flag", spans, evidence });
  }
}

// ---------------------------------------------------------------------------
// MCP03 / ASI04 — tool poisoning and rug pulls
// ---------------------------------------------------------------------------

const POISON_SIGNALS: [string, RegExp, number][] = [
  ["hidden_directive_tag", /<\s*\/?\s*(?:important|system|instructions?|secret|hidden|admin|note\s+to\s+(?:ai|assistant|model))\b[^>]*>/i, 0.65],
  ["pre_use_directive", /\b(?:before|prior\s+to|when(?:ever)?)\s+(?:using|calling|invoking|you\s+(?:use|call))\b[^.\n]{0,60}\b(?:you\s+must|must|always|first|also|make\s+sure)\b/i, 0.55],
  ["sensitive_path", /(?:~|\$HOME)\/\.(?:ssh|aws|cursor|config|kube)\b|\bid_(?:rsa|ed25519)\b|\bmcp\.json\b|\.env\b|\/etc\/(?:passwd|shadow)\b|\bcredentials?\.(?:json|ya?ml)\b/i, 0.7],
  ["conceal_from_user", /\b(?:do\s*n[o']?t|never|without)\b[^.\n]{0,25}\b(?:tell|mention|inform|reveal|show|notify|alert)(?:ing)?\b[^.\n]{0,20}\b(?:the\s+)?user\b/i, 0.75],
  ["side_channel_param", /\b(?:pass|include|put|add|send)\b[^.\n]{0,50}\b(?:as|in(?:to)?)\s+(?:the\s+)?[`'"]?\w+[`'"]?\s+(?:parameter|field|argument)\b/i, 0.45],
  ["tool_shadowing", /\b(?:instead\s+of|rather\s+than|override|replace|ignore)\b[^.\n]{0,30}\b(?:the\s+)?(?:other|\w+)\s+tool\b/i, 0.5],
  ["recipient_redirect", /\b(?:all|every)\s+(?:emails?|messages?|payments?|transfers?)\b[^.\n]{0,40}\b(?:to|must\s+go\s+to)\b[^.\n]{0,20}(?:@|https?:\/\/)/i, 0.7],
];

type ToolDefinition = Record<string, any>;

const schemaOf = (d: ToolDefinition) => d.inputSchema ?? d.parameters ?? d.input_schema ?? {};

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value as object).sort().map((k) => `${JSON.stringify(k)}:${canonical((value as any)[k])}`).join(",")}}`;
  }
  return JSON.stringify(value ?? null);
}

/** Stable SHA-256 of a tool definition (name, description, schema). */
export function toolFingerprint(definition: ToolDefinition): string {
  const body = canonical({ description: definition.description ?? "", name: definition.name ?? null, schema: schemaOf(definition) });
  return createHash("sha256").update(body).digest("hex");
}

/** Everything in a definition the model will read, as one string. */
export function toolText(definition: ToolDefinition): string {
  const parts = [String(definition.name ?? ""), String(definition.description ?? "")];
  const walk = (node: unknown): void => {
    if (Array.isArray(node)) node.forEach(walk);
    else if (node && typeof node === "object") {
      for (const [k, v] of Object.entries(node)) {
        if (["description", "title", "default", "examples", "enum"].includes(k)) parts.push(typeof v === "string" ? v : JSON.stringify(v));
        walk(v);
      }
    }
  };
  walk(schemaOf(definition));
  return parts.filter(Boolean).join("\n");
}

export class ToolPoisoningDetector extends Detector {
  readonly name = "tool_poisoning";
  readonly stages: Stage[] = ["tool_definition"];
  override readonly category = "tool_poisoning";
  readonly pins: Map<string, string>;
  private readonly threshold: number;
  private readonly pin: boolean;
  /** Learned pins are capped so invented tool names cannot grow the table forever. */
  private readonly maxPins: number;

  constructor(config: DetectorConfig) {
    super(config);
    this.threshold = config.threshold || 0.6;
    this.pin = config.options.pin ?? true;
    this.pins = new Map(Object.entries(config.options.pins ?? {}));
    this.maxPins = config.options.maxPins ?? 10_000;
  }

  detect(data: DetectorInput): Finding {
    const definition = (data.metadata.toolDefinition ?? {}) as ToolDefinition;
    const server = String(data.metadata.server ?? "default");
    const name = String(definition.name ?? data.metadata.tool ?? "unknown");
    const text = normalise(data.payload);
    const weights = new Map<string, number>();
    const matched: Record<string, unknown>[] = [];
    const spans: Span[] = [];

    for (const [id, pattern, weight] of POISON_SIGNALS) {
      const m = pattern.exec(text);
      if (m) {
        weights.set(id, weight);
        matched.push({ id, weight });
        spans.push(span(m, id));
      }
    }
    for (const signal of SIGNALS) {
      if (signal.pattern.test(text)) {
        const k = `injection:${signal.family}`;
        weights.set(k, Math.max(weights.get(k) ?? 0, signal.weight));
        matched.push({ id: signal.id, family: signal.family, weight: signal.weight });
      }
    }
    const invisible = (data.payload.match(INVISIBLE) ?? []).length;
    if (invisible) {
      weights.set("invisible_characters", 0.6);
      matched.push({ id: "invisible_characters", count: invisible });
    }

    let rugPull = false;
    const key = `${server}/${name}`;
    const fingerprint = Object.keys(definition).length ? toolFingerprint(definition) : null;
    const pin = (data.metadata.pin as boolean | undefined) ?? this.pin;
    if (fingerprint && pin) {
      const pinned = this.pins.get(key);
      if (pinned === undefined) {
        if (this.pins.size < this.maxPins) this.pins.set(key, fingerprint);
      } else if (pinned !== fingerprint) {
        rugPull = true;
        weights.set("definition_changed", 0.9);
        matched.push({ id: "definition_changed", pinned: pinned.slice(0, 12), current: fingerprint.slice(0, 12) });
      }
    }
    const evidence = { server, tool: name, fingerprint, signals: matched, rugPull };
    if (!weights.size) return this.clean("tool definition clean", evidence);
    const score = saturate([...weights.values()]);
    const summary = rugPull
      ? `tool ${key} changed after it was pinned (possible rug pull)`
      : `tool ${key} description contains embedded directives (${[...weights.keys()].sort().join(", ")})`;
    if (score >= this.threshold) {
      return this.hit({ score, summary, severity: rugPull || score >= 0.85 ? "critical" : "high", action: "block", spans, evidence });
    }
    return this.hit({ score, summary, severity: "low", action: "flag", spans, evidence });
  }
}

// ---------------------------------------------------------------------------
// LLM10 — unbounded consumption
// ---------------------------------------------------------------------------

const ENDLESS = /\b(?:repeat|say|write|output|print)\b[^.\n]{0,40}\b(?:forever|indefinitely|infinitely|endlessly|non[- ]?stop|until\s+(?:you\s+)?(?:run\s+out|crash|stop)|\d{4,}\s+times)\b/i;

export class ResourceAbuseDetector extends Detector {
  readonly name = "resource_abuse";
  readonly stages: Stage[] = ["input"];
  override readonly category = "unbounded_consumption";
  private readonly threshold: number;
  private readonly maxChars: number;
  private readonly maxMessages: number;
  private readonly maxOutputTokens: number;
  private readonly floodMinTokens: number;
  private readonly floodShare: number;

  constructor(config: DetectorConfig) {
    super(config);
    const o = config.options;
    this.threshold = config.threshold || 0.6;
    this.maxChars = o.maxChars ?? 100_000;
    this.maxMessages = o.maxMessages ?? 500;
    this.maxOutputTokens = o.maxOutputTokens ?? 0;
    this.floodMinTokens = o.floodMinTokens ?? 200;
    this.floodShare = o.floodShare ?? 0.5;
  }

  detect(data: DetectorInput): Finding {
    const text = data.payload;
    const signals: Record<string, unknown>[] = [];
    let score = 0;
    const add = (id: string, weight: number, extra: Record<string, unknown> = {}) => {
      signals.push({ id, weight, ...extra });
      score = Math.max(score, weight);
    };
    const totalChars = text.length + data.history.reduce((n, m) => n + m.content.length, 0);
    if (totalChars > this.maxChars) add("oversized_prompt", 0.9, { chars: totalChars, limit: this.maxChars });
    if (data.history.length > this.maxMessages) add("oversized_history", 0.8, { messages: data.history.length });

    const tokens = text.match(/\S+/g) ?? [];
    if (tokens.length >= this.floodMinTokens) {
      const counts = new Map<string, number>();
      let top = ["", 0] as [string, number];
      for (const tok of tokens) {
        const k = tok.toLowerCase();
        const c = (counts.get(k) ?? 0) + 1;
        counts.set(k, c);
        if (c > top[1]) top = [k, c];
      }
      const share = top[1] / tokens.length;
      if (share >= this.floodShare) add("token_flood", 0.7, { token: top[0].slice(0, 40), share: Number(share.toFixed(3)) });
    }
    if (/(.)\1{499,}/s.test(text)) add("character_flood", 0.7);
    const m = ENDLESS.exec(text);
    if (m) add("endless_generation", 0.55, { snippet: m[0].slice(0, 80) });
    const requested = data.metadata.maxTokens;
    if (this.maxOutputTokens && typeof requested === "number" && requested > this.maxOutputTokens) {
      add("output_budget_exceeded", 0.8, { requested, limit: this.maxOutputTokens });
    }
    if (!signals.length) return this.clean("request within resource bounds", { chars: totalChars, tokens: tokens.length });
    const ids = signals.map((x) => String(x.id)).sort().join(", ");
    if (score >= this.threshold) {
      return this.hit({ score, summary: `request exceeds resource bounds (${ids})`, severity: "medium", action: "block", evidence: { signals } });
    }
    return this.hit({ score, summary: `request shows resource-abuse traits (${ids})`, severity: "low", action: "flag", evidence: { signals } });
  }
}

register("system_prompt_leakage", (config) => new SystemPromptLeakageDetector(config));
register("unsafe_output", (config) => new UnsafeOutputDetector(config));
register("code_execution", (config) => new CodeExecutionDetector(config));
register("tool_poisoning", (config) => new ToolPoisoningDetector(config));
register("resource_abuse", (config) => new ResourceAbuseDetector(config));
