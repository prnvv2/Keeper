/**
 * Model backend adapters.
 *
 * Keeper does not want to become an LLM SDK. The adapter's only job is to
 * normalise "send these messages, get text back" and "stream tokens" so the
 * pipeline has one shape to work with.
 *
 * `CallableProvider` is the primary integration for existing code: if the
 * application already builds its own OpenAI/Anthropic/Bedrock call, it passes
 * a function and keeps every provider-specific parameter it was using. The
 * built-in HTTP providers exist so the ten-minute quickstart works without a
 * second SDK, and use `fetch` rather than adding a dependency.
 */

import { ConfigurationError, KeeperError } from "./errors";
import type { LLMResponse, Message, ToolCall } from "./types";
import { newId } from "./types";

export interface Provider {
  name: string;
  complete(messages: Message[], options?: Record<string, any>): Promise<LLMResponse>;
  stream?(messages: Message[], options?: Record<string, any>): AsyncIterable<string>;
}

const wireMessage = (m: Message): Record<string, unknown> =>
  m.name ? { role: m.role, content: m.content, name: m.name } : { role: m.role, content: m.content };

/** Normalise provider-specific tool-call payloads. */
export function parseToolCalls(raw: any): ToolCall[] {
  if (!Array.isArray(raw)) return [];
  const calls: ToolCall[] = [];
  for (const item of raw) {
    if (!item || typeof item !== "object") continue;
    const fn = item.function ?? item;
    if (!fn.name) continue;
    let args = fn.arguments ?? fn.input ?? {};
    if (typeof args === "string") {
      try {
        args = JSON.parse(args);
      } catch {
        args = { _raw: args };
      }
    }
    calls.push({ name: String(fn.name), arguments: args, callId: String(item.id ?? newId("call_")) });
  }
  return calls;
}

/** Wraps an application-supplied function. The recommended integration. */
export class CallableProvider implements Provider {
  constructor(
    private readonly fn: (messages: Record<string, unknown>[], options?: Record<string, any>) => Promise<string | LLMResponse> | string | LLMResponse,
    readonly name = "callable",
    private readonly model?: string,
    private readonly streamFn?: (messages: Record<string, unknown>[], options?: Record<string, any>) => AsyncIterable<string>,
  ) {}

  async complete(messages: Message[], options: Record<string, any> = {}): Promise<LLMResponse> {
    const result = await this.fn(messages.map(wireMessage), options);
    if (typeof result === "string") return { text: result, model: options.model ?? this.model ?? "callable" };
    if (result && typeof result === "object" && "text" in result) return result;
    // A provider that silently stringifies an unexpected object is how a
    // response object ends up in an audit log as "[object Object]".
    throw new KeeperError(`callable provider returned ${typeof result}; expected string or LLMResponse`);
  }

  async *stream(messages: Message[], options: Record<string, any> = {}): AsyncIterable<string> {
    if (!this.streamFn) {
      // Degrade cleanly: one chunk. Mid-stream enforcement still runs, it just
      // has nothing to break early on.
      yield (await this.complete(messages, options)).text;
      return;
    }
    yield* this.streamFn(messages.map(wireMessage), options);
  }
}

/** Deterministic fake backend for tests, demos, and the quickstart. */
export class EchoProvider implements Provider {
  readonly name = "echo";
  constructor(private readonly response?: string | ((messages: Message[]) => string)) {}

  private text(messages: Message[]): string {
    if (typeof this.response === "function") return this.response(messages);
    if (typeof this.response === "string") return this.response;
    const last = [...messages].reverse().find((m) => m.role === "user");
    return `echo: ${last?.content ?? ""}`;
  }

  async complete(messages: Message[], options: Record<string, any> = {}): Promise<LLMResponse> {
    const text = this.text(messages);
    return {
      text,
      model: options.model ?? "echo-1",
      tokensIn: messages.reduce((n, m) => n + m.content.split(/\s+/).length, 0),
      tokensOut: text.split(/\s+/).length,
      finishReason: "stop",
    };
  }

  async *stream(messages: Message[]): AsyncIterable<string> {
    const text = this.text(messages);
    for (let i = 0; i < text.length; i += 16) yield text.slice(i, i + 16);
  }
}

/**
 * Chat-completions client for any OpenAI-compatible endpoint — which covers
 * vLLM, Ollama, Together, Groq, LM Studio and Azure OpenAI with a base-URL
 * change, so it is one adapter rather than one class per vendor.
 */
export class OpenAICompatibleProvider implements Provider {
  readonly name = "openai";
  private readonly apiKey?: string;
  private readonly baseUrl: string;
  private readonly model: string;

  constructor(options: { apiKey?: string; baseUrl?: string; model?: string; defaultParams?: Record<string, any> } = {}) {
    this.apiKey = options.apiKey ?? globalThis.process?.env?.OPENAI_API_KEY;
    this.baseUrl = (options.baseUrl ?? "https://api.openai.com/v1").replace(/\/+$/, "");
    this.model = options.model ?? "gpt-4o-mini";
    this.defaultParams = options.defaultParams ?? {};
  }
  private readonly defaultParams: Record<string, any>;

  private body(messages: Message[], options: Record<string, any>, stream: boolean): Record<string, unknown> {
    const { model, ...rest } = options;
    return { model: model ?? this.model, messages: messages.map(wireMessage), stream, ...this.defaultParams, ...rest };
  }

  private headers(): Record<string, string> {
    if (!this.apiKey) throw new ConfigurationError("OpenAICompatibleProvider needs an apiKey or OPENAI_API_KEY");
    return { "Content-Type": "application/json", Authorization: `Bearer ${this.apiKey}` };
  }

  async complete(messages: Message[], options: Record<string, any> = {}): Promise<LLMResponse> {
    const response = await fetch(`${this.baseUrl}/chat/completions`, {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify(this.body(messages, options, false)),
    });
    if (!response.ok) throw new KeeperError(`model provider returned HTTP ${response.status}`);
    const data: any = await response.json();
    const choice = data.choices?.[0] ?? {};
    return {
      text: choice.message?.content ?? "",
      model: data.model ?? options.model ?? this.model,
      raw: data,
      tokensIn: data.usage?.prompt_tokens,
      tokensOut: data.usage?.completion_tokens,
      finishReason: choice.finish_reason,
      toolCalls: parseToolCalls(choice.message?.tool_calls),
    };
  }

  async *stream(messages: Message[], options: Record<string, any> = {}): AsyncIterable<string> {
    for await (const event of sse(`${this.baseUrl}/chat/completions`, this.headers(), this.body(messages, options, true))) {
      if (event === "[DONE]") return;
      try {
        const delta = JSON.parse(event).choices?.[0]?.delta?.content;
        if (delta) yield delta;
      } catch {
        continue;
      }
    }
  }
}

/** Messages-API client for Anthropic models. */
export class AnthropicProvider implements Provider {
  readonly name = "anthropic";
  private readonly apiKey?: string;
  private readonly baseUrl: string;
  private readonly model: string;
  private readonly maxTokens: number;
  private readonly version: string;

  constructor(options: { apiKey?: string; baseUrl?: string; model?: string; maxTokens?: number; version?: string } = {}) {
    this.apiKey = options.apiKey ?? globalThis.process?.env?.ANTHROPIC_API_KEY;
    this.baseUrl = (options.baseUrl ?? "https://api.anthropic.com/v1").replace(/\/+$/, "");
    this.model = options.model ?? "claude-sonnet-5";
    this.maxTokens = options.maxTokens ?? 1024;
    this.version = options.version ?? "2023-06-01";
  }

  private headers(): Record<string, string> {
    if (!this.apiKey) throw new ConfigurationError("AnthropicProvider needs an apiKey or ANTHROPIC_API_KEY");
    return { "Content-Type": "application/json", "x-api-key": this.apiKey, "anthropic-version": this.version };
  }

  /** Anthropic takes the system prompt as a top-level field, not a turn. */
  private body(messages: Message[], options: Record<string, any>, stream: boolean): Record<string, unknown> {
    const { model, maxTokens, ...rest } = options;
    const system = messages.filter((m) => m.role === "system").map((m) => m.content).join("\n\n");
    const body: Record<string, unknown> = {
      model: model ?? this.model,
      messages: messages.filter((m) => m.role !== "system").map(wireMessage),
      max_tokens: maxTokens ?? this.maxTokens,
      ...rest,
    };
    if (system) body.system = system;
    if (stream) body.stream = true;
    return body;
  }

  async complete(messages: Message[], options: Record<string, any> = {}): Promise<LLMResponse> {
    const response = await fetch(`${this.baseUrl}/messages`, {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify(this.body(messages, options, false)),
    });
    if (!response.ok) throw new KeeperError(`model provider returned HTTP ${response.status}`);
    const data: any = await response.json();
    const blocks: any[] = data.content ?? [];
    return {
      text: blocks.filter((b) => b.type === "text").map((b) => b.text).join(""),
      model: data.model ?? options.model ?? this.model,
      raw: data,
      tokensIn: data.usage?.input_tokens,
      tokensOut: data.usage?.output_tokens,
      finishReason: data.stop_reason,
      toolCalls: parseToolCalls(
        blocks.filter((b) => b.type === "tool_use").map((b) => ({ id: b.id, function: { name: b.name, arguments: b.input } })),
      ),
    };
  }

  async *stream(messages: Message[], options: Record<string, any> = {}): AsyncIterable<string> {
    for await (const event of sse(`${this.baseUrl}/messages`, this.headers(), this.body(messages, options, true))) {
      try {
        const chunk = JSON.parse(event);
        if (chunk.type === "content_block_delta" && chunk.delta?.text) yield chunk.delta.text;
      } catch {
        continue;
      }
    }
  }
}

/** Read a `text/event-stream` response, yielding raw `data:` payloads. */
async function* sse(url: string, headers: Record<string, string>, body: unknown): AsyncGenerator<string> {
  const response = await fetch(url, {
    method: "POST",
    headers: { ...headers, Accept: "text/event-stream" },
    body: JSON.stringify(body),
  });
  if (!response.ok || !response.body) throw new KeeperError(`model provider returned HTTP ${response.status}`);
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split("\n");
    buffer = lines.pop() ?? "";
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.startsWith("data:")) yield trimmed.slice(5).trim();
    }
  }
}
