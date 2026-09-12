/**
 * Access control: authorization over models and tools, and rate limiting.
 *
 * Scope note, because "RBAC" appears twice in this project: this governs which
 * end users and services may reach which models and tools. The dashboard's own
 * RBAC — who may read audit logs and publish policy — lives in the control
 * plane and is a different system.
 *
 * Authentication is deliberately thin here. The SDK runs inside an application
 * that has already authenticated its user; the recommended integration is to
 * hand Keeper the principal you already have, not to make Keeper an identity
 * provider.
 */

import { AuthorizationError, RateLimitError } from "./errors";
import { compileCondition } from "./policy";
import type { Principal } from "./types";

// ---------------------------------------------------------------------------
// Authorization
// ---------------------------------------------------------------------------

export interface Permission {
  resourceType: string; // "model" | "tool" | "agent" | custom
  pattern: string;
  effect: "allow" | "deny";
  condition?: unknown;
}

export interface Role {
  name: string;
  permissions: Permission[];
  inherits?: string[];
}

const globMatch = (value: string, pattern: string): boolean =>
  new RegExp(`^${pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".")}$`).test(value);

/** Parse `"model:gpt-4*"`, `"!tool:shell.*"`, or an object. */
export function parsePermission(spec: string | Partial<Permission>): Permission {
  if (typeof spec !== "string") {
    return {
      resourceType: spec.resourceType ?? "*",
      pattern: spec.pattern ?? "*",
      effect: spec.effect ?? "allow",
      condition: spec.condition,
    };
  }
  let text = spec.trim();
  let effect: "allow" | "deny" = "allow";
  if (text.startsWith("!")) {
    effect = "deny";
    text = text.slice(1);
  }
  const index = text.indexOf(":");
  return index >= 0
    ? { resourceType: text.slice(0, index).trim(), pattern: text.slice(index + 1).trim(), effect }
    : { resourceType: "*", pattern: text.trim(), effect };
}

export class Authorizer {
  constructor(
    readonly roles: Record<string, Role> = {},
    /** Default deny is the only defensible choice for a security control, but
     * teams roll access control out gradually, so it is configurable. */
    readonly defaultEffect: "allow" | "deny" = "deny",
    readonly superuserRoles: Set<string> = new Set(["admin"]),
  ) {}

  /** Flatten a principal's roles, following inheritance, cycles included. */
  effectivePermissions(roleNames: string[]): Permission[] {
    const seen = new Set<string>();
    const out: Permission[] = [];
    const stack = [...roleNames];
    while (stack.length) {
      const name = stack.pop()!;
      if (seen.has(name)) continue;
      seen.add(name);
      const role = this.roles[name];
      if (!role) continue;
      out.push(...role.permissions);
      stack.push(...(role.inherits ?? []));
    }
    return out;
  }

  check(principal: Principal, resourceType: string, resource: string): [boolean, string] {
    if (principal.roles.some((r) => this.superuserRoles.has(r))) return [true, "superuser role"];

    const applicable = this.effectivePermissions(principal.roles)
      .filter((p) => (p.resourceType === resourceType || p.resourceType === "*") && globMatch(resource, p.pattern))
      .filter((p) => this.conditionHolds(p, principal));

    const deny = applicable.find((p) => p.effect === "deny");
    if (deny) return [false, `denied by ${deny.resourceType}:${deny.pattern}`];
    const allow = applicable.find((p) => p.effect === "allow");
    if (allow) return [true, `allowed by ${allow.resourceType}:${allow.pattern}`];
    if (this.defaultEffect === "allow") return [true, "default allow"];
    return [false, `no permission for ${resourceType}:${resource} (roles: ${principal.roles.join(", ") || "none"})`];
  }

  authorize(principal: Principal, resourceType: string, resource: string): void {
    const [allowed, reason] = this.check(principal, resourceType, resource);
    if (!allowed) {
      throw new AuthorizationError(
        `principal '${principal.id}' may not use ${resourceType} '${resource}': ${reason}`,
        principal.id,
        `${resourceType}:${resource}`,
      );
    }
  }

  private conditionHolds(permission: Permission, principal: Principal): boolean {
    if (permission.condition == null) return true;
    return compileCondition(permission.condition)({
      principalId: principal.id,
      roles: principal.roles,
      tenant: principal.tenant,
      authenticated: principal.authenticated,
      tags: principal.attributes ?? {},
    });
  }
}

/**
 * Build an authorizer from a policy bundle's access lists, so "analysts lose
 * access to the finance model" is a policy publish rather than a deploy.
 *
 * A policy that defines no access lists has not delegated this decision to
 * Keeper, so the authorizer abstains rather than denying everything — without
 * this, an org that only wants content filtering would find every model and
 * tool call refused by an RBAC layer they never configured.
 */
export function authorizerFromPolicy(
  modelAccess: Record<string, string[]> = {},
  toolAccess: Record<string, string[]> = {},
): Authorizer {
  if (!Object.keys(modelAccess).length && !Object.keys(toolAccess).length) {
    return new Authorizer({}, "allow");
  }
  const roles: Record<string, Role> = {};
  const add = (kind: string, roleName: string, patterns: string[]): void => {
    roles[roleName] ??= { name: roleName, permissions: [] };
    for (const pattern of patterns) {
      // A leading "!" marks a deny entry; it has to stay in front of the
      // resource type for parsePermission to see it.
      const spec = pattern.startsWith("!") ? `!${kind}:${pattern.slice(1)}` : `${kind}:${pattern}`;
      roles[roleName].permissions.push(parsePermission(spec));
    }
  };
  for (const [role, patterns] of Object.entries(modelAccess)) add("model", role, patterns);
  for (const [role, patterns] of Object.entries(toolAccess)) add("tool", role, patterns);
  return new Authorizer(roles);
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

export interface Quota {
  rpm: number;
  burst: number;
}

interface Bucket {
  capacity: number;
  tokens: number;
  refillPerSecond: number;
  updated: number;
}

/**
 * Multi-scope token-bucket limiter.
 *
 * The honest limitation, stated rather than glossed: a bucket inside the
 * application process limits *that process*. Run ten replicas and a tenant
 * gets ten times the quota. Local limiting is good for immediate backpressure
 * on runaway loops and single hammering clients, and as a floor that keeps
 * working when the control plane is unreachable. For a genuine fleet-wide
 * quota, enable `distributed` and supply a lease client: consumption is
 * reported and the local bucket is resized to this instance's share, bounding
 * overshoot by one lease window. Anyone who cannot tolerate that should
 * enforce quota at the API gateway, where a synchronous check is already paid
 * for.
 */
export class RateLimiter {
  private readonly buckets = new Map<string, Bucket>();
  private readonly consumed = new Map<string, number>();
  private readonly leaseAt = new Map<string, number>();
  quotas: Record<string, Quota> = {};

  constructor(
    private defaultQuota: Quota = { rpm: 120, burst: 20 },
    readonly distributed = false,
    private readonly leaseClient?: (scope: string, consumed: number) => Promise<{ lease?: Quota }>,
    private readonly leaseIntervalS = 10,
    private readonly maxBuckets = 10_000,
  ) {}

  applyPolicy(rateLimits: Record<string, Record<string, unknown>>): void {
    this.quotas = Object.fromEntries(
      Object.entries(rateLimits).map(([scope, spec]) => [
        scope,
        { rpm: Number(spec.rpm ?? 60), burst: Number(spec.burst ?? Math.max(1, Math.floor(Number(spec.rpm ?? 60) / 6))) },
      ]),
    );
    if (this.quotas["*"]) this.defaultQuota = this.quotas["*"];
    // Resize live buckets so a tightened quota takes effect at once, rather
    // than after the old bucket drains.
    for (const [scope, bucket] of this.buckets) {
      const quota = this.quotaFor(scope);
      bucket.capacity = quota.burst;
      bucket.tokens = Math.min(bucket.tokens, quota.burst);
      bucket.refillPerSecond = quota.rpm / 60;
    }
  }

  private quotaFor(scope: string): Quota {
    return this.quotas[scope] ?? this.defaultQuota;
  }

  /** Every scope a request is charged against, narrowest first. */
  scopesFor(principal: Principal, model?: string): string[] {
    const scopes = [`principal:${principal.id}`];
    if (principal.tenant) scopes.push(`tenant:${principal.tenant}`);
    for (const role of principal.roles) scopes.push(`role:${role}`);
    if (model) scopes.push(`model:${model}`);
    scopes.push("*");
    // Only configured scopes (plus the catch-all) are charged; otherwise every
    // distinct principal id would allocate a bucket.
    return scopes.filter((s) => s in this.quotas || s === "*");
  }

  check(principal: Principal, model?: string, cost = 1): void {
    const now = Date.now() / 1000;
    const charged: string[] = [];
    for (const scope of this.scopesFor(principal, model)) {
      const bucket = this.bucket(scope, now);
      const elapsed = Math.max(0, now - bucket.updated);
      bucket.tokens = Math.min(bucket.capacity, bucket.tokens + elapsed * bucket.refillPerSecond);
      bucket.updated = now;

      if (bucket.tokens >= cost) {
        bucket.tokens -= cost;
        charged.push(scope);
        this.consumed.set(scope, (this.consumed.get(scope) ?? 0) + cost);
        continue;
      }
      // Refund the scopes already charged: a rejected request must not consume
      // quota it never used.
      for (const done of charged) {
        this.buckets.get(done)!.tokens += cost;
        this.consumed.set(done, Math.max(0, (this.consumed.get(done) ?? 0) - cost));
      }
      const retryAfter = bucket.refillPerSecond > 0 ? (cost - bucket.tokens) / bucket.refillPerSecond : Infinity;
      throw new RateLimitError(
        `rate limit exceeded for ${scope} (${this.quotaFor(scope).rpm} rpm, retry in ${retryAfter.toFixed(1)}s)`,
        retryAfter,
        scope,
      );
    }
    if (this.distributed) void this.renewLeases();
  }

  private bucket(scope: string, now: number): Bucket {
    let bucket = this.buckets.get(scope);
    if (!bucket) {
      if (this.buckets.size >= this.maxBuckets) {
        // Bounded memory: an unbounded dict keyed by principal id is a
        // denial-of-service vector against the limiter itself.
        const oldest = [...this.buckets.entries()].reduce((a, b) => (a[1].updated <= b[1].updated ? a : b));
        this.buckets.delete(oldest[0]);
        this.consumed.delete(oldest[0]);
      }
      const quota = this.quotaFor(scope);
      bucket = { capacity: quota.burst, tokens: quota.burst, refillPerSecond: quota.rpm / 60, updated: now };
      this.buckets.set(scope, bucket);
    }
    return bucket;
  }

  private async renewLeases(): Promise<void> {
    if (!this.leaseClient) return;
    const now = Date.now() / 1000;
    for (const scope of [...this.buckets.keys()]) {
      if (now - (this.leaseAt.get(scope) ?? 0) < this.leaseIntervalS) continue;
      this.leaseAt.set(scope, now);
      try {
        const response = await this.leaseClient(scope, this.consumed.get(scope) ?? 0);
        const lease = response.lease;
        if (!lease) continue;
        this.consumed.set(scope, 0);
        const bucket = this.buckets.get(scope);
        if (bucket) {
          bucket.capacity = lease.burst;
          bucket.tokens = Math.min(bucket.tokens, lease.burst);
          bucket.refillPerSecond = lease.rpm / 60;
        }
      } catch {
        // Fail to the *local* quota, not to unlimited: an unreachable control
        // plane must never raise anyone's limit.
      }
    }
  }

  state(): Record<string, unknown> {
    return {
      distributed: this.distributed,
      scopes: this.buckets.size,
      buckets: Object.fromEntries(
        [...this.buckets.entries()].slice(0, 50).map(([scope, b]) => [
          scope,
          { tokens: Number(b.tokens.toFixed(2)), capacity: b.capacity, rpm: Math.round(b.refillPerSecond * 60) },
        ]),
      ),
    };
  }

  reset(): void {
    this.buckets.clear();
    this.consumed.clear();
    this.leaseAt.clear();
  }
}
