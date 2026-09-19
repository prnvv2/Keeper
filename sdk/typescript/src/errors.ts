/** Exception hierarchy, mirroring `keeper_firewall.errors`. */

import type { Decision } from "./types.js";
import { decisionReasons } from "./types.js";

export class KeeperError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
    // Without this, `instanceof` breaks for subclasses when the package is
    // compiled down to ES5 by a consumer's toolchain.
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class ConfigurationError extends KeeperError {}

export class BlockedError extends KeeperError {
  constructor(readonly decision: Decision) {
    const reasons = decisionReasons(decision).map((r) => r.summary).join(", ") || "policy violation";
    super(
      `Keeper blocked this ${decision.stage} interaction: ${reasons} (correlationId=${decision.correlationId})`,
    );
  }
}

export class AuthenticationError extends KeeperError {}

export class AuthorizationError extends KeeperError {
  constructor(message: string, readonly principal?: string, readonly resource?: string) {
    super(message);
  }
}

export class RateLimitError extends KeeperError {
  constructor(message: string, readonly retryAfter?: number, readonly scope?: string) {
    super(message);
  }
}

export class PolicyError extends KeeperError {}

export class DetectorError extends KeeperError {
  constructor(readonly detector: string, override readonly cause: unknown) {
    super(`detector '${detector}' failed: ${String(cause)}`);
  }
}

export class TransportError extends KeeperError {}
