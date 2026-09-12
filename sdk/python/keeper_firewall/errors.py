"""Exception hierarchy for the Keeper SDK.

Every exception raised by Keeper inherits from :class:`KeeperError` so that a
host application can wrap the firewall in a single ``except`` clause without
accidentally swallowing unrelated failures.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .types import Decision


class KeeperError(Exception):
    """Base class for every error raised by the SDK."""


class ConfigurationError(KeeperError):
    """Raised when the SDK is configured in a way that cannot work."""


class BlockedError(KeeperError):
    """Raised when the firewall blocks an interaction.

    The full :class:`~keeper_firewall.types.Decision` is attached so the caller
    can render a useful message, surface the correlation id to the user, or
    re-raise a domain specific error.
    """

    def __init__(self, decision: "Decision") -> None:
        self.decision = decision
        reasons = ", ".join(r.summary for r in decision.reasons) or "policy violation"
        super().__init__(
            f"Keeper blocked this {decision.stage} interaction: {reasons} "
            f"(correlation_id={decision.correlation_id})"
        )


class AuthenticationError(KeeperError):
    """Raised when a principal cannot be authenticated."""


class AuthorizationError(KeeperError):
    """Raised when an authenticated principal is not permitted to act."""

    def __init__(self, message: str, *, principal: str | None = None, resource: str | None = None) -> None:
        self.principal = principal
        self.resource = resource
        super().__init__(message)


class RateLimitError(KeeperError):
    """Raised when a principal exceeds its configured quota."""

    def __init__(self, message: str, *, retry_after: float | None = None, scope: str | None = None) -> None:
        self.retry_after = retry_after
        self.scope = scope
        super().__init__(message)


class PolicyError(KeeperError):
    """Raised when a policy bundle is invalid or cannot be evaluated."""


class DetectorError(KeeperError):
    """Raised when a detector fails irrecoverably.

    Whether this propagates or is swallowed depends on the detector's
    configured ``fail_mode`` (see :mod:`keeper_firewall.config`).
    """

    def __init__(self, detector: str, cause: BaseException | Any) -> None:
        self.detector = detector
        self.cause = cause
        super().__init__(f"detector {detector!r} failed: {cause}")


class TransportError(KeeperError):
    """Raised when the SDK cannot talk to the control plane."""
