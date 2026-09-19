"""Authentication providers.

The SDK runs *inside* the application, which already authenticated its user.
So the common and recommended integration is :class:`CallableProvider`: the app
hands Keeper the principal it already established. Keeper is not trying to be
the application's identity system.

The other providers exist for the cases where Keeper genuinely is the first
thing to see a credential — a thin proxy-like wrapper, a standalone agent
runner, or the future sidecar mode — and to make the pluggable-auth contract
concrete rather than aspirational.

API keys are compared with :func:`hmac.compare_digest` against stored hashes,
never in plaintext and never with ``==``; an equality check on a secret is a
timing oracle, and this is a security product.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

from ..errors import AuthenticationError, ConfigurationError
from ..types import Principal


class AuthProvider(Protocol):
    """Turns a credential into a :class:`Principal`, or raises."""

    name: str

    def authenticate(self, credential: str | None, **context: Any) -> Principal: ...


@dataclass(slots=True)
class APIKeyRecord:
    """A stored API key: its hash, who it is, and what it may do."""

    key_id: str
    hash_hex: str
    principal_id: str
    roles: tuple[str, ...] = ()
    tenant: str | None = None
    disabled: bool = False
    expires_ms: int | None = None
    attributes: Mapping[str, Any] = field(default_factory=dict)


def hash_api_key(key: str, salt: str = "") -> str:
    """Hash an API key for storage.

    PBKDF2 rather than a bare SHA-256: API keys are long random strings, so a
    fast hash would usually be fine, but "usually" is doing too much work in a
    file that operators will inevitably populate with short keys by hand.
    """
    return hashlib.pbkdf2_hmac("sha256", key.encode(), (salt or "keeper").encode(), 100_000).hex()


class APIKeyProvider:
    """Authenticates against a file of hashed API keys.

    File format (JSON)::

        {
          "salt": "…",
          "keys": [
            {"key_id": "ci", "hash": "…", "principal_id": "svc:ci",
             "roles": ["service"], "tenant": "acme"}
          ]
        }

    The file is re-read when its mtime changes, so rotating a key does not
    require restarting the application.
    """

    name = "api_key"

    def __init__(self, path: str | None = None, *, records: list[APIKeyRecord] | None = None, salt: str = "") -> None:
        self.path = path
        self.salt = salt
        self._lock = threading.Lock()
        self._records: dict[str, APIKeyRecord] = {r.hash_hex: r for r in (records or [])}
        self._mtime: float | None = None
        if path:
            self._load()

    def _load(self) -> None:
        assert self.path
        if not os.path.exists(self.path):
            raise ConfigurationError(f"API key file not found: {self.path}")
        mtime = os.path.getmtime(self.path)
        with self._lock:
            if self._mtime == mtime:
                return
            with open(self.path, encoding="utf-8") as fh:
                data = json.load(fh)
            self.salt = data.get("salt", self.salt)
            records: dict[str, APIKeyRecord] = {}
            for entry in data.get("keys", []):
                record = APIKeyRecord(
                    key_id=entry["key_id"],
                    hash_hex=entry["hash"],
                    principal_id=entry.get("principal_id", entry["key_id"]),
                    roles=tuple(entry.get("roles", ())),
                    tenant=entry.get("tenant"),
                    disabled=bool(entry.get("disabled", False)),
                    expires_ms=entry.get("expires_ms"),
                    attributes=entry.get("attributes") or {},
                )
                records[record.hash_hex] = record
            self._records = records
            self._mtime = mtime

    def authenticate(self, credential: str | None, **context: Any) -> Principal:
        if not credential:
            raise AuthenticationError("no API key supplied")
        if self.path:
            self._load()
        candidate = hash_api_key(credential, self.salt)
        # Constant-time comparison against every record: a short-circuit on the
        # first mismatch would leak which prefix was correct.
        matched: APIKeyRecord | None = None
        for stored_hash, record in self._records.items():
            if hmac.compare_digest(candidate, stored_hash):
                matched = record
        if matched is None:
            raise AuthenticationError("invalid API key")
        if matched.disabled:
            raise AuthenticationError(f"API key {matched.key_id!r} is disabled")
        if matched.expires_ms and matched.expires_ms < int(time.time() * 1000):
            raise AuthenticationError(f"API key {matched.key_id!r} has expired")
        return Principal(
            id=matched.principal_id,
            roles=matched.roles,
            tenant=matched.tenant,
            attributes=dict(matched.attributes),
            authenticated=True,
            auth_method="api_key",
        )


class CallableProvider:
    """Delegates to the host application's own authentication.

    The recommended integration. The application already knows who its user is;
    this hands Keeper that identity without Keeper ever seeing a credential.
    """

    name = "callable"

    def __init__(self, resolver: Callable[..., Principal]) -> None:
        self.resolver = resolver

    def authenticate(self, credential: str | None, **context: Any) -> Principal:
        try:
            principal = self.resolver(credential, **context)
        except AuthenticationError:
            raise
        except Exception as exc:
            raise AuthenticationError(f"principal resolver failed: {exc}") from exc
        if not isinstance(principal, Principal):
            raise AuthenticationError("principal resolver must return a Principal")
        return principal


class OIDCProvider:
    """Validates an OIDC/OAuth2 JWT access token.

    Signature verification needs a JWKS fetch and RSA/EC verification, which
    means a crypto dependency. Rather than pull one into every install, this
    provider takes a ``verifier`` callable — wire it to ``PyJWT``,
    ``authlib``, or whatever the organisation already trusts:

    .. code-block:: python

        import jwt
        from jwt import PyJWKClient

        jwks = PyJWKClient(cfg.oidc_jwks_url)
        def verify(token: str) -> dict:
            key = jwks.get_signing_key_from_jwt(token).key
            return jwt.decode(token, key, algorithms=["RS256"],
                              audience=cfg.oidc_audience, issuer=cfg.oidc_issuer)

        provider = OIDCProvider(verifier=verify)

    Without a verifier it refuses to run. It does **not** fall back to decoding
    claims unverified — an unverified JWT is an attacker-controlled dictionary,
    and a security product that treats one as an identity is worse than one
    with no auth at all.
    """

    name = "oidc"

    def __init__(
        self,
        *,
        verifier: Callable[[str], Mapping[str, Any]] | None = None,
        issuer: str | None = None,
        audience: str | None = None,
        principal_claim: str = "sub",
        roles_claim: str = "roles",
        tenant_claim: str = "tid",
    ) -> None:
        self.verifier = verifier
        self.issuer = issuer
        self.audience = audience
        self.principal_claim = principal_claim
        self.roles_claim = roles_claim
        self.tenant_claim = tenant_claim

    def authenticate(self, credential: str | None, **context: Any) -> Principal:
        if self.verifier is None:
            raise ConfigurationError(
                "OIDCProvider requires a 'verifier' callable that validates the token "
                "signature; see the class docstring for a PyJWT example"
            )
        if not credential:
            raise AuthenticationError("no bearer token supplied")
        token = credential.split(" ", 1)[1] if credential.lower().startswith("bearer ") else credential
        try:
            claims = self.verifier(token)
        except Exception as exc:
            raise AuthenticationError(f"token verification failed: {exc}") from exc

        if self.issuer and claims.get("iss") != self.issuer:
            raise AuthenticationError("token issuer mismatch")
        if self.audience:
            aud = claims.get("aud")
            audiences = aud if isinstance(aud, (list, tuple)) else [aud]
            if self.audience not in audiences:
                raise AuthenticationError("token audience mismatch")

        raw_roles = claims.get(self.roles_claim) or []
        roles = tuple(raw_roles) if isinstance(raw_roles, (list, tuple)) else (str(raw_roles),)
        subject = claims.get(self.principal_claim)
        if not subject:
            raise AuthenticationError(f"token has no {self.principal_claim!r} claim")
        return Principal(
            id=str(subject),
            roles=roles,
            tenant=claims.get(self.tenant_claim),
            attributes={k: v for k, v in claims.items() if k not in ("iat", "exp", "nbf")},
            authenticated=True,
            auth_method="oidc",
        )


class MTLSProvider:
    """Derives a principal from a verified client certificate.

    TLS termination happens outside the SDK, so this provider reads the
    already-verified certificate details the server put in the request context
    (``subject``, ``fingerprint``). It trusts that its input came from a real
    mTLS handshake — which is true when the caller is the application's own
    server, and is documented as a trust assumption in ``docs/threat-model.md``.
    """

    name = "mtls"

    def __init__(self, *, allowed_fingerprints: Mapping[str, tuple[str, ...]] | None = None) -> None:
        self.allowed = dict(allowed_fingerprints or {})

    def authenticate(self, credential: str | None, **context: Any) -> Principal:
        fingerprint = context.get("fingerprint") or credential
        subject = context.get("subject")
        if not fingerprint:
            raise AuthenticationError("no client certificate fingerprint supplied")
        normalised = fingerprint.replace(":", "").lower()
        if self.allowed:
            match = None
            for allowed_fp, roles in self.allowed.items():
                if hmac.compare_digest(normalised, allowed_fp.replace(":", "").lower()):
                    match = roles
            if match is None:
                raise AuthenticationError("client certificate is not allow-listed")
            return Principal(
                id=subject or f"cert:{normalised[:16]}",
                roles=tuple(match),
                authenticated=True,
                auth_method="mtls",
            )
        return Principal(
            id=subject or f"cert:{normalised[:16]}",
            roles=tuple(context.get("roles", ())),
            authenticated=True,
            auth_method="mtls",
        )


def generate_api_key(prefix: str = "kf") -> tuple[str, str]:
    """Generate ``(key, hash)``. The key is shown once; only the hash is stored."""
    raw = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")
    key = f"{prefix}_{raw}"
    return key, hash_api_key(key)


def build_provider(config: Any, resolver: Callable[..., Principal] | None = None) -> AuthProvider:
    """Construct the provider named by :class:`AccessControlConfig`."""
    kind = config.auth_provider
    if kind == "callable":
        if resolver is None:
            raise ConfigurationError("auth_provider='callable' requires a principal resolver")
        return CallableProvider(resolver)
    if kind == "api_key":
        return APIKeyProvider(config.api_keys_path)
    if kind == "oidc":
        return OIDCProvider(issuer=config.oidc_issuer, audience=config.oidc_audience)
    if kind == "mtls":
        return MTLSProvider()
    raise ConfigurationError(f"unknown auth provider {kind!r}")
