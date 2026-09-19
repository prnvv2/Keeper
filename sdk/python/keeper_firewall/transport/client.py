"""Minimal HTTP client for talking to the control plane.

Built on :mod:`urllib.request` rather than ``requests`` or ``httpx``. The SDK
is installed into other people's applications, so every dependency we add is a
dependency *they* now have to audit, pin, and patch. A control-plane client
that posts JSON and follows an ETag does not justify pulling a transitive tree
into a security product. (The control plane itself uses httpx freely — it is a
service we deploy, not a library we inject.)

TLS verification is on and cannot be turned off by configuration; an operator
who needs a private CA points ``SSL_CERT_FILE``/``REQUESTS_CA_BUNDLE`` at it,
which is auditable in a way a ``verify=false`` flag is not.
"""

from __future__ import annotations

import gzip
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ..errors import ConfigurationError, TransportError
from ..version import __version__

USER_AGENT = f"keeper-firewall-python/{__version__}"
_GZIP_THRESHOLD = 4096


@dataclass(slots=True)
class Response:
    status: int
    body: bytes
    headers: Mapping[str, str]

    def json(self) -> Any:
        if not self.body:
            return None
        return json.loads(self.body.decode("utf-8"))

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300


class ControlPlaneClient:
    """Small, blocking JSON-over-HTTPS client.

    Every call is made from a background thread (telemetry shipping, policy
    refresh), never from the request hot path, so blocking IO here is fine and
    much simpler to reason about than an async client the host app has to keep
    an event loop alive for.
    """

    def __init__(
        self,
        base_url: str,
        *,
        api_key: str | None = None,
        timeout_ms: int = 3000,
        ca_bundle: str | None = None,
        extra_headers: Mapping[str, str] | None = None,
    ) -> None:
        scheme = urllib.parse.urlsplit(base_url).scheme.lower()
        if scheme not in ("http", "https"):
            # urlopen also honours file: and ftp:; a mistyped endpoint must not
            # turn telemetry shipping into a local file read.
            raise ConfigurationError(f"endpoint must be an http(s) URL, got scheme {scheme!r}")
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout_ms / 1000
        self.extra_headers = dict(extra_headers or {})
        self._ssl_context = ssl.create_default_context(cafile=ca_bundle)
        self._ssl_context.check_hostname = True
        self._ssl_context.verify_mode = ssl.CERT_REQUIRED

    # -- verbs -------------------------------------------------------------

    def post_json(self, path: str, payload: Any, *, headers: Mapping[str, str] | None = None) -> Response:
        body = json.dumps(payload, separators=(",", ":"), default=str).encode()
        hdrs = {"Content-Type": "application/json"}
        if len(body) > _GZIP_THRESHOLD:
            body = gzip.compress(body)
            hdrs["Content-Encoding"] = "gzip"
        hdrs.update(headers or {})
        return self.request("POST", path, body=body, headers=hdrs)

    def get_json(self, path: str, *, headers: Mapping[str, str] | None = None, params: Mapping[str, Any] | None = None) -> Response:
        if params:
            path = f"{path}?{urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})}"
        return self.request("GET", path, headers=headers)

    def request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> Response:
        url = path if urllib.parse.urlsplit(path).scheme in ("http", "https") else f"{self.base_url}{path}"
        hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json", **self.extra_headers}
        if self.api_key:
            hdrs["Authorization"] = f"Bearer {self.api_key}"
        hdrs.update(headers or {})

        request = urllib.request.Request(url, data=body, headers=hdrs, method=method)  # noqa: S310 - http(s) only
        try:
            # Scheme restricted to http(s) in __init__ and above.
            with urllib.request.urlopen(request, timeout=self.timeout, context=self._ssl_context) as resp:  # noqa: S310
                return Response(resp.status, resp.read(), dict(resp.headers))
        except urllib.error.HTTPError as exc:
            # 304 and 4xx are answers, not failures: the caller decides.
            return Response(exc.code, exc.read() or b"", dict(exc.headers or {}))
        except urllib.error.URLError as exc:
            raise TransportError(f"{method} {url} failed: {exc.reason}") from exc
        except (TimeoutError, OSError) as exc:
            raise TransportError(f"{method} {url} failed: {exc}") from exc

    # -- control plane API -------------------------------------------------

    def ship_events(self, events: list[dict[str, Any]], instance_id: str) -> Response:
        return self.post_json(
            "/v1/telemetry/events",
            {"instance_id": instance_id, "events": events},
        )

    def fetch_policy(self, bundle: str, etag: str | None = None) -> Response:
        headers = {"If-None-Match": etag} if etag else {}
        return self.get_json(f"/v1/policies/{urllib.parse.quote(bundle)}", headers=headers)

    def register_instance(self, payload: Mapping[str, Any]) -> Response:
        return self.post_json("/v1/fleet/register", dict(payload))

    def heartbeat(self, payload: Mapping[str, Any]) -> Response:
        return self.post_json("/v1/fleet/heartbeat", dict(payload))

    def check_quota(self, payload: Mapping[str, Any]) -> Response:
        return self.post_json("/v1/quota/check", dict(payload))
