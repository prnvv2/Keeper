"""ASGI middleware.

Currently one concern: decompressing request bodies.

The SDK gzips telemetry batches above a few kilobytes, which is most real
batches — an audit event carrying findings, evidence and a redacted payload is
1-4 KB, so a batch of fifty is well past the threshold. Compression matters
here: telemetry is the highest-volume thing crossing this boundary, and audit
events are JSON with enormously repetitive keys, so gzip typically takes 80% off
the wire.

ASGI servers do not decompress request bodies, and neither does Starlette, so
without this the control plane returns 400 on every compressed batch. That is
exactly the failure this middleware exists to prevent, and it is invisible in a
test suite that only ever sends one event at a time.
"""

from __future__ import annotations

import gzip
import zlib

from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

#: Refuse to inflate beyond this. A few kilobytes of crafted gzip can expand to
#: gigabytes, and an ingest endpoint that will allocate whatever a client asks
#: for is a denial-of-service primitive.
MAX_DECOMPRESSED_BYTES = 64 * 1024 * 1024


class DecompressRequestMiddleware:
    """Transparently inflate ``Content-Encoding: gzip`` / ``deflate`` bodies."""

    def __init__(self, app: ASGIApp, max_bytes: int = MAX_DECOMPRESSED_BYTES) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        encoding = Headers(scope=scope).get("content-encoding", "").lower().strip()
        if encoding not in ("gzip", "deflate"):
            await self.app(scope, receive, send)
            return

        body = bytearray()
        more = True
        while more:
            message = await receive()
            if message["type"] != "http.request":
                break
            body.extend(message.get("body", b""))
            more = message.get("more_body", False)
            if len(body) > self.max_bytes:
                await _reject(send, "compressed request body is too large")
                return

        try:
            decompressed = _inflate(bytes(body), encoding, self.max_bytes)
        except (OSError, zlib.error, ValueError) as exc:
            await _reject(send, f"could not decompress request body: {exc}")
            return

        # Rewrite the headers so downstream sees a plain, correctly-sized body.
        headers = MutableHeaders(scope=scope)
        del headers["content-encoding"]
        headers["content-length"] = str(len(decompressed))

        sent = False

        async def replay() -> Message:
            nonlocal sent
            if sent:
                return {"type": "http.disconnect"}
            sent = True
            return {"type": "http.request", "body": decompressed, "more_body": False}

        await self.app(scope, replay, send)


def _inflate(body: bytes, encoding: str, max_bytes: int) -> bytes:
    """Streaming inflate with a hard output cap (zip-bomb protection)."""
    if not body:
        return b""
    wbits = 16 + zlib.MAX_WBITS if encoding == "gzip" else zlib.MAX_WBITS
    decompressor = zlib.decompressobj(wbits)
    out = decompressor.decompress(body, max_bytes + 1)
    if len(out) > max_bytes or decompressor.unconsumed_tail:
        raise ValueError(f"decompressed body exceeds {max_bytes} bytes")
    return out + decompressor.flush()


async def _reject(send: Send, detail: str) -> None:
    import json

    payload = json.dumps({"detail": detail}).encode()
    await send({
        "type": "http.response.start",
        "status": 400,
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(payload)).encode()),
        ],
    })
    await send({"type": "http.response.body", "body": payload})


__all__ = ["MAX_DECOMPRESSED_BYTES", "DecompressRequestMiddleware", "gzip"]
