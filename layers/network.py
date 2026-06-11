# layers/network.py
# First line of defense — enforces rate limits and IP blocklists
# before any semantic processing. Prevents DoS and brute-force probing.

import time
from keeper.layers.base import BaseLayer
from keeper.core.pipeline import RequestContext
from keeper.core.engine import Action


class NetworkLayer(BaseLayer):
    name = "network"

    def __init__(self):
        # In-memory sliding-window rate tracker: {ip: [timestamps]}
        self.buckets = {}

    async def analyze(self, ctx: RequestContext, config: dict) -> RequestContext:
        # 1) Check IP blocklist
        # 2) Enforce per-IP rate limit using a 60-second sliding window
        ip = ctx.ip
        rate_limit = config.get("rate_limit", "100/min")
        max_rpm = int(rate_limit.split("/")[0])
        block_ips = config.get("block_ips", [])

        if ip in block_ips:
            ctx.action = Action.BLOCK
            ctx.violations.append(f"blocked IP: {ip}")
            return ctx

        now = time.time()
        bucket = self.buckets.get(ip, [])
        # Keep only timestamps within the last 60 seconds
        bucket = [t for t in bucket if now - t < 60]
        bucket.append(now)
        self.buckets[ip] = bucket

        if len(bucket) > max_rpm:
            ctx.action = Action.BLOCK
            ctx.violations.append(f"rate limit exceeded: {len(bucket)}/{max_rpm} rpm")
        return ctx
