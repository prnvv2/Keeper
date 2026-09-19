"""Gateway mode: the same Keeper engine as a drop-in, OpenAI/Anthropic-compatible proxy.

Keeper's primary integration is the in-process SDK. The gateway exists for the
cases where changing application code is not an option — a third-party tool,
a notebook, an agent framework you do not own — or where the security team
wants a trust boundary the application cannot opt out of::

    pip install "keeper-firewall[gateway]"
    keeper gateway --upstream https://api.openai.com/v1 --port 8787

    # then, in any OpenAI-compatible client:
    OPENAI_BASE_URL=http://localhost:8787/v1

It is not a second implementation. Every request runs through the same
:class:`~keeper_firewall.Keeper` pipeline, policy, risk matrix and audit events
as the SDK; the gateway only translates wire formats.
"""

from __future__ import annotations

from .app import GatewayConfig, KeeperGateway, create_app

__all__ = ["GatewayConfig", "KeeperGateway", "create_app"]
