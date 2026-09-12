"""Model backend adapters."""

from .base import CallableProvider, EchoProvider, Provider, parse_tool_calls
from .remote import AnthropicProvider, OpenAICompatibleProvider

__all__ = [
    "AnthropicProvider",
    "CallableProvider",
    "EchoProvider",
    "OpenAICompatibleProvider",
    "Provider",
    "parse_tool_calls",
]
