import importlib.metadata
import logging

from keeper.core.exceptions import PluginLoadError
from keeper.layers.base import BaseLayer
from keeper.guardrails.base import BaseGuardrail

logger = logging.getLogger("keeper.plugins")


def discover_layers() -> dict[str, type[BaseLayer]]:
    layers = {}
    for ep in importlib.metadata.entry_points(group="keeper.plugins.layers"):
        try:
            cls = ep.load()
            layers[ep.name] = cls
        except Exception as exc:
            logger.warning("Failed to load layer plugin '%s': %s", ep.name, exc)
    return layers


def discover_guardrails() -> dict[str, type[BaseGuardrail]]:
    guardrails = {}
    for ep in importlib.metadata.entry_points(group="keeper.plugins.guardrails"):
        try:
            cls = ep.load()
            guardrails[ep.name] = cls
        except Exception as exc:
            logger.warning("Failed to load guardrail plugin '%s': %s", ep.name, exc)
    return guardrails


def discover_integrations() -> dict[str, type]:
    integrations = {}
    for ep in importlib.metadata.entry_points(group="keeper.plugins.integrations"):
        try:
            integrations[ep.name] = ep.load()
        except Exception as exc:
            logger.warning("Failed to load integration plugin '%s': %s", ep.name, exc)
    return integrations
