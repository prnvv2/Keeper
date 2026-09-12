"""Keeper control plane.

The aggregation, investigation, policy-distribution, alerting and SIEM-export
half of the Keeper AI firewall. SDK instances report here; security teams work
here.
"""

from .version import __version__

__all__ = ["__version__"]
