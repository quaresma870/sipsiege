"""
scenarios/register_flood.py

The scenario from the first pass of this toolkit: single real
source, high rate, rotating spoofed From/To/Contact identity per
request. Reproduces the 19 July 2026 incident pattern.

Tier: active - requires --confirm <engagement_id>.
"""

from __future__ import annotations

from .base import BaseScenario


class RegisterFlood(BaseScenario):
    name = "register_flood"
    tier = "active"
    description = (
        "Single-source, high-rate REGISTER flood with rotating spoofed "
        "identities per request. Validates pike/htable trip under sustained "
        "single-IP volume."
    )
    xml_file = "register_flood.xml"
