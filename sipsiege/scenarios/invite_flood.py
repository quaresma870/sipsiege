"""
scenarios/invite_flood.py

Call-setup flood: single real source, high rate, rotating spoofed
identity AND rotating destination extension per call. Each call is
completed cleanly (INVITE -> 200 -> ACK -> immediate BYE) so the only
variable under test is call-setup rate, not dialog volume - a
distinct resource cost from register_flood, since a completed or
even just-attempted INVITE transaction makes the target allocate
transaction (and, if answered, dialog) state that a REGISTER never
does.

Tier: active - requires --confirm <engagement_id>.
"""

from __future__ import annotations

from .base import BaseScenario


class InviteFlood(BaseScenario):
    name = "invite_flood"
    tier = "active"
    description = (
        "Single-source, high-rate INVITE flood - rotating spoofed identity and "
        "destination extension per call, each call completed cleanly (ACK+BYE). "
        "Validates pike/htable and dialog limits trip under call-setup volume, "
        "not just registration volume."
    )
    xml_file = "invite_flood.xml"
