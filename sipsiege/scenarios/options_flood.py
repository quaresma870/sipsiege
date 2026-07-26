"""
scenarios/options_flood.py

Method-scope rate-limiting bypass: same flood shape as register_flood
(single real source, high rate, rotating spoofed identity per request),
using OPTIONS instead of REGISTER. Most real Kamailio configs wire
pike/htable checks into the REGISTER and INVITE routes specifically -
OPTIONS (along with SUBSCRIBE, MESSAGE, PUBLISH, etc.) commonly passes
straight through unrated. A source already blocked instantly over
REGISTER can still flood freely over an unprotected method like OPTIONS
if the same limiter isn't wired into every route that reaches it.

Tier: active - requires --confirm <engagement_id>.
"""

from __future__ import annotations

from .base import BaseScenario


class OptionsFlood(BaseScenario):
    name = "options_flood"
    tier = "active"
    description = (
        "Single-source, high-rate OPTIONS flood with rotating spoofed "
        "identities per request. Validates whether rate limiting is wired "
        "into every SIP method's route, not just REGISTER/INVITE - a source "
        "already blocked over REGISTER may still flood freely over an "
        "unprotected method like OPTIONS."
    )
    xml_file = "options_flood.xml"
