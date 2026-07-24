"""
scenarios/register_burst.py

Sends a short burst deliberately calibrated to sit just under the
pike/htable threshold you're testing, to check for false positives -
i.e. confirm legitimate bursty traffic (a phone bank rebooting, a
mass re-registration after a network blip) does NOT get blocked.

Tier: active - it still generates real volume against the target and
could trip protection if your threshold assumption is wrong, so it
goes through the same confirm gate as register_flood.

Usage note: pass --rate and --duration to size the burst relative to
whatever pike reqs_density_per_unit/sampling_time_unit you've
configured on the test SBC, e.g. if the threshold is "15 requests per
2 seconds", a burst of rate=7 for duration=2 stays just under it.
"""

from __future__ import annotations

from .base import BaseScenario


class RegisterBurst(BaseScenario):
    name = "register_burst"
    tier = "active"
    description = (
        "Short burst sized just under your configured pike threshold - "
        "confirms legitimate bursty traffic isn't false-positive blocked."
    )
    xml_file = "register_burst.xml"
