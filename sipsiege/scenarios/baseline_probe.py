"""
scenarios/baseline_probe.py

Single-request, non-destructive check: is the target reachable, and
does it currently respond to SIP? Use this before AND after an
active-tier scenario to see whether pike/htable blocking engaged
(response before, silence/timeout after) and later recovered.

Tier: baseline - no --confirm required, but still scope-gated and
still written to the audit log.
"""

from __future__ import annotations

from typing import Any

from ..core.sipp_runner import SippResult
from .base import BaseScenario, ScenarioResult


class BaselineProbe(BaseScenario):
    name = "baseline_probe"
    tier = "baseline"
    description = "Single REGISTER probe - confirms reachability, does not flood."
    xml_file = "baseline_probe.xml"

    def run(self, target: str, port: int = 5060, transport: str = "udp",
            results_root=None, **kwargs) -> ScenarioResult:
        # A probe is always exactly 1 request at rate 1 for 1 second -
        # operator-supplied rate/duration don't apply here.
        return super().run(
            target=target, port=port, rate=1, duration=1,
            transport=transport, confirm=None, results_root=results_root,
        )

    def _summarize(self, sipp_result: SippResult, total_calls: int, **kwargs) -> dict[str, Any]:
        return {
            "reachable": sipp_result.return_code == 0,
            "note": "Compare this result before/after an active scenario to see "
                    "whether the target started dropping/blocking this source.",
        }
