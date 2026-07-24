"""
scenarios/base.py

Every scenario declares a tier:
  - "baseline": read-only/single-probe, always allowed once in scope
                (still audit-logged, still scope-gated - just never
                needs --confirm).
  - "active":   sends volume traffic capable of degrading the target
                (floods, bursts). Requires --confirm <engagement_id>
                on every single invocation, no exceptions, no persisted
                override.

This mirrors the recon / active split in redteam-toolkit, adapted to
two tiers rather than three since there's no meaningful "vuln-id"
middle tier for a SIP flood-testing tool - a probe either sends one
request or it sends a lot of them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..core.engagement import Engagement, EngagementRefused
from ..core.sipp_runner import SippResult, run_sipp

SIPP_XML_DIR = Path(__file__).parent.parent / "sipp_xml"


@dataclass
class ScenarioResult:
    scenario: str
    target: str
    allowed: bool
    refusal_reason: str | None = None
    sipp_result: SippResult | None = None
    summary: dict[str, Any] = field(default_factory=dict)


class BaseScenario:
    name: str = "base"
    tier: str = "baseline"          # "baseline" | "active"
    description: str = ""
    xml_file: str = ""

    def __init__(self, engagement: Engagement):
        self.engagement = engagement

    def run(
        self,
        target: str,
        port: int = 5060,
        rate: int = 10,
        duration: int = 10,
        transport: str = "udp",
        confirm: str | None = None,
        results_root: Path | None = None,
        **kwargs,
    ) -> ScenarioResult:
        total_calls = rate * duration

        try:
            self.engagement.gate(
                action=f"scenario:{self.name}",
                target=target,
                tier=self.tier,
                confirm_engagement_id=confirm,
                rate=rate,
                duration=duration,
            )
        except EngagementRefused as e:
            return ScenarioResult(
                scenario=self.name, target=target, allowed=False, refusal_reason=str(e)
            )

        results_dir = (results_root or Path("results")) / self.name / target.replace(":", "_")
        scenario_xml = SIPP_XML_DIR / self.xml_file

        sipp_result = run_sipp(
            target=target,
            port=port,
            scenario_file=scenario_xml,
            rate=rate,
            total_calls=total_calls,
            transport=transport,
            results_dir=results_dir,
            **self._extra_sipp_kwargs(**kwargs),
        )

        summary = self._summarize(sipp_result, total_calls=total_calls, **kwargs)
        return ScenarioResult(
            scenario=self.name, target=target, allowed=True,
            sipp_result=sipp_result, summary=summary,
        )

    # Hooks for subclasses that need extra sipp args or custom summaries
    def _extra_sipp_kwargs(self, **kwargs) -> dict[str, Any]:
        return {}

    def _summarize(self, sipp_result: SippResult, total_calls: int, **kwargs) -> dict[str, Any]:
        return {
            "total_calls_attempted": total_calls,
            "return_code": sipp_result.return_code,
            "stats_file": str(sipp_result.stats_csv),
        }
