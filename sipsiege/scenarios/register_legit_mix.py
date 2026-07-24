"""
scenarios/register_legit_mix.py

Runs the attack flood and a low-rate "legitimate" REGISTER stream at
the same time, from two different local IPs, then compares the
legitimate stream's success rate during/after the flood against its
own baseline. This is the check that actually matters operationally:
pike/htable blocking the attacker is only a win if your real
endpoints don't get caught in the same net.

Requires two local IPs: one plays the attacker, one plays a normal
registered endpoint.

Tier: active - requires --confirm <engagement_id>.
"""

from __future__ import annotations

import csv
import io
from pathlib import Path
from typing import Any

from ..core.engagement import EngagementRefused
from ..core.sipp_runner import run_sipp
from .base import BaseScenario, ScenarioResult

SIPP_XML_DIR = Path(__file__).parent.parent / "sipp_xml"


def _parse_success_rate(stats_csv: Path) -> dict[str, Any] | None:
    if not stats_csv.exists():
        return None
    with open(stats_csv) as f:
        content = f.read()
    # SIPp's -stf output is semicolon-delimited with a header line.
    reader = csv.DictReader(io.StringIO(content), delimiter=";")
    rows = list(reader)
    if not rows:
        return None
    last = rows[-1]
    return {
        "successful_call": last.get("SuccessfulCall(P)") or last.get("SuccessfulCall"),
        "failed_call": last.get("FailedCall(P)") or last.get("FailedCall"),
        "call_rate": last.get("CallRate(P)") or last.get("CallRate"),
    }


class RegisterLegitMix(BaseScenario):
    name = "register_legit_mix"
    tier = "active"
    description = (
        "Runs the flood and a low-rate legitimate REGISTER stream concurrently, "
        "then compares the legitimate stream's success rate against baseline to "
        "check for collateral blocking."
    )
    xml_file = "register_flood.xml"  # attacker side reuses the flood scenario
    legit_xml_file = "register_legit.xml"

    def run(
        self,
        target: str,
        port: int = 5060,
        rate: int = 50,
        duration: int = 30,
        transport: str = "udp",
        confirm: str | None = None,
        results_root: Path | None = None,
        attacker_ip: str | None = None,
        legit_ip: str | None = None,
        legit_rate: int = 1,
        **kwargs,
    ) -> ScenarioResult:
        if not attacker_ip or not legit_ip:
            return ScenarioResult(
                scenario=self.name, target=target, allowed=False,
                refusal_reason=(
                    "register_legit_mix requires --attacker-ip and --legit-ip "
                    "(two distinct local IPs bound on this host)."
                ),
            )

        try:
            self.engagement.gate(
                action=f"scenario:{self.name}",
                target=target,
                tier=self.tier,
                confirm_engagement_id=confirm,
                rate=rate + legit_rate,
                duration=duration,
            )
        except EngagementRefused as e:
            return ScenarioResult(scenario=self.name, target=target, allowed=False, refusal_reason=str(e))

        results_dir = (results_root or Path("results")) / self.name / target.replace(":", "_")

        # 1. Baseline: legit stream alone, no attacker, to establish its
        #    normal success rate.
        baseline_dir = results_dir / "legit_baseline"
        baseline_result = run_sipp(
            target=target, port=port,
            scenario_file=SIPP_XML_DIR / self.legit_xml_file,
            rate=legit_rate, total_calls=legit_rate * 10,
            transport=transport, results_dir=baseline_dir, local_ip=legit_ip,
        )
        baseline_stats = _parse_success_rate(baseline_result.stats_csv)

        # 2. Concurrent: attacker flood + legit stream at the same time.
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            attacker_future = pool.submit(
                run_sipp,
                target=target, port=port,
                scenario_file=SIPP_XML_DIR / self.xml_file,
                rate=rate, total_calls=rate * duration,
                transport=transport, results_dir=results_dir / "attacker", local_ip=attacker_ip,
            )
            legit_future = pool.submit(
                run_sipp,
                target=target, port=port,
                scenario_file=SIPP_XML_DIR / self.legit_xml_file,
                rate=legit_rate, total_calls=legit_rate * duration,
                transport=transport, results_dir=results_dir / "legit_during", local_ip=legit_ip,
            )
            attacker_result = attacker_future.result()
            legit_during_result = legit_future.result()

        during_stats = _parse_success_rate(legit_during_result.stats_csv)

        summary = {
            "baseline_legit_stats": baseline_stats,
            "legit_stats_during_flood": during_stats,
            "attacker_return_code": attacker_result.return_code,
            "interpretation": (
                "Compare baseline_legit_stats vs legit_stats_during_flood. "
                "A meaningfully lower successful_call rate during the flood "
                "indicates the legit endpoint is being collaterally blocked, "
                "not just the attacker."
            ),
        }

        return ScenarioResult(
            scenario=self.name, target=target, allowed=True,
            sipp_result=legit_during_result, summary=summary,
        )
