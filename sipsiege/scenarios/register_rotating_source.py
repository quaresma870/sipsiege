"""
scenarios/register_rotating_source.py

Simulates a distributed/rotating-source flood - unlike register_flood
(one real IP, spoofed headers), this spawns one SIPp process per
*local* IP address you provide, all hitting the target concurrently.
This tests whether your blocking approach depends on single-source
rate (pike) or needs something broader (e.g. a WAF-style aggregate
rate limit), since per-IP thresholds like pike's won't trip if no
single source crosses the threshold on its own.

Requires: multiple IP addresses actually bound to interfaces on the
box you run this from (e.g. via `ip addr add <ip>/32 dev eth0` for
each). This tool does not configure network interfaces for you -
that's environment-specific and higher-risk to automate blindly.

Tier: active - requires --confirm <engagement_id>.
"""

from __future__ import annotations

from pathlib import Path

from ..core.engagement import EngagementRefused
from ..core.sipp_runner import run_sipp
from .base import BaseScenario, ScenarioResult

SIPP_XML_DIR = Path(__file__).parent.parent / "sipp_xml"


class RegisterRotatingSource(BaseScenario):
    name = "register_rotating_source"
    tier = "active"
    description = (
        "Concurrent REGISTER flood from multiple real local source IPs - "
        "tests whether blocking holds when no single source crosses a "
        "per-IP threshold on its own."
    )
    xml_file = "register_rotating_source.xml"

    def run(
        self,
        target: str,
        port: int = 5060,
        rate: int = 10,
        duration: int = 10,
        transport: str = "udp",
        confirm: str | None = None,
        results_root: Path | None = None,
        local_ips: list[str] | None = None,
        **kwargs,
    ) -> ScenarioResult:
        local_ips = local_ips or []
        if len(local_ips) < 2:
            return ScenarioResult(
                scenario=self.name, target=target, allowed=False,
                refusal_reason=(
                    "register_rotating_source requires --local-ips with at least "
                    "2 addresses bound on this host (e.g. --local-ips 10.0.0.5,10.0.0.6). "
                    "Got: " + repr(local_ips)
                ),
            )

        per_source_rate = max(1, rate // len(local_ips))
        total_calls_all_sources = per_source_rate * duration * len(local_ips)

        try:
            self.engagement.gate(
                action=f"scenario:{self.name}",
                target=target,
                tier=self.tier,
                confirm_engagement_id=confirm,
                rate=per_source_rate * len(local_ips),  # combined rate for budget check
                duration=duration,
            )
        except EngagementRefused as e:
            return ScenarioResult(scenario=self.name, target=target, allowed=False, refusal_reason=str(e))

        results_dir = (results_root or Path("results")) / self.name / target.replace(":", "_")
        scenario_xml = SIPP_XML_DIR / self.xml_file

        # Launch one sipp per local IP. run_sipp() is blocking, so we use
        # threads purely to get them running concurrently - each still
        # shells out to its own sipp subprocess.
        import concurrent.futures

        sipp_results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(local_ips)) as pool:
            futures = [
                pool.submit(
                    run_sipp,
                    target=target,
                    port=port,
                    scenario_file=scenario_xml,
                    rate=per_source_rate,
                    total_calls=per_source_rate * duration,
                    transport=transport,
                    results_dir=results_dir / ip.replace(".", "_"),
                    local_ip=ip,
                )
                for ip in local_ips
            ]
            for f in concurrent.futures.as_completed(futures):
                sipp_results.append(f.result())

        summary = {
            "sources_used": local_ips,
            "per_source_rate": per_source_rate,
            "total_calls_attempted": total_calls_all_sources,
            "sub_results": [str(r.results_dir) for r in sipp_results],
            "any_nonzero_return_code": any(r.return_code != 0 for r in sipp_results),
        }

        return ScenarioResult(
            scenario=self.name, target=target, allowed=True,
            sipp_result=sipp_results[0] if sipp_results else None,
            summary=summary,
        )
