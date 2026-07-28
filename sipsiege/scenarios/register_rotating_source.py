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
each) - either listed explicitly with --local-ips, or, for anything
past a handful, given as a CIDR range with --local-ip-range (e.g.
10.0.0.0/28) that gets expanded and checked against what's actually
bound. Either way, this tool never configures network interfaces for
you - that's environment-specific and higher-risk to automate blindly;
--local-ip-range only validates addresses you already bound yourself,
it doesn't add any.

The bind check itself is a throwaway UDP socket bind to (ip, 0) - the
OS refuses with EADDRNOTAVAIL if that address isn't actually assigned
to a local interface. No new dependency (no netifaces or similar) and
no parsing of `ip addr` output, which is iproute2/Linux-specific and
would make this fragile across environments.

Tier: active - requires --confirm <engagement_id>.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path

from ..core.engagement import EngagementRefused
from ..core.net import is_bound_locally
from ..core.sipp_runner import run_sipp
from .base import BaseScenario, ScenarioResult

SIPP_XML_DIR = Path(__file__).parent.parent / "sipp_xml"


def _bound_ips_in_range(cidr: str) -> tuple[list[str], list[str]]:
    """Returns (bound, unbound) for every host address in cidr, in address
    order. Doesn't configure or touch any interface - only checks."""
    network = ipaddress.ip_network(cidr, strict=False)
    candidates = [str(ip) for ip in network.hosts()]
    bound = [ip for ip in candidates if is_bound_locally(ip)]
    unbound = [ip for ip in candidates if ip not in bound]
    return bound, unbound


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
        local_ip_range: str | None = None,
        **kwargs,
    ) -> ScenarioResult:
        local_ips = list(local_ips or [])
        range_unbound: list[str] = []
        range_was_used = not local_ips and bool(local_ip_range)
        if range_was_used:
            local_ips, range_unbound = _bound_ips_in_range(local_ip_range)

        if len(local_ips) < 2:
            reason = (
                "register_rotating_source requires at least 2 real local IPs "
                "bound on this host, via --local-ips (comma-separated) or "
                "--local-ip-range (CIDR, e.g. 10.0.0.0/28). "
            )
            if range_was_used:
                total_candidates = len(local_ips) + len(range_unbound)
                reason += (
                    f"--local-ip-range {local_ip_range} has {total_candidates} candidate "
                    f"host addresses but only {len(local_ips)} are actually bound to a "
                    f"local interface - bind more with 'ip addr add <ip>/32 dev <iface>' "
                    f"for each (this tool never configures interfaces itself). "
                    f"Unbound: {range_unbound[:10]}"
                )
            else:
                reason += "Got: " + repr(local_ips)
            return ScenarioResult(
                scenario=self.name, target=target, allowed=False, refusal_reason=reason,
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
            "source_count": len(local_ips),
            "per_source_rate": per_source_rate,
            "total_calls_attempted": total_calls_all_sources,
            "sub_results": [str(r.results_dir) for r in sipp_results],
            "any_nonzero_return_code": any(r.return_code != 0 for r in sipp_results),
        }
        if range_was_used:
            summary["local_ip_range"] = local_ip_range
            summary["unbound_in_range"] = range_unbound

        return ScenarioResult(
            scenario=self.name, target=target, allowed=True,
            sipp_result=sipp_results[0] if sipp_results else None,
            summary=summary,
        )
