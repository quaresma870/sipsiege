"""
scenarios/user_enum.py

Extension/account enumeration - recon, not load. Precedes
digest_bruteforce in a real attack chain: probing a range of candidate
extensions with a single unauthenticated REGISTER each and diffing the
response tells an attacker which extensions are worth brute-forcing
before spending any real effort on them, the same technique tools like
svwar use.

Tier: baseline - no --confirm required, still scope-gated and audit-
logged like every other scenario. This is deliberately not active-tier:
it's one low-rate REGISTER per candidate, not volume capable of
degrading the target - the safety-relevant question here is what a
target's response pattern reveals, not how much traffic it can take.

The result is read directly off SIPp's own SuccessfulCall/FailedCall
counters (see user_enum.xml's docstring for why: SuccessfulCall means
"got exactly the 401 challenge we're matching for", not "found a
valid account" in some deeper sense) - if that count is short of the
number of candidates tried, the target differentiates responses
somehow (enumerable); if every candidate succeeded, it answered
uniformly (the secure case), or every single candidate coincidentally
exists - a limitation worth being honest about, the same way
camara-audit's device_location_accuracy_floor check is honest about
what it can't confirm without a real authenticated request.
"""

from __future__ import annotations

import csv
import io
from pathlib import Path

from ..core.engagement import EngagementRefused
from ..core.sipp_runner import run_sipp
from .base import SIPP_XML_DIR, BaseScenario, ScenarioResult


def _write_extension_wordlist(path: Path, ext_start: int, ext_count: int) -> None:
    # SIPp's -inf data files require an order-mode directive as their
    # first line - discovered building digest_bruteforce, see that
    # scenario's docstring for the fuller account of this class of
    # SIPp-only-not-obvious behavior.
    lines = ["SEQUENTIAL"] + [str(ext_start + i) for i in range(ext_count)]
    path.write_text("\n".join(lines) + "\n")


def _parse_call_counts(stats_csv: Path) -> tuple[int, int] | None:
    if not stats_csv.exists():
        return None
    with open(stats_csv) as f:
        reader = csv.DictReader(io.StringIO(f.read()), delimiter=";")
        rows = list(reader)
    if not rows:
        return None
    last = rows[-1]
    successful = int(last.get("SuccessfulCall(C)") or last.get("SuccessfulCall") or 0)
    failed = int(last.get("FailedCall(C)") or last.get("FailedCall") or 0)
    return successful, failed


class UserEnum(BaseScenario):
    name = "user_enum"
    tier = "baseline"
    description = (
        "Extension/account enumeration (recon) - one unauthenticated REGISTER per "
        "candidate extension in a range. Checks whether the target's response "
        "differs for real vs non-existent accounts, the recon step that precedes "
        "digest_bruteforce in a real attack chain. --ext-start/--ext-count."
    )
    xml_file = "user_enum.xml"

    def run(
        self,
        target: str,
        port: int = 5060,
        rate: int = 10,
        transport: str = "udp",
        confirm: str | None = None,
        results_root: Path | None = None,
        ext_start: int = 1000,
        ext_count: int = 10,
        **kwargs,
    ) -> ScenarioResult:
        try:
            self.engagement.gate(
                action=f"scenario:{self.name}",
                target=target,
                tier=self.tier,
                confirm_engagement_id=confirm,
                # One request per candidate extension - rate*duration is the
                # real request count the budget ceiling has to bound, not
                # sipp's own pacing rate, so duration=1 makes rate=ext_count.
                rate=ext_count,
                duration=1,
            )
        except EngagementRefused as e:
            return ScenarioResult(
                scenario=self.name, target=target, allowed=False, refusal_reason=str(e)
            )

        results_dir = (results_root or Path("results")) / self.name / target.replace(":", "_")
        results_dir.mkdir(parents=True, exist_ok=True)
        wordlist_path = results_dir / "candidates.csv"
        _write_extension_wordlist(wordlist_path, ext_start, ext_count)

        sipp_result = run_sipp(
            target=target, port=port, scenario_file=SIPP_XML_DIR / self.xml_file,
            rate=rate, total_calls=ext_count, transport=transport, results_dir=results_dir,
            extra_args=["-inf", str(wordlist_path)],
        )

        counts = _parse_call_counts(sipp_result.stats_csv)
        successful, failed = counts if counts else (0, 0)

        return ScenarioResult(
            scenario=self.name, target=target, allowed=True,
            sipp_result=sipp_result,
            summary={
                "extensions_tested": ext_count,
                "ext_range": f"{ext_start}-{ext_start + ext_count - 1}",
                "uniform_response_count": successful,
                "differentiated_response_count": failed,
                "interpretation": (
                    "differentiated_response_count > 0 means the target answers at "
                    "least some candidates differently from others - enumerable. "
                    "0 means every candidate got the same response - either "
                    "uniform/secure, or (less likely) every candidate in this range "
                    "genuinely exists; widen --ext-count if that's a real concern."
                ),
            },
        )
