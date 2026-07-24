# Legal & ethics

This toolkit generates real SIP traffic capable of degrading a target's
ability to process legitimate registrations and calls. That is the entire
point of it — validating that your SBC/Kamailio defenses actually hold
under the same conditions as a real attack. It carries the same real-world
risk as the attack it simulates.

## Only ever point this at infrastructure you own or are explicitly
## authorized to test

- A lab/test Kamailio instance you control.
- Production infrastructure **only** with explicit, written, informed
  sign-off from whoever owns it — and even then, prefer a maintenance
  window and have a rollback/mitigation plan ready before you start.
- Never a third party's infrastructure, never "just to see what happens,"
  never because a target "looked interesting."

`authorization.yml`'s `scope.targets` is the only thing standing between
"validation test" and "the incident you're trying to prevent." Treat
editing it with the same seriousness as editing a production firewall rule.

## Populate `excluded_targets` before your first real run

The template this toolkit generates ships with `scope.excluded_targets`
empty — fill it in with your known production SIP infrastructure (SBC
IPs, VIPs, reporting proxies) before running anything. This is your
safety net against a typo or copy-paste mistake in `scope.targets`: a
flood scenario can't run against something listed here, because
exclusions are checked first and always win over inclusions. Don't
remove an entry without a specific, reviewed reason.

## Why every active-tier run requires `--confirm`

`--confirm <engagement_id>` is required on every single invocation of a
flood/burst scenario — not just once at setup. This is intentional friction:
it forces a deliberate, attended decision each time real traffic is about to
be sent, and it means a scheduled job, a copy-pasted command from a
runbook, or a stale terminal session can't silently re-run a disruptive
test without someone consciously typing the engagement ID again.

## The audit log

Every scenario invocation — allowed or refused — is written to
`<engagement_id>.audit.jsonl`, hash-chained so tampering with historical
entries is detectable (`sipsiege status` checks this automatically).
This exists so that if a test does cause unexpected impact, there's an
honest, checkable record of exactly what ran, when, and against what —
useful for your own postmortem, and for demonstrating due diligence if
anyone asks later.

Known limitation: a pure hash chain detects modification, insertion, or
reordering of entries, but cannot detect truncation of the most recent
entries (there's nothing left after a cut to reference what's missing).
If that matters for your use, note the entry count somewhere out-of-band
(a ticket comment, a Slack message) after key test runs.

## Reporting findings internally

If a scenario reveals your production SBCs would have the same problem as
the test instance (e.g. `pike` isn't deployed there yet, or the threshold
is miscalibrated), treat that the way you'd treat any other vulnerability
finding — document it, prioritize the fix, and avoid leaving the gap
described in detail in a widely-shared document until it's actually closed.
