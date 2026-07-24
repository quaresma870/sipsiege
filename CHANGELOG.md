# Changelog

## Unreleased

Repo consistency pass to match the rest of the portfolio
([redteam-toolkit](https://github.com/quaresma870/redteam-toolkit),
[voipaudit](https://github.com/quaresma870/voipaudit),
[camara-audit](https://github.com/quaresma870/camara-audit)):

- Added `LICENSE` (MIT, with the same authorization disclaimer used
  elsewhere in the portfolio) and a `.gitignore` covering
  `authorization.yml`, `*.audit.jsonl`, and `results/` so a real
  engagement's scope file and audit trail can't be committed by
  accident.
- Switched CI lint from `flake8` to `ruff`, matching the rest of the
  portfolio's tooling; added the corresponding `[tool.ruff]` config to
  `pyproject.toml` and fixed the codebase to pass it.
- `init`'s `authorization.yml` template no longer ships pre-populated
  with specific internal IPs under `scope.excluded_targets` — it now
  ships empty, like camara-audit's template, with a comment telling you
  to add your own known production infrastructure before your first
  real run. Avoids baking real internal topology into a public repo's
  git history.
- Fixed `tests/integration/run_integration_test.sh`, which the
  `excluded_targets`-ships-empty change above broke: step 8 expected
  `172.21.0.57` to already be excluded and asserted the refusal
  mentioned an exclusion, but with an empty default it was refused for
  being out of `scope.targets` instead. The test now populates
  `excluded_targets` itself before asserting exclusion refusal, the
  same way a real user would.

## 0.1.0

Initial release. Scope-gated, audit-logged SIP flood-defense validation
toolkit for Kamailio/SBC, built on the safety scaffolding pattern from
[quaresma870/redteam-toolkit](https://github.com/quaresma870/redteam-toolkit).

### Bugs found and fixed while building the integration test

Both of these shipped past a fully green 41-test unit suite, because
those tests mock `run_sipp()` out entirely and never touch a real
socket. Neither was caught until the real-wheel, real-sipp, real-mock-SBC
integration test was written — which is the reason that test exists at
all, not just the unit suite.

- **Every scenario's Call-ID silently broke response matching.** Each
  SIPp XML scenario prefixed the `[call_id]` keyword (e.g.
  `Call-ID: floodtest-[call_id]`) to make it visually distinct per
  scenario. SIPp doesn't do a literal string-compare against the
  Call-ID it receives back — prefixing it broke SIPp's internal
  transaction correlation, so every response, even a perfectly
  well-formed `200 OK`, was silently discarded as "out of call."
  `baseline_probe` always reported `reachable: false` as a result,
  regardless of the target's real state. Fixed by using `[call_id]`
  verbatim in all five scenario XMLs; identity rotation still happens
  via the From/To/Contact user-part, which was never the problem.

- **A single `<recv>` sequence needs exactly one mandatory entry.**
  Every scenario listed all of `100/200/403/430/500` as
  `optional="true"`, on the assumption that "optional" meant "match
  any of these, in any combination." SIPp's own docs are explicit that
  a recv sequence needs one mandatory message; with everything
  optional, SIPp had nothing telling it the transaction was ever
  actually closed once a response matched, so it parked indefinitely
  at the next optional `<recv>` waiting for a message that would never
  arrive. Fixed by keeping `100` optional (a provisional response that
  may or may not show up) and making `200` the single mandatory recv —
  a non-200 final response and a silent drop now both surface as
  the same "not successful" signal, which is the only distinction
  this toolkit's before/after comparisons actually need.

- **SIPp hangs forever without a TTY, even after the call succeeds.**
  Run via `subprocess.run()` (no TTY attached), SIPp completed the
  call correctly but then sat on its interactive results screen
  waiting for a `q` keypress that would never come, until Python's own
  subprocess timeout killed it ~60 seconds later. `-bg` looked like an
  alternative but detaches into an untracked background process and
  returns almost immediately - before results are written - the wrong
  fit for something we need to wait on synchronously. Fixed with
  `-nostdin` (never wait on a keypress) plus `-recv_timeout 2000` (a
  deterministic 2-second per-call timeout instead of SIPp's default
  retransmission backoff, which can take 30+ seconds per call to give
  up on a genuinely blocked source).
