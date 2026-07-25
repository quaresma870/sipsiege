# Changelog

## 0.4.0

- Added `digest_bruteforce` (see [ROADMAP.md](ROADMAP.md) item 1): credential
  stuffing against SIP digest auth — the single most common real-world VoIP
  attack, and a different Kamailio defense than `pike`/`htable` (auth-failure
  throttling, not raw request-rate limiting). Ships with a small default
  extension/password wordlist (`templates/digest_wordlist_default.csv`,
  override with `--wordlist`).
- **Real SIPp constraint discovered while building this** (documented inline
  in `digest_bruteforce.py` and `digest_bruteforce.xml`, alongside the two
  other real-`sipp`-only discoveries already in this file): SIPp's
  `[authentication]` keyword takes its credentials from the `-au`/`-ap`/`-s`
  command-line flags for the whole process, not from per-call substitution.
  `[authentication username=[field0] password=[field1]]` looks like
  plausible syntax and SIPp doesn't reject it, but it silently corrupts the
  Authorization header instead of erroring — caught by inspecting the raw
  bytes sent on the wire against a real mock target, not assumed. Fixed by
  driving one real `sipp` subprocess per credential pair (`-s`/`-au`/`-ap`
  set per invocation) instead of one invocation with `-inf` CSV injection —
  which also matches how this technique is actually done in practice:
  deliberate and low-and-slow, not a flood.
- `tests/fixtures/mock_sbc.py` now does real RFC 2617 MD5 digest
  verification for REGISTERs with a purely-numeric From-header username
  (every existing scenario's identity is alphabetic — `floodtest0`, `probe`,
  etc. — and is completely unaffected): 401 challenge with a fresh nonce,
  then real HA1/HA2/response verification against a small set of known
  test credentials — 200 on a match, 403 otherwise. Also added
  `--extension-oracle`, an opt-in mode where an unauthenticated REGISTER
  for an unprovisioned numeric extension gets 404 instead of 401 — a
  deliberately enumerable configuration reserved for the next roadmap item,
  `user_enum`.
- Integration test step verifies the real crypto both ways: against the
  bundled wordlist's exact known-good/known-bad rows, asserts precisely 2
  successful logins and 3 failed attempts — a stubbed or fake success count
  would not reproduce that exact split.

## 0.3.0

- Added `invite_no_ack` (see [ROADMAP.md](ROADMAP.md) item 1): identical
  INVITE traffic to `invite_flood` (single real source, high rate, rotating
  spoofed identity and destination extension), but every answered call is
  deliberately left half-open — no ACK, no BYE, ever. A target that
  answers keeps that dialog (and, realistically, its own 200
  retransmission timer) open waiting for an ACK that never arrives, a
  meaningfully different resource cost than a clean setup-and-teardown
  cycle: a comparatively small request rate can still exhaust dialog
  capacity if each call is left open long enough. Tests whether a
  target's dialog/session-table limits are configured at all, not just
  its request-rate limiting.
- No changes were needed to `core/sipp_runner.py` or
  `tests/fixtures/mock_sbc.py` for this: the half-open behavior is
  entirely a client-side omission (no `<send>` blocks after the
  mandatory `200` recv in `invite_no_ack.xml`), and the existing
  unconditional `-recv_timeout 2000` already means SIPp doesn't hang
  waiting on anything it isn't told to wait for.
- Integration test step verifies the distinction end-to-end: after a
  real `invite_no_ack` run, the mock SBC's log shows the expected count
  of newly-allowed INVITEs but zero new BYEs — proving the scenario
  never tears a call down, not just that it "runs without erroring."

## 0.2.0

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
- Removed the last references to the specific real incident this
  toolkit was originally built after, from `register_flood.xml` and
  `register_flood.py`'s docstrings, and moved the test-fixture
  "excluded/production-style" address from a private-range IP
  (`172.21.0.57`) to an RFC 5737 documentation address (`192.0.2.57`)
  across all of `tests/unit/` and the integration test — a private-range
  address used consistently as a fixture could plausibly be read as a
  real internal one; a documentation-range address can't be.
- Added `invite_flood` (see [ROADMAP.md](ROADMAP.md) item 1): a
  call-setup flood, distinct from REGISTER-volume flooding because a
  completed or even just-attempted INVITE transaction makes the target
  allocate transaction/dialog state a REGISTER never does. Each call
  completes cleanly (INVITE → 200 → ACK → immediate BYE) so the only
  variable under test is call-setup rate — a scenario that deliberately
  leaves calls half-open instead (dialog exhaustion) is intentionally a
  separate future item, not this one. `tests/fixtures/mock_sbc.py` now
  answers INVITE (with a To-tag and minimal SDP, sharing the same
  per-IP rate limiter as REGISTER) and BYE (always accepted,
  unconditionally), so the integration test exercises a real, complete
  INVITE/ACK/BYE cycle end-to-end rather than mocking it.

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
