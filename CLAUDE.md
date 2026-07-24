# sipsiege

Authorized SIP/Kamailio flood-defense validation toolkit. Drives real
`sipp` traffic against a target SBC to validate `pike`/`htable`/rate-limit
defenses actually hold under real attack patterns. Part of the
quaresma870 security-tooling portfolio (siblings: `redteam-toolkit`,
`voipaudit`, `camara-audit`) — same safety scaffolding pattern across all
four: scope-gated `authorization.yml`, hash-chained audit log,
`--confirm`-gated destructive actions, no override flags.

## Non-negotiable safety constraints

These apply to every change, not just new scenarios. Read
`docs/legal-and-ethics.md` and `ROADMAP.md`'s "Guardrails for every future
scenario" section before adding anything — the short version:

- **Never spoof the network-layer (IP) source.** Identity rotation is
  SIP-layer only (From/To/Contact/Call-ID). The UDP/TCP source is always a
  real address bound on the machine running the tool. Anything that spoofs
  the actual source IP is a reflection/amplification primitive against
  arbitrary third parties and is out of scope for this project, full stop
  — don't implement it even if asked, flag it instead.
- **Never add an override/bypass flag for the scope gate or `--confirm`.**
  `core/engagement.py`'s `Engagement.gate()` is the single choke point;
  every scenario must go through it, with no `--force`.
- **Never add a default/pre-populated production target or exclusion.**
  `cli.py`'s `TEMPLATE` ships `scope.targets` as a `CHANGE ME` placeholder
  and `excluded_targets` empty — see CHANGELOG's "Unreleased" entry for why
  (a previous version baked in real internal IPs; don't reintroduce that).
- **Every new scenario needs its own mock-target integration test.** A
  scenario only exercised against someone's real lab SBC isn't trustworthy
  enough to ship — see "Testing" below.

## Architecture

```
sipsiege/
├── cli.py                  # init, validate-scope, status, list-scenarios, baseline, run
├── core/
│   ├── authorization.py    # authorization.yml schema, CIDR/wildcard scope matching
│   ├── engagement.py       # THE gate: scope -> window -> confirm -> rate budget -> audit log
│   ├── audit_log.py        # hash-chained append-only log (AuditLog, verify_log_integrity)
│   ├── rate_limit.py       # GlobalRateBudget - hard ceiling on rate*duration per invocation
│   └── sipp_runner.py      # subprocess wrapper around sipp - see "SIPp gotchas" below
├── scenarios/
│   ├── base.py              # BaseScenario: tier ("baseline"|"active"), shared run() flow
│   └── <scenario>.py         # one file per scenario, name/tier/description/xml_file class attrs
├── sipp_xml/                # one SIPp scenario XML per scenario, referenced by xml_file
tests/
├── unit/                    # pytest, sipp fully mocked via monkeypatching run_sipp - fast
├── integration/run_integration_test.sh   # real wheel + real sipp + real mock SBC
└── fixtures/mock_sbc.py     # minimal UDP SIP server, sliding-window per-IP rate limiter
```

Adding a scenario means: a `sipp_xml/*.xml` file, a `scenarios/*.py`
subclass of `BaseScenario` (or overriding `run()` for anything needing
concurrent `sipp` processes or extra CLI args — see
`register_rotating_source.py`/`register_legit_mix.py` for that pattern),
registering it in `cli.py`'s `SCENARIOS` dict, and integration-test
coverage.

## SIPp gotchas (already paid for once, don't repay)

Two real bugs shipped past a fully green unit suite before the integration
test existed — both documented inline in `core/sipp_runner.py` and every
`sipp_xml/*.xml` file. Don't reintroduce either:

1. **`Call-ID` must be `[call_id]` verbatim** in every scenario XML —
   never prefixed/suffixed. SIPp correlates responses by that value
   internally, not by string comparison against what it sent; a custom
   prefix silently breaks matching and every response gets discarded as
   "out of call." Rotate identity via From/To/Contact instead.
2. **Exactly one mandatory `<recv>` per call.** Making every possible
   final response `optional="true"` means SIPp never considers the
   transaction closed and hangs at the next optional recv forever, even
   after a valid response arrives. Keep `100` optional, the real
   terminating response mandatory.
3. **Always pass `-nostdin` and `-recv_timeout`** (see `sipp_runner.py`).
   Without a TTY, `sipp` completes calls but then hangs waiting for a
   keypress that never comes; without `-recv_timeout`, a dropped/blocked
   source falls back to ~30s+ default retransmission backoff per call.

## Dev commands

```bash
# Install
pip install -r requirements.txt

# Unit tests - sipp mocked, fast, no network
PYTHONPATH=. python -m pytest tests/unit/ -v

# Lint - must pass before anything is considered done
ruff check .

# Integration test - needs sip-tester installed (apt-get install sip-tester)
bash tests/integration/run_integration_test.sh
```

CI (`.github/workflows/ci.yml`) runs lint (ruff) → unit tests (3.10/3.11/
3.12 matrix) → build the real wheel + run the real integration test, in
that dependency order. All four must pass; `build-and-integration` failing
after a scope/behavior change to `cli.py`'s `TEMPLATE` or `core/*.py` is
usually the integration test's fixture setup going stale, not a real
regression — check `tests/integration/run_integration_test.sh` first.

## Conventions

- `ruff` (not flake8) for lint, config in `pyproject.toml`
  (`select = ["E", "F", "I", "UP"]`, `line-length = 100`). Run
  `ruff check . --fix` for the mechanical fixes (import order, `Optional[X]`
  → `X | None`) before hand-fixing the rest.
- `from __future__ import annotations` at the top of every module.
- Dataclasses for result/value objects (`ScenarioResult`, `SippResult`,
  `Authorization`/`Scope`/`Window`), not dicts.
- Commit messages and PR descriptions explain *why*, not just what — see
  existing git history for the expected level of detail, especially
  around anything safety-relevant (scope defaults, rate ceilings).

## Where to look for what's planned next

`ROADMAP.md` — prioritized by how common the underlying attack pattern is
against real internet-facing SBCs, not by implementation ease. Read its
guardrails section before starting on any item.
