# SIPSiege

A small, purpose-built toolkit for validating Kamailio/SBC flood defenses
(`pike`, `htable`, rate limiting) against multiple real attack patterns.
Mandatory scope enforcement via a signed `authorization.yml`, tamper-evident
audit logging, and an explicit confirmation gate before anything disruptive
runs. No scope file, no scan — no `--force` to get around it.

> ⚠️ **Read [`docs/legal-and-ethics.md`](docs/legal-and-ethics.md) before
> your first real run.** This generates real DoS-style traffic. Only ever
> point it at a lab/test SBC, or production with explicit written
> authorization and a maintenance window.

## Why this exists

Prevent and test targeted real attacks.

## Installation

```bash
pip install -r requirements.txt

# SIPp - the actual traffic generator this toolkit drives
apt-get install sip-tester
# or build from source: https://github.com/SIPp/sipp
```

## Quickstart

```bash
# 1. Create your authorization file - production SIP infra is
#    pre-excluded by default, see docs/legal-and-ethics.md
PYTHONPATH=. python -m sipsiege.cli init

# 2. Edit authorization.yml by hand: engagement_id, authorized_by,
#    scope.targets (your TEST SBC), window.start/end.

# 3. Validate it
PYTHONPATH=. python -m sipsiege.cli validate-scope

# 4. Check status (window remaining, audit log integrity)
PYTHONPATH=. python -m sipsiege.cli status

# 5. See what's available
PYTHONPATH=. python -m sipsiege.cli list-scenarios

# 6. Baseline probe - no --confirm needed, just checks reachability
PYTHONPATH=. python -m sipsiege.cli baseline 10.10.10.50

# 7. Run an active-tier scenario - requires --confirm every time
PYTHONPATH=. python -m sipsiege.cli run register_flood 10.10.10.50 \
  --rate 50 --duration 60 --confirm kamailio-pike-validation-2026-07-24

# 8. Probe again - compare against step 6 to see if pike/htable engaged
PYTHONPATH=. python -m sipsiege.cli baseline 10.10.10.50
```

## Scenarios

| Scenario | Tier | Purpose |
|---|---|---|
| `baseline_probe` | baseline | Single REGISTER — reachability + before/after block check. No `--confirm`. |
| `register_flood` | active | Single real source, rotating spoofed identity, high rate. |
| `register_burst` | active | Short burst sized just under your `pike` threshold — false-positive check for legitimate bursty traffic. |
| `register_rotating_source` | active | Concurrent flood from multiple *real* local source IPs — tests whether a per-IP threshold like `pike`'s is enough, or whether you need an aggregate limit too. Requires `--local-ips`. |
| `register_legit_mix` | active | Flood + a low-rate legitimate stream running concurrently — checks whether real endpoints get collaterally blocked. Requires `--attacker-ip` and `--legit-ip`. |

Run `list-scenarios` for the same info from the CLI. See
[ROADMAP.md](ROADMAP.md) for what's planned next — INVITE floods, digest
auth brute-force, and other attack patterns beyond REGISTER.

### register_rotating_source and register_legit_mix need extra local IPs

Both scenarios need more than one IP address actually bound to interfaces
on the machine you run this from — this toolkit doesn't configure your
network for you (too environment-specific, too risky to automate blindly).
Example, on Linux:

```bash
sudo ip addr add 10.0.0.11/32 dev eth0
sudo ip addr add 10.0.0.12/32 dev eth0
```

Then:

```bash
PYTHONPATH=. python -m sipsiege.cli run register_rotating_source 10.10.10.50 \
  --local-ips 10.0.0.11,10.0.0.12 --rate 40 --duration 30 --confirm <engagement_id>

PYTHONPATH=. python -m sipsiege.cli run register_legit_mix 10.10.10.50 \
  --attacker-ip 10.0.0.11 --legit-ip 10.0.0.12 \
  --rate 50 --duration 30 --legit-rate 1 --confirm <engagement_id>
```

## Project structure

```
sipsiege/
├── sipsiege/
│   ├── cli.py                        # init, validate-scope, status, list-scenarios, baseline, run
│   ├── core/
│   │   ├── authorization.py          # authorization.yml schema + CIDR/wildcard scope matching
│   │   ├── audit_log.py              # hash-chained, append-only audit log
│   │   ├── engagement.py             # scope gate + active-tier confirmation gate
│   │   ├── rate_limit.py             # GlobalRateBudget - hard per-invocation request ceiling
│   │   └── sipp_runner.py            # subprocess wrapper around SIPp
│   ├── scenarios/
│   │   ├── base.py                   # BaseScenario - shared gate/run/summarize flow
│   │   ├── baseline_probe.py
│   │   ├── register_flood.py
│   │   ├── register_burst.py
│   │   ├── register_rotating_source.py
│   │   └── register_legit_mix.py
│   ├── sipp_xml/                     # SIPp scenario definitions, one per scenario
│   └── templates/
├── tests/
│   ├── unit/                         # pytest, sipp fully mocked - fast, no network
│   ├── integration/
│   │   └── run_integration_test.sh   # builds the real wheel, real sipp, real mock SBC
│   └── fixtures/
│       └── mock_sbc.py               # minimal UDP SIP server with a naive rate limiter,
│                                      # used only by this project's own tests
├── .github/workflows/ci.yml          # lint -> unit tests (3.10/3.11/3.12) -> build+integration
├── docs/
│   └── legal-and-ethics.md
├── pyproject.toml
├── requirements.txt
└── README.md
```

## Testing

```bash
# Unit tests - sipp fully mocked out, fast, no network, no real SIP traffic
pip install -r requirements.txt pytest
PYTHONPATH=. python -m pytest tests/unit/ -v

# Integration test - builds the real wheel, installs it in a clean venv,
# and drives the actual installed `sipsiege` command against a live mock
# SBC using real sipp subprocess calls. Needs sipp installed.
apt-get install sip-tester
bash tests/integration/run_integration_test.sh
```

The split exists on purpose: unit tests catch logic regressions in the
scope gate, audit log, and rate budget cheaply and instantly. But two
real bugs — SIPp silently discarding every response because a scenario
prefixed the `[call_id]` keyword, and SIPp hanging forever waiting on a
keypress that never comes when run without a TTY — only show up when
something actually talks to a real socket. Both are now covered by the
integration test and documented inline in `core/sipp_runner.py` and the
`sipp_xml/*.xml` files so they don't quietly regress.


## Results & audit trail

Each scenario run writes SIPp's stats/message/error logs under
`results/<scenario>/<target>/`, and every invocation (allowed or refused)
is appended to `<engagement_id>.audit.jsonl` next to your
`authorization.yml`. `sipsiege status` verifies that log's hash chain
automatically.

## What this deliberately does not do

- No override flag for scope refusals. Fix `authorization.yml`, don't
  bypass it.
- No persisted "already confirmed" state for active-tier scenarios —
  `--confirm` is required fresh, every single run.
- No automatic network interface configuration for the multi-source
  scenarios — you set those IPs up yourself, deliberately.
- No production defaults — the `init` template ships `excluded_targets`
  empty and `scope.targets` requires a `CHANGE ME` placeholder to be
  edited by hand; you opt every target in yourself, never the other way
  around.

---

## License

MIT — see [LICENSE](LICENSE).
