"""
cli.py

CLI structure mirrors redteam-toolkit's command set, adapted for SIP:

  init                  write an authorization.yml template
  validate-scope         parse + validate authorization.yml
  status                 window remaining + audit log integrity
  list-scenarios         show available scenarios and their tier
  baseline <target>      single-probe reachability check (no --confirm)
  run <scenario> <target> --confirm <engagement_id> [options]
                          run any active-tier scenario

No scenario ever runs without a valid authorization.yml in scope and
window. Active-tier scenarios additionally require --confirm on every
single invocation - there is no persisted override.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core.audit_log import verify_log_integrity
from .core.authorization import AuthorizationError, load_authorization
from .core.engagement import Engagement, EngagementRefused
from .scenarios.baseline_probe import BaselineProbe
from .scenarios.invite_flood import InviteFlood
from .scenarios.register_burst import RegisterBurst
from .scenarios.register_flood import RegisterFlood
from .scenarios.register_legit_mix import RegisterLegitMix
from .scenarios.register_rotating_source import RegisterRotatingSource

SCENARIOS = {
    "baseline_probe": BaselineProbe,
    "register_flood": RegisterFlood,
    "register_burst": RegisterBurst,
    "register_rotating_source": RegisterRotatingSource,
    "register_legit_mix": RegisterLegitMix,
    "invite_flood": InviteFlood,
}

TEMPLATE = """\
# sipsiege authorization file
# Nothing runs against a target unless it's listed under scope.targets,
# not caught by scope.excluded_targets, and the current time is inside
# window.start/window.end. Active-tier scenarios (floods/bursts) also
# require --confirm <engagement_id> on every single invocation.

engagement_id: "kamailio-pike-validation-{date}"
authorized_by: "CHANGE ME - your name / role"
authorized_contact_email: "CHANGE ME"

scope:
  targets:
    - "CHANGE ME - your TEST SBC IP, e.g. 10.10.10.50"
  excluded_targets: []
    # Add your known production SIP infrastructure here (SBC IPs, VIPs,
    # reporting proxies, etc.) before your first real run. This is your
    # safety net against a typo or copy-paste mistake in scope.targets
    # above - exclusions are checked first and always win over
    # inclusions. Never remove an entry without a deliberate, reviewed
    # reason.

window:
  start: "{today}T00:00:00Z"
  end: "{today}T23:59:59Z"

confirmation_phrase: "I confirm authorization for kamailio-pike-validation-{date}"

# Hard ceiling on total requests (rate * duration) any single scenario
# invocation may send. Raise deliberately if you need a larger test.
max_total_requests: 5000
"""


def cmd_init(args):
    from datetime import date
    today = date.today().isoformat()
    path = Path(args.output)
    if path.exists() and not args.force:
        print(f"ERROR: {path} already exists. Use --force to overwrite.", file=sys.stderr)
        sys.exit(1)
    path.write_text(TEMPLATE.format(date=today.replace("-", "-"), today=today))
    print(f"Wrote template to {path}.")
    print("Edit every CHANGE ME field by hand before running anything - "
          "especially scope.targets and window.")


def cmd_validate_scope(args):
    try:
        auth = load_authorization(args.authorization)
    except AuthorizationError as e:
        print(f"INVALID: {e}", file=sys.stderr)
        sys.exit(1)
    print(f"OK: engagement_id={auth.engagement_id!r}")
    print(f"  authorized_by: {auth.authorized_by}")
    print(f"  targets: {auth.scope.targets}")
    print(f"  excluded_targets: {auth.scope.excluded_targets}")
    print(f"  window: {auth.window.start.isoformat()} -> {auth.window.end.isoformat()}")
    print(f"  window active now: {auth.window.is_active()}")
    print(f"  max_total_requests: {auth.max_total_requests}")


def cmd_status(args):
    try:
        eng = Engagement(args.authorization)
    except AuthorizationError as e:
        print(f"INVALID: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Engagement: {eng.auth.engagement_id}")
    print(f"Window: {eng.auth.window.remaining()}")
    valid, broken_at, count = verify_log_integrity(eng.audit_log.path)
    if valid:
        print(f"Audit log: OK ({count} entries verified)")
    else:
        print(f"Audit log: TAMPERED - chain broken at line {broken_at} "
              f"({count} entries verified before the break)")


def cmd_list_scenarios(args):
    print(f"{'name':<28} {'tier':<10} description")
    print("-" * 90)
    for name, cls in SCENARIOS.items():
        print(f"{cls.name:<28} {cls.tier:<10} {cls.description}")


def _print_result(result):
    print(f"scenario: {result.scenario}")
    print(f"target:   {result.target}")
    print(f"allowed:  {result.allowed}")
    if not result.allowed:
        print(f"refused:  {result.refusal_reason}")
        return
    print(f"summary:  {json.dumps(result.summary, indent=2, default=str)}")


def cmd_baseline(args):
    try:
        eng = Engagement(args.authorization)
    except AuthorizationError as e:
        print(f"INVALID: {e}", file=sys.stderr)
        sys.exit(1)

    scenario = BaselineProbe(eng)
    try:
        result = scenario.run(target=args.target, port=args.port, transport=args.transport)
    except EngagementRefused as e:
        print(f"REFUSED: {e}", file=sys.stderr)
        sys.exit(1)
    _print_result(result)


def cmd_run(args):
    try:
        eng = Engagement(args.authorization)
    except AuthorizationError as e:
        print(f"INVALID: {e}", file=sys.stderr)
        sys.exit(1)

    scenario_cls = SCENARIOS.get(args.scenario)
    if scenario_cls is None:
        print(f"ERROR: unknown scenario '{args.scenario}'. "
              f"See 'sipsiege list-scenarios'.", file=sys.stderr)
        sys.exit(1)

    scenario = scenario_cls(eng)

    kwargs = dict(
        target=args.target,
        port=args.port,
        rate=args.rate,
        duration=args.duration,
        transport=args.transport,
        confirm=args.confirm,
    )
    if args.local_ips:
        kwargs["local_ips"] = [ip.strip() for ip in args.local_ips.split(",")]
    if args.attacker_ip:
        kwargs["attacker_ip"] = args.attacker_ip
    if args.legit_ip:
        kwargs["legit_ip"] = args.legit_ip
    if args.legit_rate:
        kwargs["legit_rate"] = args.legit_rate

    result = scenario.run(**kwargs)
    _print_result(result)
    if not result.allowed:
        sys.exit(1)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sipsiege", description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="write an authorization.yml template")
    p_init.add_argument("-o", "--output", default="authorization.yml")
    p_init.add_argument("--force", action="store_true")
    p_init.set_defaults(func=cmd_init)

    p_val = sub.add_parser("validate-scope", help="validate authorization.yml")
    p_val.add_argument("-a", "--authorization", default="authorization.yml")
    p_val.set_defaults(func=cmd_validate_scope)

    p_status = sub.add_parser("status", help="engagement window + audit log integrity")
    p_status.add_argument("-a", "--authorization", default="authorization.yml")
    p_status.set_defaults(func=cmd_status)

    p_list = sub.add_parser("list-scenarios", help="list available scenarios")
    p_list.set_defaults(func=cmd_list_scenarios)

    p_base = sub.add_parser("baseline", help="single-probe reachability check (no --confirm needed)")
    p_base.add_argument("target")
    p_base.add_argument("-a", "--authorization", default="authorization.yml")
    p_base.add_argument("-p", "--port", type=int, default=5060)
    p_base.add_argument("--transport", choices=["udp", "tcp"], default="udp")
    p_base.set_defaults(func=cmd_baseline)

    p_run = sub.add_parser("run", help="run an active-tier scenario (requires --confirm)")
    p_run.add_argument("scenario", choices=list(SCENARIOS.keys()))
    p_run.add_argument("target")
    p_run.add_argument("-a", "--authorization", default="authorization.yml")
    p_run.add_argument("-p", "--port", type=int, default=5060)
    p_run.add_argument("-r", "--rate", type=int, default=10, help="requests/sec")
    p_run.add_argument("-d", "--duration", type=int, default=10, help="seconds")
    p_run.add_argument("--transport", choices=["udp", "tcp"], default="udp")
    p_run.add_argument("--confirm", help="must match this authorization's engagement_id")
    p_run.add_argument("--local-ips", help="comma-separated, for register_rotating_source")
    p_run.add_argument("--attacker-ip", help="for register_legit_mix")
    p_run.add_argument("--legit-ip", help="for register_legit_mix")
    p_run.add_argument("--legit-rate", type=int, default=1, help="for register_legit_mix")
    p_run.set_defaults(func=cmd_run)

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
