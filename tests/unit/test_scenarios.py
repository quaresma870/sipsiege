import json

import pytest

from sipsiege.core.audit_log import verify_log_integrity
from sipsiege.core.engagement import Engagement
from sipsiege.core.sipp_runner import SippResult
from sipsiege.scenarios.baseline_probe import BaselineProbe
from sipsiege.scenarios.digest_bruteforce import DigestBruteforce
from sipsiege.scenarios.invite_flood import InviteFlood
from sipsiege.scenarios.invite_no_ack import InviteNoAck
from sipsiege.scenarios.register_flood import RegisterFlood
from sipsiege.scenarios.register_legit_mix import RegisterLegitMix
from sipsiege.scenarios.register_rotating_source import RegisterRotatingSource
from sipsiege.scenarios.user_enum import UserEnum


def make_fake_run_sipp(calls_log, write_stats=False, successful="10", failed="0"):
    """
    Returns a fake replacement for run_sipp() that records every call's
    kwargs into calls_log (a list, mutated in place) and returns a
    plausible SippResult without touching a real sipp binary.
    """
    def _fake(**kwargs):
        calls_log.append(kwargs)
        results_dir = kwargs["results_dir"]
        results_dir.mkdir(parents=True, exist_ok=True)
        if write_stats:
            stats_csv = results_dir / "stats.csv"
            # Real sipp -stf output only ever has (P)eriodic/(C)umulative
            # column variants, never a bare name - matching that here
            # (rather than an earlier version's invented bare columns)
            # so readers that prefer (C) (digest_bruteforce, user_enum)
            # and readers that prefer (P) (register_legit_mix) both see
            # the actual successful/failed values passed in.
            stats_csv.write_text(
                "StartTime;LastResetTime;CurrentTime;ElapsedTime;CallRate(P);"
                "IncomingCall;OutgoingCall;TotalCallCreated;CurrentCall;"
                "SuccessfulCall(P);SuccessfulCall(C);FailedCall(P);FailedCall(C)\n"
                f"t0;t0;t1;1;1.0;0;0;10;0;{successful};{successful};{failed};{failed}\n"
            )
        return SippResult(
            return_code=0, stdout="", stderr="",
            results_dir=results_dir, command=["sipp", "fake"],
        )
    return _fake


@pytest.fixture
def engagement(tmp_path, write_auth):
    auth_path = write_auth(tmp_path)
    return Engagement(auth_path)


# --- BaselineProbe (baseline tier - no confirm needed) ---

def test_baseline_probe_calls_sipp_once(monkeypatch, engagement, tmp_path):
    calls = []
    monkeypatch.setattr("sipsiege.scenarios.base.run_sipp", make_fake_run_sipp(calls))

    scenario = BaselineProbe(engagement)
    result = scenario.run(target="10.10.10.50", results_root=tmp_path / "results")

    assert result.allowed
    assert len(calls) == 1
    assert calls[0]["rate"] == 1
    assert calls[0]["total_calls"] == 1


def test_baseline_probe_refused_out_of_scope_never_calls_sipp(monkeypatch, engagement, tmp_path):
    calls = []
    monkeypatch.setattr("sipsiege.scenarios.base.run_sipp", make_fake_run_sipp(calls))

    scenario = BaselineProbe(engagement)
    result = scenario.run(target="8.8.8.8", results_root=tmp_path / "results")

    assert not result.allowed
    assert "not listed in scope" in result.refusal_reason
    assert len(calls) == 0  # never touched sipp at all


# --- RegisterFlood (active tier - confirm required) ---

def test_register_flood_refused_without_confirm(monkeypatch, engagement, tmp_path):
    calls = []
    monkeypatch.setattr("sipsiege.scenarios.base.run_sipp", make_fake_run_sipp(calls))

    scenario = RegisterFlood(engagement)
    result = scenario.run(target="10.10.10.50", rate=50, duration=10, results_root=tmp_path / "results")

    assert not result.allowed
    assert "confirm" in result.refusal_reason.lower()
    assert len(calls) == 0


def test_register_flood_runs_with_correct_confirm(monkeypatch, engagement, tmp_path):
    calls = []
    monkeypatch.setattr("sipsiege.scenarios.base.run_sipp", make_fake_run_sipp(calls))

    scenario = RegisterFlood(engagement)
    result = scenario.run(
        target="10.10.10.50", rate=50, duration=10,
        confirm="test-eng-1", results_root=tmp_path / "results",
    )

    assert result.allowed
    assert len(calls) == 1
    assert calls[0]["rate"] == 50
    assert calls[0]["total_calls"] == 500
    assert result.summary["total_calls_attempted"] == 500


# --- InviteFlood (active tier - confirm required) ---

def test_invite_flood_refused_without_confirm(monkeypatch, engagement, tmp_path):
    calls = []
    monkeypatch.setattr("sipsiege.scenarios.base.run_sipp", make_fake_run_sipp(calls))

    scenario = InviteFlood(engagement)
    result = scenario.run(target="10.10.10.50", rate=50, duration=10, results_root=tmp_path / "results")

    assert not result.allowed
    assert "confirm" in result.refusal_reason.lower()
    assert len(calls) == 0


def test_invite_flood_runs_with_correct_confirm(monkeypatch, engagement, tmp_path):
    calls = []
    monkeypatch.setattr("sipsiege.scenarios.base.run_sipp", make_fake_run_sipp(calls))

    scenario = InviteFlood(engagement)
    result = scenario.run(
        target="10.10.10.50", rate=50, duration=10,
        confirm="test-eng-1", results_root=tmp_path / "results",
    )

    assert result.allowed
    assert len(calls) == 1
    assert calls[0]["rate"] == 50
    assert calls[0]["total_calls"] == 500
    assert calls[0]["scenario_file"].name == "invite_flood.xml"
    assert result.summary["total_calls_attempted"] == 500


# --- InviteNoAck (active tier - confirm required) ---

def test_invite_no_ack_refused_without_confirm(monkeypatch, engagement, tmp_path):
    calls = []
    monkeypatch.setattr("sipsiege.scenarios.base.run_sipp", make_fake_run_sipp(calls))

    scenario = InviteNoAck(engagement)
    result = scenario.run(target="10.10.10.50", rate=50, duration=10, results_root=tmp_path / "results")

    assert not result.allowed
    assert "confirm" in result.refusal_reason.lower()
    assert len(calls) == 0


def test_invite_no_ack_runs_with_correct_confirm(monkeypatch, engagement, tmp_path):
    calls = []
    monkeypatch.setattr("sipsiege.scenarios.base.run_sipp", make_fake_run_sipp(calls))

    scenario = InviteNoAck(engagement)
    result = scenario.run(
        target="10.10.10.50", rate=50, duration=10,
        confirm="test-eng-1", results_root=tmp_path / "results",
    )

    assert result.allowed
    assert len(calls) == 1
    assert calls[0]["rate"] == 50
    assert calls[0]["total_calls"] == 500
    assert calls[0]["scenario_file"].name == "invite_no_ack.xml"
    assert result.summary["total_calls_attempted"] == 500


# --- DigestBruteforce (active tier - confirm required, needs a wordlist) ---

def test_digest_bruteforce_refused_without_confirm(monkeypatch, engagement, tmp_path):
    calls = []
    monkeypatch.setattr("sipsiege.scenarios.digest_bruteforce.run_sipp", make_fake_run_sipp(calls))

    scenario = DigestBruteforce(engagement)
    result = scenario.run(target="10.10.10.50", rate=3, duration=2, results_root=tmp_path / "results")

    assert not result.allowed
    assert "confirm" in result.refusal_reason.lower()
    assert len(calls) == 0


def test_digest_bruteforce_refused_with_missing_wordlist(monkeypatch, engagement, tmp_path):
    calls = []
    monkeypatch.setattr("sipsiege.scenarios.digest_bruteforce.run_sipp", make_fake_run_sipp(calls))

    scenario = DigestBruteforce(engagement)
    result = scenario.run(
        target="10.10.10.50", rate=3, duration=2, confirm="test-eng-1",
        wordlist=str(tmp_path / "does-not-exist.csv"), results_root=tmp_path / "results",
    )

    assert not result.allowed
    assert "wordlist" in result.refusal_reason
    assert len(calls) == 0


def test_digest_bruteforce_runs_with_correct_confirm(monkeypatch, engagement, tmp_path):
    # SIPp's [authentication] keyword takes its credentials from -au/-ap/-s
    # for the whole process, not per-call substitution (see
    # digest_bruteforce.py's docstring) - so this scenario drives one real
    # sipp invocation per credential pair, not one invocation with -inf.
    monkeypatch.setattr("sipsiege.scenarios.digest_bruteforce.time.sleep", lambda _s: None)
    calls = []
    monkeypatch.setattr(
        "sipsiege.scenarios.digest_bruteforce.run_sipp",
        make_fake_run_sipp(calls, write_stats=True, successful="1", failed="0"),
    )

    scenario = DigestBruteforce(engagement)
    result = scenario.run(
        target="10.10.10.50", rate=3, duration=2,
        confirm="test-eng-1", results_root=tmp_path / "results",
    )

    assert result.allowed
    # rate * duration = 6 credential pairs -> 6 separate sipp invocations,
    # each a single call (rate=1, total_calls=1) with its own -s/-au/-ap.
    assert len(calls) == 6
    assert all(c["rate"] == 1 and c["total_calls"] == 1 for c in calls)
    assert all(c["extra_args"][0] == "-s" for c in calls)
    assert result.summary["credential_pairs_attempted"] == 6
    assert result.summary["successful_logins"] == 6  # fake always reports success
    assert result.summary["failed_attempts"] == 0
    # Each credential pair is 2 real REGISTER requests - the rate budget
    # gate must have been checked against that doubled rate, not the
    # nominal --rate. If it weren't, a max_total_requests ceiling sized
    # for the nominal rate could silently pass twice the traffic it's
    # supposed to bound.
    valid, _broken_at, _count = verify_log_integrity(engagement.audit_log.path)
    assert valid
    last_entry = json.loads(engagement.audit_log.path.read_text().splitlines()[-1])
    assert last_entry["details"]["rate"] == 6  # rate*2


# --- UserEnum (baseline tier - no confirm needed) ---

def test_user_enum_needs_no_confirm(monkeypatch, engagement, tmp_path):
    calls = []
    monkeypatch.setattr(
        "sipsiege.scenarios.user_enum.run_sipp",
        make_fake_run_sipp(calls, write_stats=True, successful="3", failed="2"),
    )

    scenario = UserEnum(engagement)
    result = scenario.run(
        target="10.10.10.50", ext_start=1000, ext_count=5, results_root=tmp_path / "results",
    )

    assert result.allowed  # baseline tier - no --confirm required, unlike active scenarios
    assert len(calls) == 1
    assert calls[0]["total_calls"] == 5
    assert calls[0]["extra_args"] == ["-inf", str(tmp_path / "results" / "user_enum" / "10.10.10.50" / "candidates.csv")]
    assert result.summary["extensions_tested"] == 5
    assert result.summary["ext_range"] == "1000-1004"
    assert result.summary["uniform_response_count"] == 3
    assert result.summary["differentiated_response_count"] == 2


def test_user_enum_refused_out_of_scope_never_calls_sipp(monkeypatch, engagement, tmp_path):
    calls = []
    monkeypatch.setattr("sipsiege.scenarios.user_enum.run_sipp", make_fake_run_sipp(calls))

    scenario = UserEnum(engagement)
    result = scenario.run(target="8.8.8.8", ext_start=1000, ext_count=5, results_root=tmp_path / "results")

    assert not result.allowed
    assert "not listed in scope" in result.refusal_reason
    assert len(calls) == 0


def test_user_enum_writes_sequential_candidates_file(monkeypatch, engagement, tmp_path):
    calls = []
    monkeypatch.setattr(
        "sipsiege.scenarios.user_enum.run_sipp",
        make_fake_run_sipp(calls, write_stats=True, successful="5", failed="0"),
    )

    scenario = UserEnum(engagement)
    scenario.run(
        target="10.10.10.50", ext_start=2000, ext_count=3, results_root=tmp_path / "results",
    )

    candidates_path = tmp_path / "results" / "user_enum" / "10.10.10.50" / "candidates.csv"
    # SIPp's -inf files require an order-mode directive as their first
    # line (SEQUENTIAL/RANDOM/USER) - discovered building
    # digest_bruteforce, see that scenario's docstring.
    assert candidates_path.read_text().splitlines() == ["SEQUENTIAL", "2000", "2001", "2002"]


# --- RegisterRotatingSource (active tier, needs >=2 local_ips) ---

def test_rotating_source_refused_with_fewer_than_two_ips(monkeypatch, engagement, tmp_path):
    calls = []
    monkeypatch.setattr("sipsiege.scenarios.register_rotating_source.run_sipp", make_fake_run_sipp(calls))

    scenario = RegisterRotatingSource(engagement)
    result = scenario.run(
        target="10.10.10.50", rate=40, duration=10, confirm="test-eng-1",
        local_ips=["10.0.0.11"], results_root=tmp_path / "results",
    )

    assert not result.allowed
    assert "at least" in result.refusal_reason
    assert len(calls) == 0


def test_rotating_source_spawns_one_sipp_per_ip(monkeypatch, engagement, tmp_path):
    calls = []
    monkeypatch.setattr("sipsiege.scenarios.register_rotating_source.run_sipp", make_fake_run_sipp(calls))

    scenario = RegisterRotatingSource(engagement)
    result = scenario.run(
        target="10.10.10.50", rate=40, duration=10, confirm="test-eng-1",
        local_ips=["10.0.0.11", "10.0.0.12"], results_root=tmp_path / "results",
    )

    assert result.allowed
    assert len(calls) == 2
    used_ips = sorted(c["local_ip"] for c in calls)
    assert used_ips == ["10.0.0.11", "10.0.0.12"]


def test_rotating_source_local_ip_range_uses_real_bound_addresses(monkeypatch, engagement, tmp_path):
    # Real bind check, not mocked: the whole 127.0.0.0/8 block binds
    # successfully on Linux (loopback special-cases it), so a small
    # range within it gives real, genuinely-bound addresses without
    # needing any interface setup or a socket.bind mock.
    calls = []
    monkeypatch.setattr("sipsiege.scenarios.register_rotating_source.run_sipp", make_fake_run_sipp(calls))

    scenario = RegisterRotatingSource(engagement)
    result = scenario.run(
        target="10.10.10.50", rate=40, duration=10, confirm="test-eng-1",
        local_ip_range="127.0.0.0/30", results_root=tmp_path / "results",
    )

    assert result.allowed
    assert len(calls) == 2  # 127.0.0.0/30's two host addresses, both bound
    assert result.summary["local_ip_range"] == "127.0.0.0/30"
    assert result.summary["unbound_in_range"] == []
    assert sorted(result.summary["sources_used"]) == ["127.0.0.1", "127.0.0.2"]


def test_rotating_source_local_ip_range_refused_when_not_bound(monkeypatch, engagement, tmp_path):
    # _is_bound_locally mocked to always fail - deterministic regardless
    # of environment, unlike relying on a specific address range being
    # unbound (a real 192.0.2.0/30 probe during development turned out
    # to bind successfully in one sandboxed environment, which is
    # exactly the kind of environment-specific surprise this avoids).
    calls = []
    monkeypatch.setattr("sipsiege.scenarios.register_rotating_source.run_sipp", make_fake_run_sipp(calls))
    monkeypatch.setattr("sipsiege.scenarios.register_rotating_source._is_bound_locally", lambda ip: False)

    scenario = RegisterRotatingSource(engagement)
    result = scenario.run(
        target="10.10.10.50", rate=40, duration=10, confirm="test-eng-1",
        local_ip_range="192.0.2.0/30", results_root=tmp_path / "results",
    )

    assert not result.allowed
    assert "at least" in result.refusal_reason
    assert "192.0.2.0/30" in result.refusal_reason
    assert "0 are actually bound" in result.refusal_reason
    assert len(calls) == 0


def test_rotating_source_explicit_local_ips_take_precedence_over_range(monkeypatch, engagement, tmp_path):
    calls = []
    monkeypatch.setattr("sipsiege.scenarios.register_rotating_source.run_sipp", make_fake_run_sipp(calls))

    scenario = RegisterRotatingSource(engagement)
    result = scenario.run(
        target="10.10.10.50", rate=40, duration=10, confirm="test-eng-1",
        local_ips=["10.0.0.11", "10.0.0.12"], local_ip_range="127.0.0.0/30",
        results_root=tmp_path / "results",
    )

    assert result.allowed
    assert sorted(c["local_ip"] for c in calls) == ["10.0.0.11", "10.0.0.12"]
    assert "local_ip_range" not in result.summary


# --- RegisterLegitMix (active tier, needs attacker_ip + legit_ip) ---

def test_legit_mix_refused_without_both_ips(monkeypatch, engagement, tmp_path):
    calls = []
    monkeypatch.setattr("sipsiege.scenarios.register_legit_mix.run_sipp", make_fake_run_sipp(calls))

    scenario = RegisterLegitMix(engagement)
    result = scenario.run(
        target="10.10.10.50", rate=50, duration=10, confirm="test-eng-1",
        attacker_ip="10.0.0.11", results_root=tmp_path / "results",  # legit_ip missing
    )

    assert not result.allowed
    assert "attacker-ip" in result.refusal_reason and "legit-ip" in result.refusal_reason
    assert len(calls) == 0


def test_legit_mix_runs_baseline_then_concurrent(monkeypatch, engagement, tmp_path):
    calls = []
    monkeypatch.setattr(
        "sipsiege.scenarios.register_legit_mix.run_sipp",
        make_fake_run_sipp(calls, write_stats=True, successful="9", failed="1"),
    )

    scenario = RegisterLegitMix(engagement)
    result = scenario.run(
        target="10.10.10.50", rate=50, duration=10, confirm="test-eng-1",
        attacker_ip="10.0.0.11", legit_ip="10.0.0.12", legit_rate=1,
        results_root=tmp_path / "results",
    )

    assert result.allowed
    # 1 baseline (legit alone) + 2 concurrent (attacker + legit) = 3 sipp invocations
    assert len(calls) == 3
    assert result.summary["baseline_legit_stats"]["successful_call"] == "9"
    assert result.summary["legit_stats_during_flood"]["successful_call"] == "9"
