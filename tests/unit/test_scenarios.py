
import pytest

from sipsiege.core.engagement import Engagement
from sipsiege.core.sipp_runner import SippResult
from sipsiege.scenarios.baseline_probe import BaselineProbe
from sipsiege.scenarios.register_flood import RegisterFlood
from sipsiege.scenarios.register_legit_mix import RegisterLegitMix
from sipsiege.scenarios.register_rotating_source import RegisterRotatingSource


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
            stats_csv.write_text(
                "StartTime;LastResetTime;CurrentTime;ElapsedTime;CallRate(P);"
                "IncomingCall;OutgoingCall;TotalCallCreated;CurrentCall;"
                "SuccessfulCall;SuccessfulCall(P);FailedCall;FailedCall(P)\n"
                f"t0;t0;t1;1;1.0;0;0;10;0;10;{successful};0;{failed}\n"
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
