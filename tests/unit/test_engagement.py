import pytest

from sipsiege.core.audit_log import verify_log_integrity
from sipsiege.core.engagement import Engagement, EngagementRefused


def test_allows_in_scope_baseline_target(tmp_path, write_auth):
    auth_path = write_auth(tmp_path)
    eng = Engagement(auth_path)
    eng.gate(action="scenario:baseline_probe", target="10.10.10.50", tier="baseline")
    valid, _, count = verify_log_integrity(eng.audit_log.path)
    assert valid and count == 1


def test_refuses_excluded_target(tmp_path, write_auth):
    auth_path = write_auth(tmp_path)
    eng = Engagement(auth_path)
    with pytest.raises(EngagementRefused, match="exclusion"):
        eng.gate(action="scenario:baseline_probe", target="192.0.2.57", tier="baseline")


def test_refuses_out_of_scope_target(tmp_path, write_auth):
    auth_path = write_auth(tmp_path)
    eng = Engagement(auth_path)
    with pytest.raises(EngagementRefused, match="not listed in scope"):
        eng.gate(action="scenario:baseline_probe", target="8.8.8.8", tier="baseline")


def test_active_tier_without_confirm_refused(tmp_path, write_auth):
    auth_path = write_auth(tmp_path)
    eng = Engagement(auth_path)
    with pytest.raises(EngagementRefused, match="require --confirm"):
        eng.gate(action="scenario:register_flood", target="10.10.10.50", tier="active")


def test_active_tier_with_wrong_confirm_refused(tmp_path, write_auth):
    auth_path = write_auth(tmp_path)
    eng = Engagement(auth_path)
    with pytest.raises(EngagementRefused, match="require --confirm"):
        eng.gate(
            action="scenario:register_flood", target="10.10.10.50", tier="active",
            confirm_engagement_id="wrong-id",
        )


def test_active_tier_with_correct_confirm_allowed(tmp_path, write_auth):
    auth_path = write_auth(tmp_path)
    eng = Engagement(auth_path)
    eng.gate(
        action="scenario:register_flood", target="10.10.10.50", tier="active",
        confirm_engagement_id="test-eng-1", rate=10, duration=5,
    )  # should not raise


def test_baseline_tier_ignores_confirm_requirement(tmp_path, write_auth):
    """baseline-tier scenarios never need --confirm, even without it."""
    auth_path = write_auth(tmp_path)
    eng = Engagement(auth_path)
    eng.gate(action="scenario:baseline_probe", target="10.10.10.50", tier="baseline")


def test_rate_budget_exceeded_refused(tmp_path, write_auth):
    auth_path = write_auth(tmp_path, max_total_requests=100)
    eng = Engagement(auth_path)
    with pytest.raises(EngagementRefused, match="exceeds this engagement's max_total_requests"):
        eng.gate(
            action="scenario:register_flood", target="10.10.10.50", tier="active",
            confirm_engagement_id="test-eng-1", rate=1000, duration=100,
        )


def test_refusals_are_still_audit_logged(tmp_path, write_auth):
    auth_path = write_auth(tmp_path)
    eng = Engagement(auth_path)
    try:
        eng.gate(action="scenario:baseline_probe", target="8.8.8.8", tier="baseline")
    except EngagementRefused:
        pass
    valid, _, count = verify_log_integrity(eng.audit_log.path)
    assert valid and count == 1  # the refusal itself was logged
