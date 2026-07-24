from datetime import datetime, timedelta, timezone

import pytest

from sipsiege.core.authorization import (
    AuthorizationError,
    Scope,
    Window,
    load_authorization,
)

# write_auth fixture (callable factory) comes from tests/unit/conftest.py


# --- Scope matching ---

def test_exact_ip_match():
    scope = Scope(targets=["10.10.10.50"], excluded_targets=[])
    assert scope.is_authorized("10.10.10.50")
    assert not scope.is_authorized("10.10.10.51")


def test_cidr_match():
    scope = Scope(targets=["192.168.1.0/24"], excluded_targets=[])
    assert scope.is_authorized("192.168.1.77")
    assert not scope.is_authorized("192.168.2.77")


def test_wildcard_hostname_match():
    scope = Scope(targets=["*.lab.internal"], excluded_targets=[])
    assert scope.is_authorized("sbc1.lab.internal")
    assert scope.is_authorized("lab.internal")
    assert not scope.is_authorized("sbc1.prod.internal")


def test_exclusion_always_wins_even_if_also_in_scope():
    scope = Scope(targets=["10.0.0.0/8"], excluded_targets=["10.10.10.50"])
    assert not scope.is_authorized("10.10.10.50")
    assert scope.is_authorized("10.10.10.51")


def test_target_with_port_matches_on_host_only():
    scope = Scope(targets=["10.10.10.50"], excluded_targets=[])
    assert scope.is_authorized("10.10.10.50:5060")


# --- Window ---

def test_window_active_now():
    now = datetime.now(timezone.utc)
    w = Window(start=now - timedelta(hours=1), end=now + timedelta(hours=1))
    assert w.is_active(now)


def test_window_expired():
    now = datetime.now(timezone.utc)
    w = Window(start=now - timedelta(hours=2), end=now - timedelta(hours=1))
    assert not w.is_active(now)
    assert w.remaining(now) == "expired"


# --- Full authorization.yml loading ---

def test_load_valid_authorization(tmp_path, write_auth):
    path = write_auth(tmp_path)
    auth = load_authorization(path)
    assert auth.engagement_id == "test-eng-1"
    assert auth.is_authorized("10.10.10.50")
    assert not auth.is_authorized("172.21.0.57")  # excluded
    assert not auth.is_authorized("8.8.8.8")       # not in scope


def test_refusal_reason_for_excluded_target(tmp_path, write_auth):
    path = write_auth(tmp_path)
    auth = load_authorization(path)
    reason = auth.refusal_reason("172.21.0.57")
    assert "exclusion" in reason


def test_refusal_reason_for_out_of_scope_target(tmp_path, write_auth):
    path = write_auth(tmp_path)
    auth = load_authorization(path)
    reason = auth.refusal_reason("8.8.8.8")
    assert "not listed in scope.targets" in reason


def test_refusal_reason_for_expired_window(tmp_path, write_auth):
    now = datetime.now(timezone.utc)
    path = write_auth(
        tmp_path,
        start=(now - timedelta(hours=3)).isoformat(),
        end=(now - timedelta(hours=1)).isoformat(),
    )
    auth = load_authorization(path)
    reason = auth.refusal_reason("10.10.10.50")
    assert "window" in reason


def test_missing_file_raises(tmp_path):
    with pytest.raises(AuthorizationError):
        load_authorization(tmp_path / "does-not-exist.yml")


def test_empty_targets_raises(tmp_path, write_auth):
    path = write_auth(tmp_path, targets=[])
    with pytest.raises(AuthorizationError, match="scope.targets is empty"):
        load_authorization(path)


def test_window_end_before_start_raises(tmp_path, write_auth):
    now = datetime.now(timezone.utc)
    path = write_auth(
        tmp_path,
        start=now.isoformat(),
        end=(now - timedelta(hours=1)).isoformat(),
    )
    with pytest.raises(AuthorizationError, match="window.end must be after"):
        load_authorization(path)
