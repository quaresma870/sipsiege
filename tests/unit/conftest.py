from datetime import datetime, timedelta, timezone

import pytest
import yaml


def _write_auth(tmp_path, **overrides):
    now = datetime.now(timezone.utc)
    defaults = dict(
        engagement_id="test-eng-1",
        authorized_by="Test User",
        targets=["10.10.10.50", "192.168.1.0/24", "*.lab.internal"],
        excluded=["172.21.0.57"],
        start=(now - timedelta(hours=1)).isoformat(),
        end=(now + timedelta(hours=1)).isoformat(),
        confirmation_phrase="I confirm authorization for test-eng-1",
        max_total_requests=5000,
    )
    defaults.update(overrides)

    data = {
        "engagement_id": defaults["engagement_id"],
        "authorized_by": defaults["authorized_by"],
        "scope": {
            "targets": defaults["targets"],
            "excluded_targets": defaults["excluded"],
        },
        "window": {
            "start": defaults["start"],
            "end": defaults["end"],
        },
        "confirmation_phrase": defaults["confirmation_phrase"],
        "max_total_requests": defaults["max_total_requests"],
    }
    path = tmp_path / "authorization.yml"
    path.write_text(yaml.safe_dump(data, default_flow_style=False))
    return path


@pytest.fixture
def write_auth():
    """Returns a callable: write_auth(tmp_path, **overrides) -> Path"""
    return _write_auth
