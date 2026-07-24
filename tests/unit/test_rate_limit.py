import pytest

from sipsiege.core.rate_limit import GlobalRateBudget, RateBudgetExceeded


def test_within_budget_returns_total():
    budget = GlobalRateBudget(max_total_requests=1000)
    total = budget.check(rate_per_sec=50, duration_sec=10)
    assert total == 500


def test_exactly_at_budget_is_allowed():
    budget = GlobalRateBudget(max_total_requests=500)
    total = budget.check(rate_per_sec=50, duration_sec=10)
    assert total == 500


def test_exceeding_budget_raises():
    budget = GlobalRateBudget(max_total_requests=100)
    with pytest.raises(RateBudgetExceeded) as exc_info:
        budget.check(rate_per_sec=50, duration_sec=10)
    assert "100" in str(exc_info.value)
    assert "500" in str(exc_info.value)
