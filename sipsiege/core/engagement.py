"""
core/engagement.py

The gate every scenario runs through, mirroring redteam-toolkit's
Engagement class: scope check -> window check -> (for active-tier
scenarios) confirmation-phrase/engagement-id check -> rate budget
check -> audit log entry -> only then does anything touch the wire.

There is deliberately no override flag. A refused check is refused;
the caller can fix authorization.yml and try again, but there is no
--force.
"""

from __future__ import annotations

from pathlib import Path

from .audit_log import AuditLog
from .authorization import Authorization, load_authorization
from .rate_limit import GlobalRateBudget, RateBudgetExceeded


class EngagementRefused(Exception):
    pass


class Engagement:
    def __init__(self, authorization_path: str | Path):
        self.auth: Authorization = load_authorization(authorization_path)
        log_path = Path(self.auth.raw_path).parent / f"{self.auth.engagement_id}.audit.jsonl"
        self.audit_log = AuditLog(log_path)
        self.rate_budget = GlobalRateBudget(self.auth.max_total_requests)

    def gate(
        self,
        action: str,
        target: str,
        tier: str,
        confirm_engagement_id: str | None = None,
        rate: int | None = None,
        duration: int | None = None,
    ) -> None:
        """
        Raises EngagementRefused with a clear reason if the action is not
        authorized. Always writes an audit log entry, whether allowed or
        refused, so refusals are visible in the trail too.
        """
        reason = self.auth.refusal_reason(target)
        if reason:
            self.audit_log.record(action, target, allowed=False, reason=reason)
            raise EngagementRefused(reason)

        if tier == "active":
            if confirm_engagement_id != self.auth.engagement_id:
                reason = (
                    "active-tier scenarios require --confirm <engagement_id> "
                    f"matching this authorization's engagement_id ('{self.auth.engagement_id}'). "
                    "This is required on every single invocation - it does not persist."
                )
                self.audit_log.record(action, target, allowed=False, reason=reason)
                raise EngagementRefused(reason)

        if rate is not None and duration is not None:
            try:
                self.rate_budget.check(rate, duration)
            except RateBudgetExceeded as e:
                self.audit_log.record(action, target, allowed=False, reason=str(e))
                raise EngagementRefused(str(e))

        self.audit_log.record(
            action, target, allowed=True,
            details={"tier": tier, "rate": rate, "duration": duration},
        )
