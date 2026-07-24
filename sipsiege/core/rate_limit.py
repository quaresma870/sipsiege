"""
core/rate_limit.py

A hard ceiling on total requests a single invocation may send,
independent of whatever rate/duration the operator asks for. This
exists so a typo (an extra zero on --duration) can't turn a planned
5,000-request validation test into an accidental multi-hour DoS
against the test SBC.

Mirrors the "global rate budget" concept from redteam-toolkit's
production-hardening sprint, scoped down to what a single-process
SIPp-driving tool actually needs.
"""

from __future__ import annotations

from dataclasses import dataclass


class RateBudgetExceeded(Exception):
    pass


@dataclass
class GlobalRateBudget:
    max_total_requests: int

    def check(self, rate_per_sec: int, duration_sec: int) -> int:
        """Returns the computed total, or raises if it exceeds the ceiling."""
        total = rate_per_sec * duration_sec
        if total > self.max_total_requests:
            raise RateBudgetExceeded(
                f"requested scenario would send {total} requests "
                f"({rate_per_sec}/sec * {duration_sec}s), which exceeds this "
                f"engagement's max_total_requests ceiling of {self.max_total_requests}.\n"
                f"Lower --rate/--duration, or raise max_total_requests in "
                f"authorization.yml if you deliberately intend a larger test."
            )
        return total
