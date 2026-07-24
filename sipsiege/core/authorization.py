"""
core/authorization.py

Scope enforcement for the SIP red-team toolkit, modeled on the
scope-gate pattern from quaresma870/redteam-toolkit: nothing runs
against a target unless it's explicitly listed in a signed
authorization.yml, inside the authorized time window, and not
excluded.

Unlike a generic web pentest tool, "targets" here are SIP hosts
(IP, IP:port, or hostname) rather than URLs/domains, so matching is
IP/CIDR-based with optional hostname exact-match.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import yaml


class AuthorizationError(Exception):
    """Raised for any malformed or invalid authorization.yml."""


def _parse_target_port(target: str) -> str:
    """Strip an optional :port suffix so scope matching is IP/host-only."""
    if target.count(":") == 1 and not target.startswith("["):
        host, _, _port = target.partition(":")
        return host
    return target


def _host_matches(pattern: str, host: str) -> bool:
    """CIDR match for IPs, exact/wildcard match for hostnames."""
    try:
        network = ipaddress.ip_network(pattern, strict=False)
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            return False
        return addr in network
    except ValueError:
        pass  # not a CIDR/IP pattern - fall through to hostname matching

    if pattern.startswith("*."):
        suffix = pattern[1:]  # keep the leading dot
        return host == pattern[2:] or host.endswith(suffix)
    return host == pattern


@dataclass
class Window:
    start: datetime
    end: datetime

    def is_active(self, now: datetime | None = None) -> bool:
        now = now or datetime.now(timezone.utc)
        return self.start <= now <= self.end

    def remaining(self, now: datetime | None = None) -> str:
        now = now or datetime.now(timezone.utc)
        if now > self.end:
            return "expired"
        delta = self.end - now
        hours, remainder = divmod(int(delta.total_seconds()), 3600)
        minutes = remainder // 60
        return f"{hours}h {minutes}m remaining"


@dataclass
class Scope:
    targets: list[str] = field(default_factory=list)
    excluded_targets: list[str] = field(default_factory=list)

    def is_authorized(self, target: str) -> bool:
        host = _parse_target_port(target)

        for excl in self.excluded_targets:
            if _host_matches(excl, host):
                return False  # exclusions always win, regardless of inclusions

        return any(_host_matches(pat, host) for pat in self.targets)


@dataclass
class Authorization:
    engagement_id: str
    authorized_by: str
    scope: Scope
    window: Window
    confirmation_phrase: str
    max_total_requests: int = 5000  # hard safety ceiling, see rate_limit.py
    raw_path: Path | None = None

    def is_authorized(self, target: str, now: datetime | None = None) -> bool:
        return self.scope.is_authorized(target) and self.window.is_active(now)

    def refusal_reason(self, target: str, now: datetime | None = None) -> str | None:
        """Returns a human-readable reason a target is refused, or None if authorized."""
        host = _parse_target_port(target)
        for excl in self.scope.excluded_targets:
            if _host_matches(excl, host):
                return f"target '{target}' matches an explicit exclusion ('{excl}')"
        if not any(_host_matches(pat, host) for pat in self.scope.targets):
            return f"target '{target}' is not listed in scope.targets"
        if not self.window.is_active(now):
            return f"engagement window is not active ({self.window.remaining(now)})"
        return None


def _parse_datetime(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def load_authorization(path: str | Path) -> Authorization:
    path = Path(path)
    if not path.exists():
        raise AuthorizationError(
            f"authorization file not found: {path}\n"
            f"Run 'sipsiege init' to create a template."
        )

    with open(path) as f:
        try:
            data = yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            raise AuthorizationError(f"invalid YAML in {path}: {e}")

    required = ["engagement_id", "authorized_by", "scope", "window", "confirmation_phrase"]
    missing = [k for k in required if k not in data]
    if missing:
        raise AuthorizationError(f"authorization.yml missing required fields: {missing}")

    scope_data = data["scope"] or {}
    if not scope_data.get("targets"):
        raise AuthorizationError(
            "scope.targets is empty - at least one authorized target is required. "
            "This is almost certainly a mistake; refusing to proceed."
        )

    scope = Scope(
        targets=list(scope_data.get("targets", [])),
        excluded_targets=list(scope_data.get("excluded_targets", [])),
    )

    window_data = data["window"] or {}
    try:
        window = Window(
            start=_parse_datetime(window_data["start"]),
            end=_parse_datetime(window_data["end"]),
        )
    except (KeyError, ValueError) as e:
        raise AuthorizationError(f"invalid window.start/window.end: {e}")

    if window.end <= window.start:
        raise AuthorizationError("window.end must be after window.start")

    return Authorization(
        engagement_id=data["engagement_id"],
        authorized_by=data["authorized_by"],
        scope=scope,
        window=window,
        confirmation_phrase=data["confirmation_phrase"],
        max_total_requests=int(data.get("max_total_requests", 5000)),
        raw_path=path,
    )
