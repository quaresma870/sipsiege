"""
core/audit_log.py

Tamper-evident, append-only audit log — same hash-chain approach as
redteam-toolkit's audit_log.py. Every scenario invocation (allowed or
refused) gets one JSON line; each line's hash covers its own content
plus the previous line's hash, so editing, deleting, or reordering
any historical entry breaks the chain from that point forward.

Known limitation (inherited from the same design, and worth stating
plainly rather than implying false guarantees): a pure hash chain
cannot detect truncation of the *most recent* entries, since nothing
after the cut remains to reference what's missing. If that matters
for your use, record entry_count out-of-band after key milestones
(paste it into a ticket, Slack message, etc.) and compare later.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS_HASH = "0" * 64


def _line_hash(prev_hash: str, entry: dict[str, Any]) -> str:
    payload = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev_hash + payload).encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def _last_hash(self) -> str:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return GENESIS_HASH
        with open(self.path) as f:
            last_line = None
            for line in f:
                line = line.strip()
                if line:
                    last_line = line
            if last_line is None:
                return GENESIS_HASH
            return json.loads(last_line)["_hash"]

    def record(
        self,
        action: str,
        target: str,
        allowed: bool,
        reason: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        prev_hash = self._last_hash()
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "target": target,
            "allowed": allowed,
            "reason": reason,
            "details": details or {},
            "_prev_hash": prev_hash,
        }
        entry["_hash"] = _line_hash(prev_hash, entry)
        with open(self.path, "a") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")


def verify_log_integrity(path: str | Path) -> tuple[bool, int | None, int]:
    """
    Returns (valid, broken_at_line, entry_count).
    broken_at_line is 1-indexed and None if the log is fully valid.
    """
    path = Path(path)
    if not path.exists():
        return True, None, 0

    prev_hash = GENESIS_HASH
    count = 0
    with open(path) as f:
        for i, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            claimed_hash = entry.pop("_hash")
            claimed_prev = entry.get("_prev_hash")
            if claimed_prev != prev_hash:
                return False, i, count
            recomputed = _line_hash(prev_hash, entry)
            if recomputed != claimed_hash:
                return False, i, count
            prev_hash = claimed_hash
            count += 1
    return True, None, count
