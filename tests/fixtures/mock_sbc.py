"""
tests/fixtures/mock_sbc.py

A minimal UDP SIP server used only for this project's own tests. It is
NOT a stand-in for Kamailio/pike behavior in general — it implements a
deliberately simple sliding-window per-source-IP rate limit so that
integration tests can exercise the *whole* SIPSiege code path (CLI ->
scope/confirm gate -> SIPp subprocess -> real UDP packets -> a server
that actually starts dropping a flooding source) without depending on
a real Kamailio instance being available in CI.

Behavior:
  - Responds "200 OK" to any REGISTER from a source IP that has sent
    <= `threshold` requests in the trailing `window` seconds.
  - Silently drops (no response) once that source exceeds the
    threshold - mimicking the observable effect of pike blocking
    (the client sees no reply / a timeout), which is exactly what
    SIPSiege's baseline_probe scenario is designed to detect.
  - A blocked source recovers once enough time passes that its
    request count within the trailing window drops back under
    threshold.

Usage:
  python mock_sbc.py --host 127.0.0.1 --port 5070 --threshold 15 --window 2
"""

from __future__ import annotations

import argparse
import re
import socket
import time
from collections import defaultdict, deque

VIA_RE = re.compile(rb"^Via:\s*(.+)$", re.MULTILINE)
FROM_RE = re.compile(rb"^From:\s*(.+)$", re.MULTILINE)
TO_RE = re.compile(rb"^To:\s*(.+)$", re.MULTILINE)
CALLID_RE = re.compile(rb"^Call-ID:\s*(.+)$", re.MULTILINE)
CSEQ_RE = re.compile(rb"^CSeq:\s*(.+)$", re.MULTILINE)


def build_200_ok(request: bytes) -> bytes:
    def _find(pattern):
        m = pattern.search(request)
        return m.group(1).strip() if m else b""

    via = _find(VIA_RE)
    frm = _find(FROM_RE)
    to = _find(TO_RE)
    call_id = _find(CALLID_RE)
    cseq = _find(CSEQ_RE)

    lines = [
        b"SIP/2.0 200 OK",
        b"Via: " + via,
        b"From: " + frm,
        b"To: " + to,
        b"Call-ID: " + call_id,
        b"CSeq: " + cseq,
        b"Content-Length: 0",
        b"",
        b"",
    ]
    return b"\r\n".join(lines)


class SlidingWindowLimiter:
    def __init__(self, threshold: int, window_seconds: float):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self._hits: dict[str, deque] = defaultdict(deque)

    def allow(self, source_ip: str) -> bool:
        now = time.monotonic()
        dq = self._hits[source_ip]
        dq.append(now)
        cutoff = now - self.window_seconds
        while dq and dq[0] < cutoff:
            dq.popleft()
        return len(dq) <= self.threshold


def serve(host: str, port: int, threshold: int, window: float, log_path: str | None = None):
    limiter = SlidingWindowLimiter(threshold=threshold, window_seconds=window)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    print(f"mock_sbc listening on {host}:{port} "
          f"(threshold={threshold} reqs / {window}s window)")

    logf = open(log_path, "a") if log_path else None
    allowed_count = 0
    dropped_count = 0

    try:
        while True:
            data, addr = sock.recvfrom(65535)
            source_ip = addr[0]
            if data.startswith(b"REGISTER"):
                ok = limiter.allow(source_ip)  # call exactly once - it mutates state
                if ok:
                    resp = build_200_ok(data)
                    sock.sendto(resp, addr)
                    allowed_count += 1
                else:
                    dropped_count += 1  # simulate pike-style silent drop
                if logf:
                    logf.write(
                        f"{time.time()} {source_ip} {'ALLOWED' if ok else 'DROPPED'} "
                        f"allowed_total={allowed_count} dropped_total={dropped_count}\n"
                    )
                    logf.flush()
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()
        if logf:
            logf.close()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=5070)
    p.add_argument("--threshold", type=int, default=15,
                    help="max requests per source IP within --window before dropping")
    p.add_argument("--window", type=float, default=2.0, help="sliding window, seconds")
    p.add_argument("--log", default=None, help="optional path to append a simple hit log")
    args = p.parse_args()
    serve(args.host, args.port, args.threshold, args.window, args.log)


if __name__ == "__main__":
    main()
