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
  - Responds "200 OK" to any REGISTER or INVITE from a source IP that
    has sent <= `threshold` requests (REGISTER and INVITE share one
    counter, same as a real per-IP pike threshold would) in the
    trailing `window` seconds. An allowed INVITE gets a To-tag and a
    minimal SDP answer, since it needs to look like a real
    dialog-establishing response for invite_flood's ACK/BYE to make
    sense.
  - Silently drops (no response) once that source exceeds the
    threshold - mimicking the observable effect of pike blocking
    (the client sees no reply / a timeout), which is exactly what
    SIPSiege's baseline_probe/invite_flood scenarios are designed to
    detect.
  - REGISTER is the one place this mock does something genuinely
    protocol-aware rather than just "always 200 or always drop": if
    the From header's username is purely numeric (a provisioned-
    extension-style identity, as used by digest_bruteforce/user_enum -
    every other scenario here uses an alphabetic identity like
    "floodtest0" or "probe" and is completely unaffected), it's
    treated as requiring real digest auth. An unauthenticated REGISTER
    gets a 401 with a fresh nonce; a REGISTER carrying an Authorization
    header gets its digest response verified for real (RFC 2617 MD5,
    no qop) against KNOWN_CREDENTIALS - 200 if it matches, 403 if it
    doesn't. With --extension-oracle, an unauthenticated REGISTER for
    a numeric username NOT in KNOWN_CREDENTIALS gets 404 instead of
    401 - a deliberately enumerable ("is this extension real?")
    configuration for user_enum to detect; without the flag (the
    default), every numeric username gets the same 401 regardless.
  - BYE always gets a plain 200 OK, unconditionally, uncounted against
    the limiter - tearing down a call you already let through isn't
    the thing being rate-limited. ACK gets no response, as normal.
  - OPTIONS models a real method-scope rate-limiting gap: by default
    it's answered 200 OK unconditionally, NOT counted against the same
    per-IP limiter REGISTER/INVITE share - mirroring how real Kamailio
    configs commonly wire pike/htable into the REGISTER/INVITE routes
    specifically and leave other methods passing straight through.
    With --limit-options, OPTIONS shares the same limiter/counter as
    REGISTER and INVITE instead - the secure configuration, for
    options_flood's integration test to verify both ways.
  - A blocked source recovers once enough time passes that its
    request count within the trailing window drops back under
    threshold.
  - Tracks which source IP established each dialog (the source of the
    INVITE that got a 200) in `established_dialogs`. By default (the
    vulnerable configuration bye_spoof is built to catch) a BYE for a
    known dialog is accepted regardless of whether it comes from that
    same source - unchanged from every prior version of this mock, so
    invite_flood/invite_no_ack's existing log-format assertions ("...
    BYE" with nothing after) still match exactly. With
    --reject-cross-source-bye, a BYE whose source doesn't match the
    dialog's established source gets 403 instead - the secure
    configuration. Either way, a cross-source BYE (accepted or
    rejected) is logged with an explicit ACCEPTED_CROSS_SOURCE /
    REJECTED_CROSS_SOURCE tag so it's never confused with a normal,
    same-source teardown in the log.

Usage:
  python mock_sbc.py --host 127.0.0.1 --port 5070 --threshold 15 --window 2
"""

from __future__ import annotations

import argparse
import hashlib
import random
import re
import socket
import time
import uuid
from collections import defaultdict, deque

VIA_RE = re.compile(rb"^Via:\s*(.+)$", re.MULTILINE)
FROM_RE = re.compile(rb"^From:\s*(.+)$", re.MULTILINE)
TO_RE = re.compile(rb"^To:\s*(.+)$", re.MULTILINE)
CALLID_RE = re.compile(rb"^Call-ID:\s*(.+)$", re.MULTILINE)
CSEQ_RE = re.compile(rb"^CSeq:\s*(.+)$", re.MULTILINE)
AUTHORIZATION_RE = re.compile(rb"^Authorization:\s*(.+)$", re.MULTILINE)

# Synthetic test credentials only - matched against sipsiege's own
# bundled tests/../templates/digest_wordlist_default.csv so the
# digest_bruteforce integration test can exercise a real MD5 match
# (200) and a real MD5 mismatch (403), not stubbed outcomes.
KNOWN_CREDENTIALS = {
    "1000": "changeme",
    "1234": "password123",
}
REALM = "mocksbc"


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


def build_invite_200_ok(request: bytes) -> bytes:
    """Like build_200_ok, but adds a To-tag (this is the UAS establishing
    a new dialog) and a minimal SDP answer, so a real ACK/BYE flow makes
    sense on top of it - unlike REGISTER's 200, this response has to hold
    up as the start of an actual dialog, not just an accepted request."""

    def _find(pattern):
        m = pattern.search(request)
        return m.group(1).strip() if m else b""

    via = _find(VIA_RE)
    frm = _find(FROM_RE)
    to = _find(TO_RE)
    call_id = _find(CALLID_RE)
    cseq = _find(CSEQ_RE)

    to_tag = f"mocksbc{random.randint(100000, 999999)}".encode()
    to_with_tag = to + b";tag=" + to_tag

    sdp_body = (
        b"v=0\r\n"
        b"o=mocksbc 0 0 IN IP4 127.0.0.1\r\n"
        b"s=-\r\n"
        b"c=IN IP4 127.0.0.1\r\n"
        b"t=0 0\r\n"
        b"m=audio 40000 RTP/AVP 0\r\n"
        b"a=rtpmap:0 PCMU/8000\r\n"
    )

    header_lines = [
        b"SIP/2.0 200 OK",
        b"Via: " + via,
        b"From: " + frm,
        b"To: " + to_with_tag,
        b"Call-ID: " + call_id,
        b"CSeq: " + cseq,
        b"Content-Type: application/sdp",
        b"Content-Length: " + str(len(sdp_body)).encode(),
    ]
    return b"\r\n".join(header_lines) + b"\r\n\r\n" + sdp_body


def _sip_header_lines(request: bytes) -> list[bytes]:
    """The Via/From/To/Call-ID/CSeq lines every response here mirrors
    back, factored out since build_401_challenge and
    build_403_forbidden both need exactly this and nothing else."""
    def _find(pattern):
        m = pattern.search(request)
        return m.group(1).strip() if m else b""

    return [
        b"Via: " + _find(VIA_RE),
        b"From: " + _find(FROM_RE),
        b"To: " + _find(TO_RE),
        b"Call-ID: " + _find(CALLID_RE),
        b"CSeq: " + _find(CSEQ_RE),
    ]


def extract_from_username(request: bytes) -> str:
    """Pulls the user part out of the From header's sip:user@host URI -
    used to decide whether a REGISTER's username looks like a real
    provisioned extension (purely numeric) or one of this project's own
    scenario identities (always alphabetic, e.g. "floodtest0", "probe")."""
    m = FROM_RE.search(request)
    if not m:
        return ""
    uri_match = re.search(rb"sip:([^@]+)@", m.group(1))
    return uri_match.group(1).decode(errors="replace") if uri_match else ""


def extract_call_id(request: bytes) -> str:
    """Used to key established_dialogs (see serve()'s docstring) - the
    same Call-ID value a BYE for that dialog must carry."""
    m = CALLID_RE.search(request)
    return m.group(1).strip().decode(errors="replace") if m else ""


def build_401_challenge(request: bytes) -> bytes:
    """Fresh WWW-Authenticate challenge, no qop - so the [authentication]
    keyword's own digest computation (and _digest_response_matches'
    verification of it below) stays the simple RFC 2617 case."""
    nonce = uuid.uuid4().hex
    lines = [b"SIP/2.0 401 Unauthorized", *_sip_header_lines(request)]
    lines.append(f'WWW-Authenticate: Digest realm="{REALM}", nonce="{nonce}", algorithm=MD5'.encode())
    lines += [b"Content-Length: 0", b"", b""]
    return b"\r\n".join(lines)


def build_404_not_found(request: bytes) -> bytes:
    lines = [b"SIP/2.0 404 Not Found", *_sip_header_lines(request), b"Content-Length: 0", b"", b""]
    return b"\r\n".join(lines)


def build_403_forbidden(request: bytes) -> bytes:
    lines = [b"SIP/2.0 403 Forbidden", *_sip_header_lines(request), b"Content-Length: 0", b"", b""]
    return b"\r\n".join(lines)


def _parse_digest_header(header_value: bytes) -> dict[str, str]:
    """Parses a SIP Authorization header's key="value" (or bare key=value)
    pairs into a plain dict - just enough to verify a digest response,
    not a general-purpose header parser."""
    text = header_value.decode(errors="replace")
    return {k: (quoted or bare) for k, quoted, bare in re.findall(r'(\w+)=(?:"([^"]*)"|([^,\s]+))', text)}


def digest_response_matches(auth: dict[str, str], method: bytes, password: str) -> bool:
    """Real RFC 2617 MD5 digest verification (no qop) - HA1/HA2/response,
    not a stubbed comparison. This is what makes the digest_bruteforce
    integration test's 200-for-correct/403-for-wrong assertions mean
    something: the crypto actually has to match."""
    username = auth.get("username", "")
    realm = auth.get("realm", "")
    nonce = auth.get("nonce", "")
    uri = auth.get("uri", "")
    claimed_response = auth.get("response", "")

    ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
    ha2 = hashlib.md5(f"{method.decode()}:{uri}".encode()).hexdigest()
    expected = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
    return expected == claimed_response


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


def serve(
    host: str, port: int, threshold: int, window: float,
    log_path: str | None = None, extension_oracle: bool = False,
    limit_options: bool = False, reject_cross_source_bye: bool = False,
):
    limiter = SlidingWindowLimiter(threshold=threshold, window_seconds=window)
    established_dialogs: dict[str, str] = {}  # call_id -> source IP that set it up
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    print(f"mock_sbc listening on {host}:{port} "
          f"(threshold={threshold} reqs / {window}s window, "
          f"extension_oracle={extension_oracle}, limit_options={limit_options}, "
          f"reject_cross_source_bye={reject_cross_source_bye})")

    logf = open(log_path, "a") if log_path else None
    allowed_count = 0
    dropped_count = 0

    try:
        while True:
            data, addr = sock.recvfrom(65535)
            source_ip = addr[0]
            method = data.split(b" ", 1)[0]

            if method == b"REGISTER":
                ok = limiter.allow(source_ip)  # call exactly once - it mutates state
                if not ok:
                    dropped_count += 1  # simulate pike-style silent drop
                    if logf:
                        logf.write(
                            f"{time.time()} {source_ip} REGISTER DROPPED "
                            f"allowed_total={allowed_count} dropped_total={dropped_count}\n"
                        )
                        logf.flush()
                    continue

                allowed_count += 1
                username = extract_from_username(data)
                auth_header = AUTHORIZATION_RE.search(data)

                if not username.isdigit():
                    # Every existing scenario's identity (floodtest0,
                    # probe, legituser, ...) is alphabetic - unaffected
                    # by digest auth, exactly the pre-existing behavior.
                    resp, tag = build_200_ok(data), "ALLOWED"
                elif auth_header:
                    auth = _parse_digest_header(auth_header.group(1))
                    expected_password = KNOWN_CREDENTIALS.get(username)
                    if expected_password is not None and digest_response_matches(
                        auth, b"REGISTER", expected_password
                    ):
                        resp, tag = build_200_ok(data), "AUTH_OK"
                    else:
                        resp, tag = build_403_forbidden(data), "AUTH_FAIL"
                elif extension_oracle and username not in KNOWN_CREDENTIALS:
                    resp, tag = build_404_not_found(data), "NOT_FOUND"
                else:
                    resp, tag = build_401_challenge(data), "AUTH_CHALLENGE"

                sock.sendto(resp, addr)
                if logf:
                    logf.write(
                        f"{time.time()} {source_ip} REGISTER {tag} "
                        f"allowed_total={allowed_count} dropped_total={dropped_count}\n"
                    )
                    logf.flush()
            elif method == b"INVITE":
                ok = limiter.allow(source_ip)  # call exactly once - it mutates state
                if ok:
                    resp = build_invite_200_ok(data)
                    sock.sendto(resp, addr)
                    allowed_count += 1
                    established_dialogs[extract_call_id(data)] = source_ip
                else:
                    dropped_count += 1  # simulate pike-style silent drop
                if logf:
                    logf.write(
                        f"{time.time()} {source_ip} INVITE "
                        f"{'ALLOWED' if ok else 'DROPPED'} "
                        f"allowed_total={allowed_count} dropped_total={dropped_count}\n"
                    )
                    logf.flush()
            elif method == b"BYE":
                # Tearing down a call that already got through isn't
                # what's being rate-limited here - never counted against
                # the limiter. But bye_spoof cares whether the source
                # tearing it down was ever actually part of the dialog.
                established_source = established_dialogs.get(extract_call_id(data))
                cross_source = established_source is not None and established_source != source_ip
                if reject_cross_source_bye and cross_source:
                    sock.sendto(build_403_forbidden(data), addr)
                    if logf:
                        logf.write(f"{time.time()} {source_ip} BYE REJECTED_CROSS_SOURCE\n")
                        logf.flush()
                else:
                    sock.sendto(build_200_ok(data), addr)
                    if logf:
                        if cross_source:
                            logf.write(f"{time.time()} {source_ip} BYE ACCEPTED_CROSS_SOURCE\n")
                        else:
                            # Unchanged format from every prior version of
                            # this mock - invite_flood/invite_no_ack's own
                            # integration-test assertions grep for exactly
                            # this line shape (" BYE$"), never hit by
                            # bye_spoof since they never send a
                            # cross-source teardown.
                            logf.write(f"{time.time()} {source_ip} BYE\n")
                        logf.flush()
            elif method == b"OPTIONS":
                if limit_options:
                    # Secure configuration: OPTIONS shares the same
                    # per-IP counter as REGISTER/INVITE.
                    ok = limiter.allow(source_ip)  # call exactly once - it mutates state
                    if ok:
                        sock.sendto(build_200_ok(data), addr)
                        allowed_count += 1
                    else:
                        dropped_count += 1
                    if logf:
                        logf.write(
                            f"{time.time()} {source_ip} OPTIONS "
                            f"{'ALLOWED' if ok else 'DROPPED'} "
                            f"allowed_total={allowed_count} dropped_total={dropped_count}\n"
                        )
                        logf.flush()
                else:
                    # Default, vulnerable configuration: the real gap
                    # this scenario tests - OPTIONS is answered
                    # unconditionally, never touching the limiter at
                    # all, unlike every other counted method here.
                    sock.sendto(build_200_ok(data), addr)
                    if logf:
                        logf.write(f"{time.time()} {source_ip} OPTIONS UNLIMITED\n")
                        logf.flush()
            # ACK and anything else: no response expected, ignore.
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
    p.add_argument("--extension-oracle", action="store_true",
                    help="unauthenticated REGISTER for an unknown numeric extension gets "
                         "404 instead of 401 - deliberately enumerable, for user_enum")
    p.add_argument("--limit-options", action="store_true",
                    help="OPTIONS shares the same per-IP limiter as REGISTER/INVITE - the "
                         "secure configuration. Default (off) leaves OPTIONS uncounted and "
                         "unconditionally answered, the method-scope gap options_flood tests")
    p.add_argument("--reject-cross-source-bye", action="store_true",
                    help="a BYE for a known dialog whose source doesn't match the source "
                         "that established it gets 403 instead of being torn down - the "
                         "secure configuration. Default (off) accepts it regardless, the "
                         "dialog-hijacking gap bye_spoof tests")
    args = p.parse_args()
    serve(
        args.host, args.port, args.threshold, args.window, args.log,
        args.extension_oracle, args.limit_options, args.reject_cross_source_bye,
    )


if __name__ == "__main__":
    main()
