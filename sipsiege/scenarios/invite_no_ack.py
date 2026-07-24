"""
scenarios/invite_no_ack.py

Half-open call / dialog exhaustion: identical INVITE traffic to
invite_flood (single real source, high rate, rotating spoofed identity
and destination extension), but every call that gets a 200 is
deliberately left hanging - no ACK, no BYE, ever. A target that
answers keeps that dialog (and, realistically, its own 200
retransmission timer) open for the duration of its own retransmission/
timeout window, which is a meaningfully different resource cost than
invite_flood's clean setup-and-teardown cycle: a comparatively small
request rate can still exhaust dialog capacity if each one is left
open long enough, testing whether a target's dialog/session limits are
configured at all, not just its request-rate limiting.

No -recv_timeout tuning turned out to be needed beyond what
core/sipp_runner.py already sets unconditionally for every scenario:
since this scenario has nothing after the mandatory 200 recv, SIPp
simply finishes that call there and moves on - it only hangs waiting
on something it's actually told to wait for.

Tier: active - requires --confirm <engagement_id>.
"""

from __future__ import annotations

from .base import BaseScenario


class InviteNoAck(BaseScenario):
    name = "invite_no_ack"
    tier = "active"
    description = (
        "Single-source, high-rate INVITE flood where every answered call is "
        "deliberately left half-open - no ACK, no BYE, ever. Validates dialog/"
        "session-table limits under sustained half-open volume, not just "
        "pike/htable's request-rate limiting."
    )
    xml_file = "invite_no_ack.xml"
