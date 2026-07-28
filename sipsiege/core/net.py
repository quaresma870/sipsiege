"""
core/net.py

Shared "is this address actually mine" check - used by any scenario
that needs more than one real local source IP (register_rotating_source,
bye_spoof). A throwaway UDP socket bind to (ip, 0): the OS refuses with
EADDRNOTAVAIL if that address isn't actually assigned to a local
interface. No new dependency (no netifaces or similar) and no parsing
of `ip addr` output, which is iproute2/Linux-specific and would make
this fragile across environments. Never configures interfaces itself -
only checks what's already bound.
"""

from __future__ import annotations

import socket


def is_bound_locally(ip: str) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind((ip, 0))
        return True
    except OSError:
        return False
