"""
core/sipp_runner.py

Thin wrapper around invoking SIPp as a subprocess. Deliberately not a
Python SIP stack - SIPp is the de-facto standard traffic generator
for this kind of testing and battle-tested for rate control, so we
shell out to it rather than reimplementing SIP transaction handling.

Two non-obvious SIPp behaviors this wrapper works around, found the
hard way while building the integration test:

1. Without a TTY, SIPp completes a test's calls but still sits on its
   interactive screen waiting for a 'q' keypress that will never
   arrive - subprocess.run() then hangs until its own timeout kills
   it. -nostdin prevents this; -bg (background/daemonize) looked like
   an alternative but detaches into an untracked child process and
   returns almost immediately, before results are actually written -
   wrong fit for something we need to wait on synchronously.

2. -recv_timeout gives a deterministic, fast per-call timeout. Without
   it, a call that never gets a matching response (a genuinely blocked/
   dropped source, or a scenario bug) falls back to SIPp's default
   retransmission backoff, which takes on the order of 30+ seconds per
   call to give up. That's a real problem at any call volume.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


class SippNotFoundError(Exception):
    pass


@dataclass
class SippResult:
    return_code: int
    stdout: str
    stderr: str
    results_dir: Path
    command: list[str]

    @property
    def stats_csv(self) -> Path:
        return self.results_dir / "stats.csv"


def ensure_sipp_installed() -> None:
    if shutil.which("sipp") is None:
        raise SippNotFoundError(
            "sipp is not installed or not on PATH.\n"
            "Install it with 'apt-get install sip-tester' or build from "
            "https://github.com/SIPp/sipp"
        )


def run_sipp(
    target: str,
    port: int,
    scenario_file: Path,
    rate: int,
    total_calls: int,
    transport: str,
    results_dir: Path,
    local_ip: str | None = None,
    extra_args: list[str] | None = None,
) -> SippResult:
    ensure_sipp_installed()
    results_dir.mkdir(parents=True, exist_ok=True)

    transport_flag = "u1" if transport == "udp" else "t1"

    cmd = [
        "sipp",
        f"{target}:{port}",
        "-sf", str(scenario_file),
        "-t", transport_flag,
        "-r", str(rate),
        "-rp", "1000",
        "-m", str(total_calls),
        "-nostdin",                  # never wait on a keypress - see sipp_runner module docstring
        "-recv_timeout", "2000",     # 2s: fail fast on a blocked/dropped source instead of ~32s
        "-trace_msg",
        "-trace_err",
        "-trace_stat",
        "-stf", str(results_dir / "stats.csv"),
        "-message_file", str(results_dir / "messages.log"),
        "-error_file", str(results_dir / "errors.log"),
    ]
    if local_ip:
        cmd += ["-i", local_ip]
    if extra_args:
        cmd += extra_args

    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=total_calls / max(rate, 1) + 60)

    return SippResult(
        return_code=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
        results_dir=results_dir,
        command=cmd,
    )
