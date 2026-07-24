# Roadmap

This tracks what's shipped and what's planned for `sipsiege`. Order reflects
current priority, not a fixed release schedule. Everything here stays inside
the existing safety model — scope-gated, `--confirm`-gated, audit-logged —
see [Guardrails for every future scenario](#guardrails-for-every-future-scenario)
before picking any of these up.

## Shipped

### v0.1.0
- Authorization/scope model (CIDR + wildcard SIP-host matching), hash-chained
  tamper-evident audit log, hard per-invocation rate ceiling.
- Five scenarios, all REGISTER-based: `baseline_probe`, `register_flood`,
  `register_burst`, `register_rotating_source`, `register_legit_mix`.
- CI: real wheel, real `sipp`, real mock SBC — not mocked, not `CliRunner`.

### v0.2.0
- `invite_flood` — call-setup flood. A REGISTER flood exhausts registration
  handling; this exhausts call/dialog state instead — each INVITE that gets
  a provisional or final response makes the target allocate transaction
  and (if not torn down) dialog state, a heavier resource hit per request
  than a REGISTER. Rotates spoofed identity *and* destination extension
  per call; each call completes cleanly (INVITE → 200 → ACK → immediate
  BYE) so the only variable under test is call-setup rate — a scenario
  that deliberately leaves calls half-open instead is intentionally a
  separate item (see `invite_no_ack` below), not this one.
  `tests/fixtures/mock_sbc.py` now answers INVITE (To-tag + minimal SDP,
  sharing REGISTER's per-IP limiter) and BYE (always accepted,
  unconditionally), so the integration test exercises a real, complete
  INVITE/ACK/BYE cycle rather than mocking it.

## Next — attack scenario coverage

REGISTER and INVITE flooding are two real patterns among several. The
items below are each grounded in a documented, commonly-seen SIP/VoIP
attack technique — prioritized by how often they show up against real
internet-facing SBCs, not by implementation difficulty.

### 1. `invite_no_ack` — half-open call / dialog exhaustion (highest priority)
A real, specifically damaging variant of #1: send INVITE, receive
180/200, and deliberately never send ACK (or send it and never BYE).
Each half-open dialog consumes SBC session-table memory for the duration
of its retransmission/timeout window — a small request rate can still
exhaust dialog capacity if dialogs are left open long enough, which is a
meaningfully different failure mode from a raw per-second rate trip and
tests whether Kamailio's dialog module / max-dialog limits are configured
at all, not just `pike`. Tier: active. Needs: `-recv_timeout` tuning so
SIPp doesn't itself hang waiting on an ACK it's told not to send — same
class of problem already solved once for `baseline_probe` in
`core/sipp_runner.py`, worth reusing that lesson here.

### 2. `digest_bruteforce` — credential stuffing against REGISTER auth
The single most common real-world VoIP attack is not flooding, it's
credential stuffing against SIP digest auth to hijack a trunk for toll
fraud — attackers cycle short numeric extensions (1000-9999) against
common/default passwords. This exercises a *different* Kamailio defense
than `pike`/`htable`: auth-failure-specific throttling (e.g. `pike` tuned
on 401/403 responses, or fail2ban-style external blocking on auth
failures specifically). A pure volume flood and a low-and-slow credential
stuffing run can trip completely different thresholds, so this is not
redundant with `register_flood` even though both are REGISTER-shaped.
Tier: active. Needs: SIPp's built-in digest auth support (`-au`/`-ap` or
inline `[authentication]` in the XML) and a wordlist-driving loop over
extension/password pairs — this is the first scenario that needs
per-attempt credential variation rather than just identity rotation.

### 3. `user_enum` — extension/account enumeration (recon tier)
Precedes #2 in a real attack chain: probing REGISTER or OPTIONS against a
range of extensions and diffing the response (401 = valid account exists,
404 = doesn't) to build a target list before brute-forcing it — the same
technique tools like `svwar` use. Low volume, not disruptive, so this
belongs at `baseline` tier like `baseline_probe`, not `active` — it's
recon, not load. Valuable on its own merit (confirms whether Kamailio
returns a uniform response regardless of account existence, which is the
actual defense against this) and as the natural companion/precondition to
#2. Good candidate to ship together with #2.

### 4. `rotating_source`, scaled realistically
The existing `register_rotating_source` is correct in design (real bound
local IPs, no source-IP spoofing — see guardrails below) but is currently
bottlenecked at "however many IPs you're willing to `ip addr add` by
hand." A real distributed flood is dozens to thousands of sources. Worth
adding a `--local-ip-range 10.0.0.0/24` convenience that validates the
range is actually bound (never auto-configures interfaces itself — that
non-goal stays) and drives many more concurrent `sipp` processes, so the
"does aggregate rate limiting exist, not just per-IP" question in the
existing scenario's docstring can actually be tested at a realistic
source count instead of 2-3.

### 5. `bye_spoof` — in-dialog request forgery / session hijacking
Tests something none of the current scenarios touch: whether the SBC
validates that a BYE/CANCEL/re-INVITE for an existing dialog actually
comes from a party to that dialog (correct topology hiding, tag/Call-ID
handling) rather than accepting any request that happens to guess or
replay a Call-ID + tags. A legitimate two-party call is set up first (via
`register_legit_mix`'s legit stream or a new minimal call fixture), then
a forged BYE is sent from a third source using guessed/observed dialog
identifiers. This is lower priority than 1-3 (needs real dialog-state
plumbing SIPp doesn't make trivial, and the attack precondition —
obtaining a real Call-ID/tag pair — usually requires the attacker to have
already compromised a leg of the call or be on-path, so it's less of a
pure internet-exposure risk than the others). Worth a design spike before
committing to it.

### 6. RTP/media-plane flood
Everything shipped and planned above is signaling-plane (SIP itself).
After a real or simulated call setup, a separate attack surface exists at
the negotiated RTP port — garbage UDP volume there tests the SBC/RTP
proxy's media-plane rate limiting independently of `pike`/`htable`, which
only see SIP signaling. Needs a minimal RTP packet generator (or driving
`sipp`'s own RTP echo capability) bound to the port negotiated by a real
completed call. Bigger scope than the SIP-only scenarios above — sequence
after 1-3 land.

## Later — instrumentation, not new attack surface

These make existing and future scenarios more useful without adding new
traffic patterns:

- **Legit-call latency/jitter during flood**, not just success/fail.
  `register_legit_mix` currently reports pass/fail via SIPp's
  `SuccessfulCall`/`FailedCall` counters; call setup *time* degrading
  under load (even while technically still succeeding) is itself a
  real-world impact worth surfacing.
- **Run-history comparison** — `sipsiege status` already verifies the
  audit log; a `sipsiege report <engagement_id>` that summarizes what ran,
  in what order, and links each run's `results/` directory would make
  postmortems and due-diligence writeups (see `docs/legal-and-ethics.md`'s
  "Reporting findings internally" section) much less manual.
- **IPv6 source support** end-to-end (scenario XMLs, `sipp_runner.py`,
  `register_rotating_source`'s local-IP handling) — real attackers
  increasingly use IPv6 specifically because operators' rate-limiting is
  more often tuned for IPv4 only.

## Guardrails for every future scenario

Every item above must keep the properties that make this toolkit safe to
run against production with authorization at all — these are non-negotiable
constraints on implementation, not aspirations:

- **No IP-layer source spoofing, ever.** Identity rotation happens at the
  SIP layer (From/To/Contact/Call-ID) exactly as today; the underlying UDP/
  TCP source is always a real address you actually control and bound
  yourself. A scenario that spoofs the network-layer source could be
  repurposed as a reflection/amplification attack against an arbitrary
  third party — that is categorically out of scope for this project,
  regardless of how it's gated.
- **No default target lists, no scanning beyond `scope.targets`.** Recon
  scenarios like `user_enum` enumerate *accounts* on an already-authorized
  target; they never discover or touch new targets on their own.
  `authorization.yml`'s scope gate applies identically to every tier.
  `--confirm` stays required fresh on every single active-tier invocation.
- **Every new scenario ships with a mock-target integration test**, same
  as the current five — a scenario that's only ever been run against a
  real SBC in someone's lab isn't trustworthy enough to ship.
