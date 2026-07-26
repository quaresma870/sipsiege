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
  separate item (see v0.3.0 below), not this one.
  `tests/fixtures/mock_sbc.py` now answers INVITE (To-tag + minimal SDP,
  sharing REGISTER's per-IP limiter) and BYE (always accepted,
  unconditionally), so the integration test exercises a real, complete
  INVITE/ACK/BYE cycle rather than mocking it.

### v0.3.0
- `invite_no_ack` — half-open call / dialog exhaustion. Identical INVITE
  traffic to `invite_flood`, but every answered call is deliberately left
  half-open — no ACK, no BYE, ever. Each half-open dialog consumes the
  target's session-table memory (and, realistically, its 200
  retransmission timer) for the duration of its own retransmission/
  timeout window — a comparatively small request rate can still exhaust
  dialog capacity if calls are left open long enough, a meaningfully
  different failure mode from a raw per-second rate trip. Tests whether
  dialog/session limits are configured at all, not just request-rate
  limiting. Turned out to need no `-recv_timeout` tuning or `mock_sbc.py`
  changes — the half-open behavior is entirely a client-side omission (no
  `<send>` after the mandatory `200` recv), and the existing
  unconditional `-recv_timeout 2000` already means SIPp only hangs
  waiting on things it's actually told to wait for.

### v0.4.0
- `digest_bruteforce` — credential stuffing against SIP digest auth, the
  single most common real-world VoIP attack (not flooding) — attackers
  cycle short numeric extensions against common/default passwords to
  hijack a trunk for toll fraud. Exercises a *different* Kamailio defense
  than `pike`/`htable`: auth-failure-specific throttling, not raw
  request-rate limiting. Turned out SIPp's `[authentication]` keyword
  can't take per-call credentials via `[field0]`/`[field1]` substitution
  the way this entry originally assumed — it silently corrupts the
  Authorization header instead of erroring. Fixed by driving one real
  `sipp` subprocess per credential pair (`-s`/`-au`/`-ap` per invocation)
  rather than one invocation with `-inf` CSV injection, which turned out
  to match how this technique is actually done in practice anyway:
  deliberate and low-and-slow, not a flood. See CHANGELOG.md for the
  full account of the discovery.

### v0.5.0
- `user_enum` — extension/account enumeration (recon tier). Precedes
  `digest_bruteforce` in a real attack chain: one unauthenticated
  REGISTER per candidate extension, diffing the response (401 = exists,
  404 = doesn't with `--extension-oracle`) to build a target list before
  brute-forcing it — the same technique tools like `svwar` use. Baseline
  tier like `baseline_probe`, not active — it's recon, not load. A
  single mandatory `401` recv (see every other scenario's "exactly one
  mandatory recv" pattern) means SIPp's own SuccessfulCall/FailedCall
  split *is* the enumeration signal, no new instrumentation needed.
  `mock_sbc.py`'s `--extension-oracle` flag (built alongside
  `digest_bruteforce` in 0.4.0) gets its first real exercise here -
  the integration test verifies both the secure (uniform 401) and
  vulnerable (differentiated 401/404) configurations for real.

### v0.6.0
- `register_rotating_source` scaling. Was bottlenecked at "however many
  IPs you're willing to `ip addr add` by hand." Added `--local-ip-range`
  (CIDR) as an alternative to listing addresses one at a time with
  `--local-ips`, so the "does aggregate rate limiting exist, not just
  per-IP" question can be tested at dozens of sources instead of 2-3.
  Never auto-configures interfaces — that non-goal stays; the range is
  only checked against what's actually bound, via a throwaway UDP socket
  bind per candidate address (no `netifaces`, no parsing `ip addr`
  output). If both `--local-ips` and `--local-ip-range` are given, the
  explicit list wins outright rather than merging the two.

### v0.7.0
- `options_flood` — method-scope rate-limiting bypass. Same flood shape
  as `register_flood` (single real source, high rate, rotating spoofed
  identity per request), but using OPTIONS instead of REGISTER. Most
  real Kamailio configs wire `pike`/`htable` checks into the REGISTER
  and INVITE routes specifically; OPTIONS (along with SUBSCRIBE,
  MESSAGE, PUBLISH, etc.) commonly passes straight through unrated. A
  source already blocked instantly over REGISTER can still flood
  freely over an unprotected method like OPTIONS if the same limiter
  isn't wired into every route that reaches it.
  `tests/fixtures/mock_sbc.py` gained `--limit-options`: by default
  (off) OPTIONS is answered unconditionally and never touches the
  per-IP limiter at all — the real gap this scenario demonstrates; with
  the flag, OPTIONS shares the same counter as REGISTER/INVITE — the
  secure configuration. The integration test verifies both: a 100-call
  flood against the default mock succeeds 100/100 (unrated bypass),
  the identical flood against a `--limit-options` mock trips the
  limiter and drops calls, same rigor as every prior "test both
  configurations for real" scenario.
- Kamailio defense coverage doc: `docs/kamailio-defenses.md`, concrete
  configuration guidance (modparams, route snippets) for defending
  against every scenario this toolkit ships, one section per scenario.

## Next — attack scenario coverage

REGISTER flooding, INVITE flooding (clean and half-open), digest
credential stuffing, and extension enumeration are the patterns covered
so far. The items below are each grounded in a documented, commonly-seen
SIP/VoIP attack technique — prioritized by how often they show up against
real internet-facing SBCs, not by implementation difficulty.

### 1. `bye_spoof` — in-dialog request forgery / session hijacking
Tests something none of the current scenarios touch: whether the SBC
validates that a BYE/CANCEL/re-INVITE for an existing dialog actually
comes from a party to that dialog (correct topology hiding, tag/Call-ID
handling) rather than accepting any request that happens to guess or
replay a Call-ID + tags. A legitimate two-party call is set up first (via
`register_legit_mix`'s legit stream or a new minimal call fixture), then
a forged BYE is sent from a third source using guessed/observed dialog
identifiers. Genuinely harder than everything shipped so far (needs real
dialog-state plumbing SIPp doesn't make trivial, and the attack
precondition — obtaining a real Call-ID/tag pair — usually requires the
attacker to have already compromised a leg of the call or be on-path, so
it's less of a pure internet-exposure risk than the others). First in
this list mainly by elimination; worth a design spike before committing
to it, not a straightforward next build.

### 2. RTP/media-plane flood
Everything shipped and planned above is signaling-plane (SIP itself).
After a real or simulated call setup, a separate attack surface exists at
the negotiated RTP port — garbage UDP volume there tests the SBC/RTP
proxy's media-plane rate limiting independently of `pike`/`htable`, which
only see SIP signaling. Needs a minimal RTP packet generator (or driving
`sipp`'s own RTP echo capability) bound to the port negotiated by a real
completed call. Bigger scope than the SIP-only scenarios above — sequence
after 1 lands.

### 3. Malformed-message parser stress (`sanity` module / RFC 4475 SIP Torture Test)
Every scenario shipped so far sends well-formed SIP; nothing tests
whether the target's `sanity_check()` / core parser (max header count,
max message length, malformed Request-URI, mismatched Content-Length,
etc.) is actually hardened rather than just assumed hardened. RFC 4475
("SIP Torture Test Messages") already defines a canonical set of
deliberately-malformed-but-parseable messages for exactly this purpose
— this scenario would replay a subset of them at a real target. Harder
than the flood scenarios: "success" here isn't a clean SuccessfulCall
count, it's confirming the target rejected or safely ignored each
malformed message rather than crashing, hanging, or forwarding it
somewhere it shouldn't — needs a different, per-message pass/fail
model than the binary 200/not-200 pattern every other scenario uses.

### 4. TCP/TLS connection-table exhaustion (`tcp_max_connections`)
Every current scenario is UDP, stateless per request. A real Kamailio
deployment listening on TCP/TLS instead has (or should have) a
`tcp_max_connections`/`tls_max_connections` ceiling — a source that
opens many connections without ever completing a transaction on them
can exhaust that table independently of any SIP-layer rate limiting.
Meaningfully more SIPp complexity than anything shipped so far (holding
raw TCP/TLS connections open deliberately, not just sending fast) —
worth a design spike on how to do this with SIPp before committing to
an implementation approach.

### 5. Trusted-header IP spoofing (`real_ip_header` / reverse-proxy trust)
A misconfiguration class, not a volume attack: when Kamailio sits behind
a load balancer or SBC and is configured to trust a client-supplied
header (e.g. `X-Real-IP`) for its own per-source-IP accounting instead
of the actual UDP/TCP source, that header can be forged to make every
request look like it came from a different (or constantly-rotating)
source — evading `pike` entirely from one real, single source, without
ever touching the network-layer source address (so this stays inside
the "no IP-layer spoofing, ever" guardrail below). Needs
`tests/fixtures/mock_sbc.py` to model a reverse-proxy trust boundary
that doesn't exist yet — a flag for "trust this header for per-source
accounting" alongside real from-socket accounting, so the integration
test can demonstrate both a trusting (vulnerable) and non-trusting
(secure) configuration, same rigor as `--extension-oracle` and
`options_flood`'s `--limit-options`.

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
