# Kamailio defense configuration guide

This is the other half of `sipsiege`: not just "does this scenario detect
a gap," but "what do I actually put in `kamailio.cfg` to close it." Each
section below maps to one shipped scenario (see the
[Scenarios table](../README.md#scenarios)), names the Kamailio module(s)
that defend against it, gives a concrete config snippet, and says how to
validate the fix with `sipsiege` itself.

None of this is a drop-in `kamailio.cfg` — it's the relevant fragment for
each defense, assuming a fairly standard `REQINIT`/`WITHINDLG`/registrar/
INVITE routing skeleton (the one `kamailio-basic` and most packaged
configs start from). Adjust names/routes to match your own file. Test
every change with `sipsiege` against a lab instance before touching
production — see [legal-and-ethics.md](legal-and-ethics.md).

## The core building block: `pike` + `htable`

Almost everything below builds on the same two modules:

- **`pike`** tracks request rate per source IP over a sliding window and
  flags a source once it crosses a threshold.
- **`htable`** is a generic in-memory key/value store — used here both as
  `pike`'s own ban table and, in several sections below, as a hand-rolled
  counter for things `pike` doesn't track by itself (per-account auth
  failures, aggregate rate across many sources, etc.).

```
loadmodule "pike.so"
modparam("pike", "sampling_time_unit", 2)
modparam("pike", "reqs_density_per_unit", 30)   # tune to your real traffic
modparam("pike", "remove_latency", 4)

loadmodule "htable.so"
modparam("htable", "htable", "ipban=>size=8;autoexpire=300;")
```

```
route[REQINIT] {
    if (!mf_process_maxfwd_header("10")) {
        sl_send_reply("483", "Too Many Hops");
        exit;
    }
    if ($sht(ipban=>$si) != $null) {
        # already banned - drop silently, same observable effect
        # sipsiege's baseline_probe/*_flood scenarios are built to detect
        exit;
    }
    if (!pike_check_req()) {
        xlog("L_ALERT", "ALERT: pike blocking $rm from $si\n");
        $sht(ipban=>$si) = 1;
        exit;
    }
    ...
}
```

**This is also where `options_flood`'s finding gets fixed** — see that
section below; the fix is about *where* this block runs, not a new
module.

## `register_flood` / `register_burst`

Both are the same underlying defense — `pike` on the REGISTER route,
exercised at two different rates. `register_flood` confirms the
threshold trips at all; `register_burst` (sized just under it)
checks that legitimate bursty re-registration (e.g. many phones
re-registering after a network blip) *doesn't* falsely trip the same
limiter.

The config above, applied in `REQINIT` (which every request passes
through before method-specific routing), already covers this. The only
real tuning knob is `reqs_density_per_unit` / `sampling_time_unit` —
too low and `register_burst` starts failing legitimate traffic; too
high and `register_flood` never trips. Validate both directions:

```bash
sipsiege run register_flood <target> --rate 50 --duration 20 --confirm <id>   # must trip
sipsiege run register_burst <target> --confirm <id>                          # must NOT trip
```

## `register_rotating_source`

`pike` is inherently per-source-IP. A flood spread across many real
source addresses, each individually under threshold, sails straight
through a per-IP-only defense — this is what `register_rotating_source`
(`--local-ips`/`--local-ip-range`) tests. The defense is an *aggregate*
limit on top of the per-IP one, independent of how many distinct sources
are involved. Kamailio's `ratelimit` module does this natively:

```
loadmodule "ratelimit.so"
modparam("ratelimit", "timer_interval", 1)

route[REQINIT] {
    ...
    if (!rl_check("register_pipe")) {
        sl_send_reply("503", "Aggregate REGISTER rate exceeded");
        exit;
    }
    ...
}

# defined once at startup, e.g. via rl_set_count(), or statically:
# pipe "register_pipe": algorithm TAILDROP, limit 200 req/s process-wide
```

Validate with `register_rotating_source` across at least 2 source IPs,
each individually under your per-IP `pike` threshold but summing above
the aggregate pipe limit — the flood should now trip even though no
single source would have.

## `register_legit_mix`

The flip side of the above: does blocking an attacker collaterally block
real traffic sharing the same target? The defense isn't a new module,
it's making sure known-good sources are explicitly trusted so they never
enter the ban path at all, via the `permissions` module's trusted table:

```
loadmodule "permissions.so"
modparam("permissions", "db_url", "DEFAULT_DB_URL")

route[REQINIT] {
    if (allow_source_address()) {
        # trusted peer (your own PBX, a known SIP trunk, etc.) - skip
        # pike/htable entirely for this source
    } else if (!pike_check_req()) {
        ...
    }
}
```

Validate with `register_legit_mix --attacker-ip <flood-source>
--legit-ip <trusted-source>` — the legit stream's success rate should be
unaffected by the concurrent flood once the legit source is in the
trusted table (and, notably, should regress *without* it — that's the
false-positive gap this scenario exists to catch).

## `invite_flood`

Same `pike`/`ratelimit` defenses as REGISTER apply — the difference is
that an INVITE that gets through allocates transaction and dialog state
the moment it's answered, a heavier per-request cost than a REGISTER.
Bound the transaction table itself as a second layer, independent of
request rate:

```
loadmodule "tm.so"
modparam("tm", "fr_timer", 5000)          # 5s to get a final response
modparam("tm", "fr_inv_timer", 10000)     # 10s to get a final INVITE response
```

Short `fr_inv_timer` values bound how long a stalled/slow-to-answer
INVITE holds transaction state, limiting how much a moderate-rate INVITE
flood can pile up even before dialog concerns come into play.

## `invite_no_ack`

The `dialog` module tracks established dialogs; the defense that
matters here is bounding how long a dialog is allowed to sit
half-open (answered but never ACKed/torn down) rather than trusting the
far end to ever send a BYE:

```
loadmodule "dialog.so"
modparam("dialog", "dlg_match_mode", 1)
modparam("dialog", "default_timeout", 180)   # force-expire a dialog after 3 min
modparam("dialog", "dlg_extra_hdrs", "")

route[WITHINDLG] {
    if (!has_totag()) return;
    if (!loose_route()) {
        sl_send_reply("404", "Not Found");
        exit;
    }
    ...
}

onreply_route[INVITE_REPLIES] {
    if (t_check_status("2[0-9][0-9]")) {
        dlg_manage();   # start tracking this dialog for lifetime enforcement
    }
}
```

`default_timeout` is the actual defense: it caps how long any dialog —
including a deliberately-abandoned one from this scenario — is allowed
to consume session-table memory before Kamailio expires it itself,
regardless of whether the far end ever sends BYE.

Validate by running `invite_no_ack` and confirming (via `dlg.list` on
Kamailio's RPC interface, or your own monitoring) that dialog count
returns to baseline after `default_timeout` elapses, without needing a
real BYE.

## `digest_bruteforce`

This is a fundamentally different defense than request-rate limiting:
throttling on *auth failure*, not raw volume, since a low-and-slow
credential-stuffing run (this scenario's own design, one request per
credential pair with pacing) can stay well under any `pike` threshold
while still being a real attack. `htable` again, keyed by source and/or
target extension rather than just source IP:

```
loadmodule "htable.so"
modparam("htable", "htable", "authfail=>size=8;autoexpire=300;")

route[REGISTRAR_AUTH] {
    if (!www_authenticate("$td", "subscriber")) {
        $var(key) = "af~" + $si + "~" + $tU;
        $sht(authfail=>$var(key)) = $sht(authfail=>$var(key)) + 1;
        if ($sht(authfail=>$var(key)) > 5) {
            xlog("L_ALERT", "ALERT: auth-failure throttle tripped for $tU from $si\n");
            sl_send_reply("403", "Forbidden");
            exit;
        }
        auth_challenge("$td", "1");
        exit;
    }
    ...
}
```

Keying by `$si~$tU` (source *and* target extension) catches both a
single source brute-forcing many extensions and many sources converging
on one extension — either pattern alone can otherwise stay under a
naive per-IP-only counter.

Validate with `digest_bruteforce --wordlist <yours>` and confirm the
mock/real target starts returning 403 (throttled) rather than 401
(still challenging) once the failure count for that source/extension
pair crosses your threshold.

## `user_enum`

Not a rate-based defense at all — the fix is making sure the REGISTER
auth path returns an *identical* response for a real extension and a
non-existent one. The vulnerable pattern this scenario is built to catch
is a registrar returning 404 (or any other differentiated response) for
an unprovisioned extension instead of the same 401 challenge every
account gets:

```
route[REGISTRAR_AUTH] {
    # WRONG - leaks whether $tU is provisioned before any auth attempt:
    # if (!subscriber_exists("$tU")) { sl_send_reply("404", "Not Found"); exit; }

    # RIGHT - challenge unconditionally; a nonexistent account simply
    # can never produce a valid digest response, which the existing
    # www_authenticate() check already handles identically either way.
    if (!www_authenticate("$td", "subscriber")) {
        auth_challenge("$td", "1");
        exit;
    }
    ...
}
```

Validate with `user_enum --ext-start <n> --ext-count <k>` against a
range spanning both real and non-existent extensions — every candidate
should read as `uniform_response_count`, none as
`differentiated_response_count`.

## `options_flood`

The gap this scenario tests is entirely about *where* rate limiting is
wired in, not a missing module. A config that only calls
`pike_check_req()` inside method-specific branches — e.g. only within
`route[REGISTRAR]` or `route[INVITE]` — never sees OPTIONS,
SUBSCRIBE, MESSAGE, PUBLISH, or any other method that doesn't hit those
branches. The fix is making sure the check in `REQINIT` (see the "core
building block" section at the top) is method-agnostic and runs before
any method dispatch, for every request:

```
route {
    route(REQINIT);   # pike_check_req() lives HERE - runs for every
                       # method before route() branches by $rm below

    if ($rm == "REGISTER") { route(REGISTRAR); return; }
    if ($rm == "INVITE")   { route(INVITE); return; }
    if ($rm == "OPTIONS")  {
        sl_send_reply("200", "OK");   # already covered by REQINIT above
        exit;
    }
    ...
}
```

The common misconfiguration this scenario exists to catch looks like
the opposite: `pike_check_req()` called *inside* `route[REGISTRAR]` and
`route[INVITE]` specifically, with the top-level `route {}` block
dispatching by method *before* ever reaching either of those — in which
case OPTIONS (and anything else not explicitly routed) never touches
the limiter at all.

Validate with `options_flood --rate 50 --duration 5 --confirm <id>`,
comparing call volume the target actually processed against your
configured `pike`/`ratelimit` threshold — it should trip exactly like
`register_flood` does at the same rate, not sail through unaffected.

## `bye_spoof`

None of the defenses above touch this: `pike`/`htable`/`ratelimit` are
all about *how much* traffic a source sends, and `bye_spoof` isn't a
volume attack at all — it's one forged in-dialog request from a source
that was never part of the call. The relevant defense is Kamailio's
`dialog` module tracking which leg a request actually belongs to, plus
strict `loose_route()` enforcement, rather than anything rate-based:

```
loadmodule "dialog.so"
modparam("dialog", "dlg_match_mode", 1)   # match dialogs on tag+Call-ID,
                                           # not just Call-ID alone

route[WITHINDLG] {
    if (!has_totag()) return;

    # loose_route() fails closed for a request that doesn't match a
    # route set Kamailio itself inserted via Record-Route on the
    # original INVITE - a guessed/replayed Call-ID+tags pair alone
    # isn't enough if the request didn't actually traverse the path
    # Kamailio expects for that dialog.
    if (!loose_route()) {
        sl_send_reply("404", "Not Found");
        exit;
    }

    if (!dlg_matches_source($si)) {
        # dlg_matches_source() is illustrative, not a real modparam -
        # the actual mechanism is comparing the request's source against
        # what the dialog module (with dlg_match_mode set to track this)
        # or your own htable-based bookkeeping recorded for this dialog's
        # legs when the INVITE was answered. The point is: validate BEFORE
        # forwarding, not after.
        xlog("L_ALERT", "ALERT: in-dialog $rm for $ci from unexpected source $si\n");
        sl_send_reply("403", "Forbidden");
        exit;
    }
    ...
}
```

The `dlg_matches_source()` call above is illustrative — Kamailio's
`dialog` module doesn't ship a modparam of exactly that name; the real
implementation is either your own `htable` recording each leg's source
IP when the dialog is confirmed (the same approach
`tests/fixtures/mock_sbc.py`'s `--reject-cross-source-bye` takes) or a
topology-hiding module (`topoh`) that replaces the Call-ID/tags/Route
set the far end sees with Kamailio-generated opaque values in the first
place — an attacker who never saw the real dialog identifiers can't
forge a request carrying them at all, which closes this gap
structurally rather than by checking source IPs after the fact.

Validate with `bye_spoof --caller-ip <ip1> --spoofer-ip <ip2> --confirm
<id>` — `hijack_bye_accepted` should read `false` once source
validation (or topology hiding) is actually wired in, versus `true`
against an unpatched config.

## Coming next

Three more Kamailio defense mechanisms are tracked as future scenarios
in [ROADMAP.md](../ROADMAP.md#next--attack-scenario-coverage) once
they're built: parser hardening against malformed SIP (the `sanity`
module / RFC 4475), TCP/TLS connection-table exhaustion
(`tcp_max_connections`), and trusted-header IP spoofing behind a
reverse proxy (`real_ip_header`). This doc will grow a section for each
as they ship.
