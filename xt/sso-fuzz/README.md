# sso-fuzz — a live-fire target + crash oracle for `mojo_nisaba_sso`

Dev-only tooling to hunt for **robustness failures and exploitable defects** in
the `App::Nisaba::WebSSO` provider (`src_bin/mojo_nisaba_sso`) in an automated
way — crashes, 500s, unhandled Perl exceptions, DoS/ReDoS, and injection — by
running it as a real network listener and watching what breaks while an external
fuzzer (`ffuf`, `wfuzz`, Burp, curl loops, a raw fuzzer, …) hammers it.

This is **not** an OIDC conformance suite (the `t/web-sso*.t` tests already cover
protocol logic). Its value is the network layer the in-process `Test::Mojo`
tests can't reach: a real socket and multiple worker processes.

> ⚠️ Dev/test only. Seeds throwaway cleartext credentials and drops the session
> cookie `Secure` flag so it works over plain HTTP. Never run against anything
> real.

## The pieces

| Script | Role |
| --- | --- |
| `sso-fuzz-target.pl` | Boots the provider as a long-lived **prefork** HTTP listener with a seeded backend. |
| `sso-fuzz-supervisor.pl` | The **crash oracle**: launches the target, waits for readiness, then watches for breakage and writes a findings report. |
| `probe-check.pl` | Standalone smoke test of the SSO abuse checks (Mojo::UserAgent) — the same assertions as `xt/sso-fuzz.t`, outside the test harness. |

You normally run only the supervisor; it launches the target for you.

## As author tests (`prove xt/`)

The security probes are also wired as Test::More tests so they run inside the
Perl test framework:

```sh
prove -l xt/sso-fuzz.t          # mock backend
prove -l xt/sso-fuzz-slapd.t    # real OpenLDAP (skips if slapd/Test::OpenLDAP absent)
prove -lr xt/                   # both
```

Each boots `xt/sso-fuzz/sso-fuzz-target.pl` as a real prefork daemon on an
ephemeral port and asserts open-redirect / LDAP-injection / header-injection /
parser-abuse resistance as subtests (shared logic in `xt/lib/NisabaSSOFuzz.pm`).
They are author/extended tests — not part of the default `make test` run — and
skip cleanly when Mojolicious, `DBD::SQLite`, or `Test::OpenLDAP` are missing.

## Backends

* `--backend mock` (default) — monkey-patched fake LDAP (same shape as
  `t/web-sso.t`). No external services, deterministic, fast. Right for
  HTTP-layer / Perl-code-path bugs: malformed or oversized params, JSON bombs on
  the passkey endpoint, malformed JWT `id_token_hint`, bad Base64 in PKCE/Basic
  auth, crashes, ReDoS.
* `--backend slapd` — a **real** OpenLDAP via `Test::OpenLDAP`
  (`t/lib/NisabaSlapdTest.pm`). Required for anything that reaches an LDAP search
  filter — **LDAP injection** on the login `user` / `client_id` — which the mock
  backend renders structurally invisible (its stub does a string `eq`). Needs
  `slapd` and `Test::OpenLDAP` installed.

## Usage

```sh
# mock backend, auto-picked port, run until Ctrl-C
perl xt/sso-fuzz/sso-fuzz-supervisor.pl

# real-LDAP backend, flag memory blowups, verbose target logging
perl xt/sso-fuzz/sso-fuzz-supervisor.pl --backend slapd --mem-limit 800 --log-level debug

# fixed port, enable the app's own rate limiter, stop after 10 minutes
perl xt/sso-fuzz/sso-fuzz-supervisor.pl --port 3000 --rate-limit 1 --duration 600
```

The supervisor prints a `READY` banner with the URL once discovery answers.
Point your fuzzer at it, then Ctrl-C to stop and get a report. Seeded
credentials (printed in the target banner):

* user `alice` / `correct`
* confidential client `conf` / `s3cret` (`client_secret_basic`, HS256),
  redirect `https://fuzz.example.com/callback`
* (mock only) public client `pub` (PKCE S256, RS256),
  redirect `https://fuzz.example.com/pub-callback`
* (mock only) CSRF token `sso-fuzz-csrf` (header `X-CSRF-Token`) for form POSTs

## What the oracle flags

| Severity | Signal |
| --- | --- |
| critical | target process exits unexpectedly; health probe cannot connect / discovery unreachable |
| high | discovery non-200; probe hangs past `--hang-budget` (ReDoS/DoS); prefork worker death; RSS over `--mem-limit` |
| medium | Perl/runtime errors in the log (`Can't locate`, `Undefined subroutine`, `died`, DBI/LDAP errors, …); app-logged `[error]` |
| low | Perl warnings (uninitialised value, wide character, …) |

Output: a live stream of first-seen findings, a summary table on shutdown, and a
machine-readable `sso-fuzz-report.json` (path via `--report`). Exit code is `2`
if any critical finding fired, `1` if any finding fired, `0` if clean. The raw
merged target log is kept at `--log` (default `./sso-fuzz-target.log`).

## Active abuse checks — `probe-check.pl`

`probe-check.pl` drives itself off the target's OIDC discovery document and
actively asserts four exploitable-defect classes, printing PASS/FAIL per check
and exiting non-zero on any FAIL. It needs only `Mojo::UserAgent` and is handy as
a fast "is this target secure?" check outside the test harness:

| Check | What it does | Flags |
| --- | --- | --- |
| open redirect | unregistered `redirect_uri` on `/authorize` and `post_logout_redirect_uri` on `/sso/logout` | a 3xx `Location` to the attacker host (CWE-601) |
| header injection | CR/LF in a reflected param (`state`) on the error redirect | the payload splitting into a *new response header* — value-only reflection is not flagged (CWE-113) |
| LDAP injection | filter metacharacters in `client_id` (and the login `user`) | a wildcard/injection that resolves to a real client / bypasses auth the way a random-unknown value never does (CWE-90) |
| parser abuse | malformed JSON (passkey finish), bad Base64 Basic auth, malformed `id_token_hint`, oversized params | an HTTP 500 or a dropped connection instead of a clean 4xx |

```sh
perl xt/sso-fuzz/probe-check.pl --host 127.0.0.1 --port <port>
```

Against the seeded harness target it reports `pass=15 fail=0` (the target is
expected to be secure; a FAIL is a real defect). The same assertions run as
Test::More subtests via `prove -l xt/sso-fuzz.t` (see above).

## Driving it with an external fuzzer

Once `READY`, point any HTTP fuzzer at the printed URL and watch the supervisor's
output/report for anything the traffic knocks loose, e.g.:

```sh
# long / malformed paths and query values
ffuf -u 'http://127.0.0.1:<port>/authorize?client_id=conf&scope=FUZZ' -w wordlist.txt
# form-field fuzzing against the token endpoint
wfuzz -d 'grant_type=FUZZ&code=FUZZ' -z file,wordlist.txt http://127.0.0.1:<port>/token
```

## Notes / limits

* `--rate-limit` defaults **off** so payloads reach parsing code instead of
  being throttled at 429. Turn it on to exercise the limiter itself.
* The slapd backend's seeded client is HS256 (`addOIDCClient` does not generate
  RSA keys), which is enough to complete the code+token flow; use the mock
  backend's `pub` client for public-client / PKCE paths.
* The oracle detects breakage; it does not attribute it to a specific request.
  Correlate findings with your fuzzer's request log and the target log by
  timestamp.
