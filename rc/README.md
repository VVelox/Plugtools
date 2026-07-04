# Service files for the App::Nisaba web applications

Service definitions for the three App::Nisaba web front ends:

| Service                   | Application                  | Default port |
|---------------------------|------------------------------|--------------|
| `mojo_nisaba`             | LDAP admin web interface     | 8080         |
| `mojo_nisaba_selfservice` | Self-service portal          | 8081         |
| `mojo_nisaba_sso`         | OpenID Connect SSO provider  | 8082         |

```
rc/
├── systemd/   # Linux (systemd) unit files + sysusers/tmpfiles helpers
└── freebsd/   # FreeBSD rc.d scripts
```

All three run the Mojolicious `prefork` server in the foreground and log to the
platform's journal/syslog. Configuration is taken from the `nisabarc` file
pointed to by `NISABA_CONFIG` (LDAP connection, `websecret`, `oidcbase`, the
`sso*` keys, etc.); the listen address and a couple of environment variables are
set per-service as shown below.

**A session secret is required.** Each service signs its session cookies — which
carry every authentication decision — with the secret. Set `websecret` in
`nisabarc` (or `NISABA_SECRET` in the environment) to a long random string, e.g.
`openssl rand -base64 48`. The services **refuse to start** without one rather
than fall back to a predictable default. Use the same value across all three
workers of a service (and keep it stable across restarts) so existing sessions
remain valid.

**Session cookies are marked `Secure` by default**, so browsers only send them
over HTTPS — serve these behind TLS (directly or via a TLS-terminating reverse
proxy with `MOJO_REVERSE_PROXY=1`). For plain-HTTP development or testing, set
`cookieSecure=0` in `nisabarc` (or `NISABA_COOKIE_SECURE=0` in the environment)
to drop the flag. Cookies are always `SameSite=Lax`.

`mojo_nisaba_sso` keeps its OIDC authorization codes and access tokens in a
SQLite database at `/var/db/nisaba` (`ssoStoragePath`). All three services also
keep a small brute-force **rate-limiter** database there (see below); apart from
that they are network-only. The service units grant write access to
`/var/db/nisaba` and otherwise run with a read-only filesystem.

**Brute-force rate limiting** is on by default on every auth endpoint (login,
TOTP challenge, passkey login, and the self-service forgot/reset flows). It
counts failures per `(username, client-IP)` with a higher per-IP backstop and
locks a key out once a threshold is reached. State lives in
`/var/db/nisaba/web_rate_limiter.sqlite` (`rateLimitPath`). It **fails closed**:
if that database can't be written, guarded endpoints return `503` — so the
service user must be able to write `/var/db/nisaba` (the units and rc scripts
arrange this). Disable it with `rateLimit=0` (or `NISABA_RATELIMIT=0`); tune any
scope with `rateLimit<Scope><Max|Window|Lockout>` keys (scopes: `Login`,
`LoginIp`, `Totp`, `TotpIp`, `Passkey`, `Reset`, `Forgot`, `ForgotIp`). Behind a
reverse proxy, set `MOJO_REVERSE_PROXY=1` so the client IP is taken from
`X-Forwarded-For` rather than the proxy.

`mojo_nisaba_sso` **requires PKCE (S256) from public clients** — those registered
with `token_endpoint_auth_method=none`, which cannot authenticate at the token
endpoint. This defends against authorization-code interception and is on by
default. To allow legacy public clients that cannot do PKCE, set `ssoRequirePkce=0`
in `nisabarc` (or `NISABA_REQUIRE_PKCE=0` in the environment) — strongly
discouraged. Confidential clients are unaffected.

**ID tokens are always signed.** Each client must be registered with an
`RS256` or `HS256` signing algorithm; the provider refuses to issue an unsigned
(`alg=none`) token and returns `server_error` for a client that has no usable
signing key. The admin UI only offers RS256/HS256, and discovery advertises only
those.

By default the services speak plain HTTP and are meant to sit behind a
TLS-terminating reverse proxy. To terminate TLS in the app itself instead, see
[Serving HTTPS directly](#serving-https-directly) below.

The examples assume the executables are installed in `/usr/local/bin`. If
`make install` placed them elsewhere (e.g. `/usr/bin`), adjust the paths.

---

## Linux (systemd)

1. Install the unit files:

   ```sh
   install -m 0644 systemd/mojo_nisaba.service \
                   systemd/mojo_nisaba_selfservice.service \
                   systemd/mojo_nisaba_sso.service \
                   /etc/systemd/system/
   ```

2. Create the `nisaba` service user and the SSO state directory:

   ```sh
   install -m 0644 systemd/nisaba.sysusers.conf  /etc/sysusers.d/nisaba.conf
   install -m 0644 systemd/nisaba.tmpfiles.conf  /etc/tmpfiles.d/nisaba.conf
   systemd-sysusers
   systemd-tmpfiles --create
   ```

   (Or create them by hand: `useradd --system --home-dir /var/db/nisaba \
   --shell /usr/sbin/nologin nisaba` and `install -d -o nisaba -g nisaba \
   -m 0700 /var/db/nisaba`.)

3. Point each service at your `nisabarc`. Either edit `NISABA_CONFIG=` in the
   unit, or drop an optional environment file (overrides the unit defaults):

   ```sh
   install -d /usr/local/etc/nisaba
   cat > /usr/local/etc/nisaba/mojo_nisaba_sso.env <<'EOF'
   LISTEN=http://*:8082
   NISABA_CONFIG=/usr/local/etc/nisabarc
   # NISABA_SECRET=...            # REQUIRED unless websecret is set in nisabarc
   # MOJO_REVERSE_PROXY=1         # only behind a trusted reverse proxy
   EOF
   ```

4. Enable and start:

   ```sh
   systemctl daemon-reload
   systemctl enable --now mojo_nisaba_sso.service
   systemctl status mojo_nisaba_sso.service
   journalctl -u mojo_nisaba_sso -f
   ```

### Notes

- **Reverse proxy / TLS.** These units listen on plain HTTP on a high port,
  intended to sit behind a TLS-terminating reverse proxy (see the Apache
  example in `mojo_nisaba_sso`'s POD). When proxied, set `MOJO_REVERSE_PROXY=1`
  so absolute URLs (the OIDC issuer, redirect URIs) are generated correctly —
  and set `ssoIssuer` in `nisabarc` to the public URL. Do **not** set
  `MOJO_REVERSE_PROXY` if the app is reachable by clients directly.
- **Binding a privileged port directly** (e.g. `:443`): set `LISTEN`
  accordingly and uncomment the `AmbientCapabilities`/`CapabilityBoundingSet`
  lines in the unit.
- **Hardening.** The units are sandboxed (`ProtectSystem=strict`,
  `MemoryDenyWriteExecute`, a `@system-service` syscall filter, etc.). If an XS
  module misbehaves under the sandbox, relax the relevant directive (most often
  `MemoryDenyWriteExecute=` or `SystemCallFilter=`).

---

## FreeBSD (rc.d)

1. Install the rc.d scripts:

   ```sh
   install -m 0555 freebsd/mojo_nisaba \
                   freebsd/mojo_nisaba_selfservice \
                   freebsd/mojo_nisaba_sso \
                   /usr/local/etc/rc.d/
   ```

2. Enable and configure in `/etc/rc.conf` (knobs are documented at the top of
   each script):

   ```sh
   sysrc mojo_nisaba_sso_enable="YES"
   sysrc mojo_nisaba_sso_config="/usr/local/etc/nisabarc"
   # sysrc mojo_nisaba_sso_listen="http://*:8082"
   # sysrc mojo_nisaba_sso_user="www"
   ```

3. Start:

   ```sh
   service mojo_nisaba_sso start
   service mojo_nisaba_sso status
   ```

### Notes

- Each service runs as `mojo_<name>_user` (default `www`); a dedicated,
  unprivileged user is recommended. `daemon(8)` supervises the process,
  restarts it on exit (5 s delay), and routes its output to syslog.
- The `mojo_nisaba_sso` script creates `/var/db/nisaba` (owned by the service
  user) for the SQLite grant store on start.
- The reverse-proxy / `MOJO_REVERSE_PROXY` guidance above applies here too; set
  it via the environment if needed (e.g. in an `rc.conf.d` wrapper) or run
  behind a proxy and set `ssoIssuer`.

---

## Serving HTTPS directly

The services default to plain HTTP on a high port, intended to sit behind a
TLS-terminating reverse proxy (recommended for production — see the Apache
example in `mojo_nisaba_sso`'s POD). Mojolicious can also terminate TLS itself:
give it an `https://` listen URL with `cert` and `key` query parameters.

```
https://*:8443?cert=/usr/local/etc/nisaba/tls/server.crt&key=/usr/local/etc/nisaba/tls/server.key
```

- Requires **`IO::Socket::SSL`** to be installed (it is not a hard dependency of
  App::Nisaba; install it only if you terminate TLS in the app).
- `cert` and `key` are PEM files and must be readable by the service user.
  Under systemd they must also be on a normal system path — `ProtectHome=` hides
  home directories from the sandbox.
- An `https://` URL with **no** `cert`/`key` makes Mojolicious fall back to a
  built-in self-signed certificate. That is for local testing only — never
  production.
- Other supported query parameters: `ca` (verify client certificates against
  this CA file), `ciphers`, and `version` (e.g. `TLSv1.2`). See the
  `Mojo::Server::Daemon` documentation for the full list.
- Binding `:8443` needs no special privileges. To bind `:443` directly, grant
  `CAP_NET_BIND_SERVICE` (systemd: uncomment the `AmbientCapabilities` /
  `CapabilityBoundingSet` lines in the unit).

Set it like any other listen URL:

- **systemd** — set `LISTEN` in the unit or the environment file. systemd passes
  `${LISTEN}` as a single argument, so the `&` needs no escaping:

  ```
  LISTEN=https://*:8443?cert=/usr/local/etc/nisaba/tls/server.crt&key=/usr/local/etc/nisaba/tls/server.key
  ```

- **FreeBSD** — set `mojo_<name>_listen` in `rc.conf`, keeping the value inside
  the double quotes so the shell does not treat the `&` as an operator (the
  rc.d scripts also quote it internally when passing it to the server):

  ```sh
  sysrc mojo_nisaba_sso_listen="https://*:8443?cert=/usr/local/etc/nisaba/tls/server.crt&key=/usr/local/etc/nisaba/tls/server.key"
  ```

Whether the app terminates TLS itself or sits behind a proxy, set `ssoIssuer`
in `nisabarc` to the public `https://` URL so the OIDC issuer and
redirect/endpoint URLs are correct.
