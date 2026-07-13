# Security considerations

## The bind DN is the real power

Everything — CLI and all three web apps — operates through the `bind`
DN in the config, which can write every user, group, and password in
its bases. So...

- the config file holds that password and the session secret; keep it
  mode 600, owned by what runs the apps
- the LDAP connection defaults to plaintext with `TLSverify=none`; for
  anything not on localhost set `starttls=1` and `TLSverify=require`
- the web apps *authorize* narrowly (admin group membership, or
  own-entry-only in the portal), but a compromise of the app process
  itself yields the full bind. Treat the hosts running them
  accordingly.

Password *verification* in the web apps is the one thing not done with
the admin bind: the user's own DN and password are bound to the
directory, so the apps never judge hashes themselves and the
directory's own policy (lockouts, ppolicy overlays) applies.

## The session secret

`websecret` (or `NISABA_SECRET`) signs every session cookie. There is
deliberately no default and the apps refuse to start without one —
generate it (`openssl rand -base64 48`) rather than inventing it.
Sessions are signed, not encrypted: they cannot be forged without the
secret, but their contents (a username) are readable. Rotating the
secret invalidates every live session, which is also the recovery move
if it ever leaks. Note it is also an HMAC ingredient in the
self-service reset tokens — same blast radius.

## What the web apps do for themselves

- **CSRF, twice** — state-changing requests must present an
  Origin/Referer matching the app's own origin, *and* the per-session
  synchronizer token (form field or `X-CSRF-Token` header), compared in
  constant time. The SSO's server-to-server endpoints (`/token`,
  `/userinfo`, and kin) are exempt, as they must be — they authenticate
  with client credentials and bearer tokens instead.
- **rate limiting, everywhere a secret can be guessed** — logins, TOTP
  codes, passkey assertions, reset mail, reset submissions, and the SSO
  token endpoint. Per-user limits clear on success; per-IP backstops do
  not, so one valid credential cannot launder a spray. The limiter
  stores SHA-256 hashes, never raw usernames or IPs, and if its
  database is unreachable the guarded endpoints answer 503 — failing
  closed.
- **cookies** — `SameSite=Lax`, `Secure` unless `cookieSecure=0`. Only
  set `cookieSecure=0` when browsers genuinely reach the app over plain
  HTTP, meaning development.
- **LDAP filter escaping** — user-supplied names pass through
  `escape_filter_value` before touching a filter.
- **redaction** — the admin UI's entry viewer redacts password
  attributes; OIDC client credentials are shown once at creation rather
  than parked in the session.

The SSO provider's own long list — mandatory S256 PKCE, exact redirect
URIs, single-use codes, rotated refresh tokens, hashed grants, no
`alg=none` — lives in [Sukkal.md](Sukkal.md#what-it-refuses).

## Reset mail

The forgot-password flow only exists if `smtpserver` is set. It never
confirms whether an account exists, its tokens die in an hour, and all
of them die the moment the password changes (they are bound to a
fingerprint of the current password). It is also the most tightly
rate-limited feature, since each request emits mail. The mail itself is
plaintext SMTP unless `smtptls` says otherwise — say otherwise.

## Behind a reverse proxy, three traps

- **client IPs** — the rate limiter keys on the connection's remote
  address. If everything arrives from the proxy's IP, per-IP backstops
  throttle the proxy, i.e. everyone. Make sure the app sees real client
  addresses.
- **`passkeyRpId`** — WebAuthn credentials are scoped to the RP ID,
  derived from the `Host` header unless pinned. Pin it.
- **`ssoIssuer`** — the SSO derives nothing correctly from `Host`
  behind a proxy; set the public URL explicitly.

## The state on disk

`/var/db/nisaba` holds the rate-limiter database and the SSO grant
store. The grant store contains hashes of live bearer tokens and is
kept at mode 0600 in a 0700 directory — leave it that way, and give
each app instance its own rather than sharing over NFS. The rate
limiter contains only hashed keys and counters, but there is no reason
to be generous with it either.

## What Nisaba does not do

No LDAP ACL management — the directory's own ACLs decide what the bind
DN and users binding as themselves may do, and they are your last line;
set them so users can bind but not read each other's `totpSecret`,
`passkeyCredential`, or `userPassword` attributes. No password quality
enforcement — that too belongs to the directory server. And no audit
log of its own beyond the web apps' request logs; if you need one, the
plugin hooks are the place to hang it.
