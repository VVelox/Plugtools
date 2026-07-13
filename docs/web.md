# The admin UI — mojo_nisaba

Everything the CLI tools do and more, from a browser. It is a
Mojolicious app, so all the usual server commands work...

```shell
# development
mojo_nisaba daemon -l http://127.0.0.1:8080

# production
mojo_nisaba prefork -l http://127.0.0.1:8080

# with an explicit config
mojo_nisaba prefork --pt-config /usr/local/etc/nisabarc -l http://127.0.0.1:8080
```

It refuses to start without a session secret — `websecret` in the
config or `NISABA_SECRET` in the environment. rc scripts and systemd
units for boot are covered in [install.md](install.md); the shipped
ones listen on port 8080.

## Who may enter

Only members of the `adminGroup` group (default `LDAPadmin`) may log
in — membership by `memberUid` or by primary GID. Login is password
first; if the account has TOTP active a code is demanded next, and
accounts with passkeys may sign in with those instead. All three paths
are rate limited per user and per IP (see
[configuration.md](configuration.md)), and every state-changing request
passes the two-layer CSRF checks described in
[security.md](security.md).

## Users

The user list, and per user...

- the posixAccount basics: GECOS, shell, home, UID, primary GID, and
  password set/remove
- group membership — add to and remove from any number of groups
- promotion to `inetOrgPerson`, unlocking the human details: `cn`,
  `sn`, `givenName`, `displayName`, mail, telephone and mobile numbers,
  title, room number, employee number and type, preferred language,
  URIs, descriptions, postal addresses — multi-valued ones added and
  removed a value at a time
- SSH public keys — enable `ldapPublicKey` on the entry, then add and
  remove `sshPublicKey` values
- TOTP — enable, generate a secret (rendered as a QR code plus setup
  URL), verify to activate, and administratively adjust status,
  algorithm, period, digits, or remove the secret; scratch codes may be
  minted here only if `totpAdminAddScratchCodes=1`
- passkeys — enable passkey storage for the account, see what
  credentials it carries (nickname, transports, timestamps), and revoke
  them; enrollment itself is done by the user in the
  [self-service portal](selfservice.md)
- deletion, with per-action say over `removeHome` and `removeGroup`

Viewing an entry shows its LDAP source with password attributes
redacted.

## Groups and netgroups

Groups: create (GID auto-allocated or explicit), change GID (with
optional member primary-GID update), description, membership, delete,
and a "clean" action that does what [plgclean](usage.md#plgclean) does
across all groups.

Netgroups (shown only when `netgroupbase` is set): create with any
number of `(host,user,domain)` triples and member netgroups, then edit
descriptions, triples, and members, or delete.

## OIDC clients — provisioning the sukkal

Shown only when `oidcbase` is set. This is where relying parties are
registered for [the SSO provider](Sukkal.md); the SSO itself has no
registration endpoint.

Creating a client generates its credentials...

- a random `clientId`
- for confidential clients, a random client secret
- for RS256 clients, an RSA signing key pair

...and records the policy the SSO will enforce:

- **type** — confidential or public; public clients get no secret, must
  use `none` at the token endpoint, and are forced to PKCE
- **redirect URIs** — exact-match, one or more; no wildcards
- **scopes** — an allow-list; the SSO refuses any request for a scope
  not registered here, so register everything the RP will ask for
  (`openid` is always permitted)
- **grant types** — `authorization_code`, plus `refresh_token` if the
  client should get refresh tokens
- **token endpoint auth** — `client_secret_basic`,
  `client_secret_post`, or `none`
- **ID token signing** — `RS256` (per-client key pair, default) or
  `HS256` (signed with the client secret; unavailable to public
  clients)
- **display metadata** for the consent screen — name, homepage, logo,
  policy, and ToS URIs, contacts
- **behavior** — `defaultMaxAge`, post-logout redirect URIs, and the
  rarer registration attributes from the [oidc schema](schemas.md)

The client page can regenerate the secret and rotate the signing keys;
on rotation the old public keys (up to two) stay published at the JWKS
endpoint so already-issued tokens keep verifying through the overlap.

Client creation refuses combinations the SSO would refuse at runtime —
a public client asking for HS256, unsupported auth methods, and the
like — so a client that saves is a client that works.

## Behind a proxy

Terminate TLS in front of it and pass `Host` through faithfully — the
passkey relying-party ID is derived from the request host unless
`passkeyRpId` pins it, and pinning it is recommended. If the hop from
proxy to app is plain HTTP but browsers reach the proxy over HTTPS,
leave `cookieSecure` alone (the cookie is still only ever sent over
HTTPS from the browser's point of view).
