# Architecture

Everything in the dist is a different hand holding the same stylus.
`App::Nisaba` is the module that actually reads and writes the
directory; the CLI tools, the admin UI, the self-service portal, and
the SSO provider all drive it. One INI config, by default
`~/.config/nisabarc`, serves them all — see
[configuration](configuration.md).

## The tablets

Nisaba keeps three kinds of entry, each under its own base DN...

- **users** under `userbase` — `posixAccount` entries, optionally
  raised to `inetOrgPerson` for the human details (mail, phone, title,
  room, and so on). The RDN attribute is `userPrimary` (default `uid`,
  may be `cn` or `uidNumber`).
- **groups** under `groupbase` — `posixGroup` entries with `memberUid`
  members. RDN attribute is `groupPrimary` (default `cn`, may be
  `gidNumber`).
- **netgroups** under `netgroupbase` — `nisNetgroup` entries carrying
  `nisNetgroupTriple` values of the form `(host,user,domain)` and
  `memberNisNetgroup` references to other netgroups. Optional; leaving
  `netgroupbase` unset disables the feature everywhere.

When a user or group is added without an explicit UID/GID, Nisaba scans
the directory (and, with `NSScheck` on, the local NSS databases too)
and takes the first free number at or above `UIDstart`/`GIDstart`.
Passwords are set through the LDAP password-modify extension, so the
directory server does the hashing with whatever scheme it is configured
for.

## The marks of trust

Beside the names, auxiliary objectClasses record what each account may
authenticate with. Each wants a schema loaded into the directory server
(see [schemas](schemas.md)) and each is optional...

- `ldapPublicKey` / `sshPublicKey` — SSH public keys, the standard
  openssh-lpk schema
- `totpUser` — TOTP secret, status, algorithm/period/digits, and
  single-use scratch codes; `mfaGroup` lets a group demand MFA of its
  members
- `passkeyUser` — WebAuthn/FIDO2 credentials, one encoded
  `passkeyCredential` value per passkey
- `oidcSubject` — extra OIDC claims (nickname, picture, verified flags,
  and so on) for users, and `oidcRelyingParty` entries under `oidcbase`
  for registered OIDC clients

## The tools

The CLI tools are thin wrappers over the module, one action apiece,
carrying their names from the dist's former life as Plugtools:
`pluadd`, `plumod`, `plupass`, `plurm` for users; `plgadd`, `plgmod`,
`plgrm`, `plgclean` for groups; `plngmod` for netgroups. See
[usage](usage.md). On error they exit with the App::Nisaba error
code.

The module also has plugin hooks — `pluginAddUser`,
`pluginDeleteGroup`, and kin in the config name Perl modules to run
when the matching action fires, so things like mail spool creation can
be hung off account changes. `App::Nisaba::Plugins::Dump` ships as a
debugging example.

## The three web apps

All three are Mojolicious apps sharing the same bones
(`App::Nisaba::WebUtil` and friends)...

- a session cookie signed with `websecret` (the apps refuse to start
  without one — there is deliberately no default), `SameSite=Lax`,
  `Secure` unless `cookieSecure=0`
- two-layer CSRF protection: an Origin/Referer check on every
  state-changing request, then a per-session synchronizer token compared
  in constant time
- a shared SQLite-backed rate limiter (default
  `/var/db/nisaba/web_rate_limiter.sqlite`) with per-user limits and
  per-IP backstops on login, TOTP, passkey, password-reset, and token
  endpoints; it hashes what it stores and fails closed if the database
  is unreachable
- templates and static assets resolved from the dist share directory
  via `File::ShareDir`

They differ in who they serve...

- **`mojo_nisaba`** (admin UI, rc default port 8080) — full management
  of users, groups, netgroups, and OIDC client registration. Only
  members of the `adminGroup` group (default `LDAPadmin`) may log in;
  login is password, then TOTP if enrolled, with passkeys also
  supported. See [web](web.md).
- **`mojo_nisaba_selfservice`** (rc default port 8081) — any user may
  log in, and only to tend their own entry: password change,
  forgot-password by mail (if SMTP is configured), SSH keys, TOTP
  enrollment, passkeys. Password verification is done by binding to
  LDAP *as the user*, not by comparing hashes. See
  [selfservice](selfservice.md).
- **`mojo_nisaba_sso`** (rc default port 8082) — the sukkal; an OpenID
  Connect provider doing authorization code flow with PKCE, refresh
  token rotation, revocation, introspection, and RP-initiated logout.
  Grants live hashed in a shared store (SQLite by default,
  `/var/db/nisaba/websso.sqlite`) so the worker processes agree and
  restarts do not log the world out. See [Sukkal](Sukkal.md).

The admin UI writes the tablets, the self-service portal lets each name
tend its own line, and the sukkal reads them aloud at the gate — none
of them keep state of their own beyond sessions, grants, and rate-limit
counters; LDAP is the single source of truth.

## Where she sits in the pantheon

The rest of the household watch the network — Lilith keeps the annals
of alerts, Baphomet accuses, Ereshkigal banishes, Lamashtu hoards the
packets, and Virani divines them back out. Nisaba is not in that kill
chain at all. She is the census: the accounts the others run as, the
groups that gate their sockets (Ereshkigal's `authed_groups`, for one,
is exactly the kind of group Nisaba keeps), and the sign-on in front of
whatever web frontends the household raises. She needs none of them and
none of them require her — but a household needs its scribe.
