# Configuration

One INI file serves the module, the CLI tools, and all three web apps.
The default is `~/.config/nisabarc` (per XDG); the web apps also honor
the `NISABA_CONFIG` environment variable and a `--pt-config <path>`
flag ahead of the usual Mojolicious command. Keys live at the top of
the file (the empty/default INI section).

## Required

| key         | what                                                    |
|-------------|---------------------------------------------------------|
| `bind`      | DN to bind as, e.g. `cn=admin,dc=example,dc=com`        |
| `pass`      | password for the bind DN                                |
| `userbase`  | base DN users live under                                |
| `groupbase` | base DN groups live under                               |

The web apps additionally require `websecret` (below).

## LDAP connection

| key          | default     | what                                          |
|--------------|-------------|-----------------------------------------------|
| `server`     | `127.0.0.1` | LDAP server                                   |
| `port`       | `389`       | LDAP port                                     |
| `starttls`   | unset       | negotiate StartTLS after connecting           |
| `TLSverify`  | `none`      | `none`, `optional`, or `require`              |
| `SSLversion` | `tlsv1`     | TLS version handed to IO::Socket::SSL         |
| `SSLciphers` | `ALL`       | OpenSSL cipher string                         |

For anything not on localhost you want `starttls=1` and
`TLSverify=require`.

## Identity policy

| key            | default                | what                                              |
|----------------|------------------------|---------------------------------------------------|
| `userPrimary`  | `uid`                  | user RDN attribute: `uid`, `cn`, or `uidNumber`   |
| `groupPrimary` | `cn`                   | group RDN attribute: `cn` or `gidNumber`          |
| `UIDstart`     | `1001`                 | first UID tried when auto-allocating              |
| `GIDstart`     | `1001`                 | first GID tried when auto-allocating              |
| `NSScheck`     | `1`                    | also check local NSS for name/ID collisions       |
| `defaultShell` | `/bin/tcsh`            | shell for new users                               |
| `HOMEproto`    | `/home/%%USERNAME%%/`  | home template; `%%USERNAME%%` is substituted      |
| `userUpdate`   | `1`                    | update members' gidNumber when a group GID changes|
| `removeHome`   | `0`                    | delete the home dir when deleting a user          |
| `removeGroup`  | `1`                    | delete a user's primary group if left empty       |

## Home directory creation

Only matters where the tool runs on the machine that holds the homes.

| key            | default      | what                                  |
|----------------|--------------|---------------------------------------|
| `createHome`   | `1`          | create the home dir on user add       |
| `skeletonHome` | `/etc/skel/` | skeleton copied into new homes        |
| `chownHome`    | `1`          | chown the new home to the user        |
| `chmodHome`    | `1`          | chmod the new home                    |
| `chmodValue`   | `640`        | mode used by chmodHome                |

## Optional bases — the feature switches

| key            | default | what                                                          |
|----------------|---------|---------------------------------------------------------------|
| `netgroupbase` | empty   | base DN for `nisNetgroup` entries; empty disables netgroups   |
| `oidcbase`     | empty   | base DN for `oidcRelyingParty` entries; empty disables OIDC   |

## TOTP

| key                         | default  | what                                        |
|-----------------------------|----------|---------------------------------------------|
| `totpissuer`                | `Nisaba` | issuer name shown in authenticator apps     |
| `totpMaxScratchCodes`       | `10`     | scratch codes generated per batch           |
| `totpAdminAddScratchCodes`  | `0`      | let admins mint scratch codes in the web UI |

## Passkeys (WebAuthn)

| key                        | default     | what                                                      |
|----------------------------|-------------|-----------------------------------------------------------|
| `passkeyRpId`              | empty       | relying party ID (the domain); empty = derive per request |
| `passkeyUserVerification`  | `preferred` | `required`, `preferred`, or `discouraged`                 |

Behind a reverse proxy, set `passkeyRpId` explicitly.

## SMTP — forgot-password mail

Leaving `smtpserver` empty disables the whole forgot/reset flow.

| key          | default | what                                            |
|--------------|---------|--------------------------------------------------|
| `smtpserver` | empty   | SMTP relay                                       |
| `smtpfrom`   | empty   | From address on reset mail                       |
| `smtpport`   | `25`    | SMTP port                                        |
| `smtptls`    | empty   | empty, `starttls`, or `ssl` (implicit TLS)       |
| `smtpuser`   | empty   | SMTP auth user, optional                         |
| `smtppass`   | empty   | SMTP auth password, optional                     |

## Web apps

| key            | default | what                                                             |
|----------------|---------|-------------------------------------------------------------------|
| `websecret`    | none    | session cookie signing secret; **required**, no built-in default |
| `cookieSecure` | `1`     | mark the session cookie Secure (HTTPS only)                      |
| `adminGroup`   | `LDAPadmin` | group whose members may use the admin UI                     |

## Rate limiting

All web apps share one SQLite-backed limiter.

| key             | default                                    | what                        |
|-----------------|--------------------------------------------|-----------------------------|
| `rateLimit`     | `1`                                        | master switch               |
| `rateLimitPath` | `/var/db/nisaba/web_rate_limiter.sqlite`   | limiter database            |

Each scope has `max` failures per `window` seconds, then a `lockout`;
`*_ip` scopes are per-IP backstops that are never cleared by a success.
Override any value as `rateLimit<Scope><Param>`, e.g.
`rateLimitLoginMax=10`, `rateLimitTotpIpLockout=3600`. The scopes and
defaults...

| scope       | max | window | lockout | guards                            |
|-------------|-----|--------|---------|-----------------------------------|
| `Login`     | 8   | 900    | 900     | password attempts per user+IP     |
| `LoginIp`   | 50  | 900    | 1800    | password attempts per IP          |
| `Totp`      | 5   | 300    | 900     | TOTP codes per user+IP            |
| `TotpIp`    | 50  | 900    | 1800    | TOTP codes per IP                 |
| `Passkey`   | 30  | 900    | 900     | passkey assertions per IP         |
| `Forgot`    | 3   | 3600   | 3600    | reset-mail requests per user+IP   |
| `ForgotIp`  | 10  | 3600   | 3600    | reset-mail requests per IP        |
| `Reset`     | 20  | 3600   | 3600    | reset submissions per IP          |
| `Token`     | 10  | 900    | 900     | SSO token failures per client+IP  |
| `TokenIp`   | 100 | 900    | 1800    | SSO token failures per IP         |

Blocked requests get HTTP 429 with a `Retry-After` header; if the
limiter database is unavailable the guarded endpoints answer 503 — it
fails closed.

## SSO — the sukkal

See [Sukkal.md](Sukkal.md) for what these govern.

| key                          | default                        | what                                             |
|------------------------------|--------------------------------|---------------------------------------------------|
| `ssoIssuer`                  | empty                          | public base URL of the provider; set it in production |
| `ssoCodeLifetime`            | `600`                          | authorization code lifetime, seconds             |
| `ssoTokenLifetime`           | `3600`                         | access token lifetime, seconds                   |
| `ssoIdTokenLifetime`         | `ssoTokenLifetime`             | ID token lifetime, seconds                       |
| `ssoRefreshTokenLifetime`    | `2592000`                      | refresh token lifetime, seconds (30 days)        |
| `ssoConsentLifetime`         | `0`                            | durable consent lifetime; `0` = indefinite       |
| `ssoRequirePkce`             | `1`                            | demand S256 PKCE of public clients               |
| `ssoStorageBackend`          | `SQLite`                       | grant store backend                              |
| `ssoStoragePath`             | `/var/db/nisaba/websso.sqlite` | grant store location                             |
| `ssoStorageCleanupInterval`  | `300`                          | seconds between expired-grant sweeps; `0` = off  |

## Plugins

Each key names a comma-separated list of Perl modules run when the
matching action fires: `pluginAddUser`, `pluginAddGroup`,
`pluginDeleteUser`, `pluginDeleteGroup`, `pluginGroupAddUser`,
`pluginGroupRemoveUser`, `pluginGroupGIDchange`, `pluginUserSetPass`,
`pluginUserGECOSchange`, `pluginUserShellChange`,
`pluginUserUIDchange`, `pluginUserGIDchange`. See
`perldoc App::Nisaba` for the plugin interface and
`App::Nisaba::Plugins::Dump` for a worked example.

## Environment variables

The web apps honor these over (or in the secret's case, alongside) the
config...

| variable                | what                                       |
|-------------------------|--------------------------------------------|
| `NISABA_CONFIG`         | config file path                           |
| `NISABA_SECRET`         | session secret, if not set as `websecret`  |
| `NISABA_COOKIE_SECURE`  | override `cookieSecure`                    |
| `NISABA_RATELIMIT`      | override `rateLimit`                       |
| `NISABA_RATELIMIT_PATH` | override `rateLimitPath`                   |
| `NISABA_REQUIRE_PKCE`   | override `ssoRequirePkce`                  |

## A complete example

```ini
server=ldap.example.com
port=389
starttls=1
TLSverify=require
bind=cn=admin,dc=example,dc=com
pass=WhateverYouSetAsApassword
userbase=ou=users,dc=example,dc=com
groupbase=ou=groups,dc=example,dc=com
netgroupbase=ou=netgroups,dc=example,dc=com
oidcbase=ou=oidc,dc=example,dc=com

defaultShell=/bin/sh
HOMEproto=/home/%%USERNAME%%/
createHome=0

adminGroup=LDAPadmin
websecret=Fq4EXAMPLEsQGeneratedWithOpensslRandBase6448XkPz
cookieSecure=1

totpissuer=Example Corp
passkeyRpId=account.example.com

smtpserver=mail.example.com
smtpport=587
smtptls=starttls
smtpfrom=nisaba@example.com

ssoIssuer=https://sso.example.com
```
