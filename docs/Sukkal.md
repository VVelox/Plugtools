# The Sukkal — mojo_nisaba_sso

In Sumerian myth a sukkal is the vizier of a god — the attendant who
stands at the gate, receives petitioners, announces them, and vouches
for them before the throne. Inanna had Ninshubur; Enki had Isimud.

In the world above, `mojo_nisaba_sso` is Nisaba's sukkal: an OpenID
Connect provider. Applications never read her tablets — they send the
user to the gate, the sukkal takes the introduction (password, TOTP,
passkey), consults the rolls, and returns a sealed word that the
petitioner is who they claim: an ID token signed with the client's
registered key. Clients are registered from
[the admin UI](web.md#oidc-clients--provisioning-the-sukkal) as
`oidcRelyingParty` entries under `oidcbase`; the sukkal only reads
them.

## What it speaks

Authorization code flow only, per OIDC Core 1.0, with...

- **PKCE** (RFC 7636), S256 only — and mandatory for public clients
  unless `ssoRequirePkce=0`
- **refresh tokens** (only for clients registered with the
  `refresh_token` grant), rotated on every use so a replayed token
  fails immediately; scope narrowing on refresh is honored
- **revocation** (RFC 7009) and **introspection** (RFC 7662)
- **RP-initiated logout** with post-logout redirect URIs validated
  against registration

The endpoints...

| path                                | what                                        |
|-------------------------------------|---------------------------------------------|
| `/.well-known/openid-configuration` | discovery document                          |
| `/authorize`                        | authorization endpoint                      |
| `/token`                            | token endpoint (POST)                       |
| `/userinfo`                         | claims for a bearer access token            |
| `/jwks`                             | public signing keys, all clients            |
| `/revoke`                           | token revocation                            |
| `/introspect`                       | token introspection                         |
| `/sso/login`, `/sso/totp`, `/sso/consent` | the human-facing pages                |
| `/sso/passkeys/login/start`, `.../finish` | passkey login                         |
| `/sso/logout`                       | end session                                 |

Scopes: `openid`, `profile`, `email`, `phone`, `address` — but each
client only gets what its registration allow-lists, and a request for
anything more is refused with `invalid_scope`. Claims are drawn from
the user's `inetOrgPerson` attributes, with the rarer OIDC claims
(nickname, picture, verified flags, address parts) from the
[`oidcSubject` auxiliary class](schemas.md). The ID token carries the
core identity claims; the full set is served at `/userinfo`.

## Standing at the gate

Login at the sukkal is the same trust ladder as everywhere else in
Nisaba: password (verified by binding as the user), then TOTP if
active; passkeys accepted where enrolled. All of it rate limited, per
user and per IP, including a `Token`/`TokenIp` scope guarding the token
endpoint against secret-guessing.

After authentication comes consent — which client is asking, its
registered name and logo, and the scopes requested. Consent is
remembered two ways...

- in the session, for the browser's lifetime
- durably ("remember this decision"), persisted in the grant store and
  keyed by user and client, living `ssoConsentLifetime` seconds
  (default `0`, indefinite)

`prompt=none` (silent auth) succeeds only when a fresh-enough session
and a standing consent both exist, otherwise answering
`login_required`/`consent_required` as the spec demands. `prompt=login`
and `prompt=consent` force their steps; `max_age` — from the request or
the client's registered `oidcDefaultMaxAge` — forces re-authentication
of stale sessions, and `auth_time` is always in the ID token.

## Grants and keys

Codes, access tokens, and refresh tokens are held server-side in a
shared store — SQLite by default at `/var/db/nisaba/websso.sqlite`,
mode 0600 under a 0700 directory — hashed with SHA-256, never in the
clear and never in the browser session. The shared store is what lets
the worker processes agree, makes codes and refresh tokens atomically
single-use, and keeps grants alive across restarts. Expired grants are
swept opportunistically every `ssoStorageCleanupInterval` seconds.

Signing is per client: RS256 clients get their own RSA key pair minted
at registration, HS256 clients are signed with their client secret, and
`alg=none` is never issued under any circumstance. When keys are
rotated from the admin UI, up to two old public keys stay published at
`/jwks` so tokens in flight keep verifying.

Lifetimes are config: `ssoCodeLifetime` (600), `ssoTokenLifetime`
(3600), `ssoIdTokenLifetime` (falls back to the access token lifetime),
`ssoRefreshTokenLifetime` (30 days). See
[configuration.md](configuration.md).

## Running it

```shell
# development
mojo_nisaba_sso daemon -l http://127.0.0.1:8082

# production — Hypnotoad (hot restarts, tunable; see configuration.md)
NISABA_LISTEN=http://127.0.0.1:8082 hypnotoad /usr/local/bin/mojo_nisaba_sso
```

Same rules as the other apps: `websecret`/`NISABA_SECRET` required,
boot scripts (which run Hypnotoad) in [install.md](install.md) (shipped
port 8082). Two things matter more here than elsewhere...

- **set `ssoIssuer`** to the public HTTPS base URL
  (`https://sso.example.com`, no path, no trailing slash). Everything
  in the discovery document hangs off it, and deriving it from the
  `Host` header behind a proxy is a trap. The app warns at startup if
  it is unset in production.
- **HTTPS end to end from the browser's view** — every token, code,
  and cookie crosses this wire.

## Walkthrough: Apache mod_auth_openidc

The classic use... put an arbitrary web app behind Apache and let
mod_auth_openidc do the OIDC dance against the sukkal.

First, in [the admin UI](web.md), register a confidential client with
redirect URI exactly `https://app.example.com/redirect_uri` and with
every scope the module will request (`openid profile email` below —
register `profile` and `email`, or the request dies with
`invalid_scope`). Note the generated client ID and secret.

Then...

```apache
LoadModule auth_openidc_module libexec/apache24/mod_auth_openidc.so

OIDCProviderMetadataURL https://sso.example.com/.well-known/openid-configuration
OIDCClientID            the-client-id-from-nisaba
OIDCClientSecret        the-client-secret-from-nisaba
OIDCRedirectURI         https://app.example.com/redirect_uri
OIDCCryptoPassphrase    output-of-openssl-rand-hex-32
OIDCScope               "openid profile email"
OIDCPKCEMethod          S256
OIDCRemoteUserClaim     sub

<VirtualHost *:443>
    ServerName app.example.com
    SSLEngine on
    SSLCertificateFile    /etc/ssl/certs/app.pem
    SSLCertificateKeyFile /etc/ssl/private/app.key

    # hand the user's claims to the backend as OIDC_CLAIM_* headers
    OIDCPassClaimsAs headers

    <Location />
        AuthType openid-connect
        Require valid-user
        ProxyPass        http://127.0.0.1:3000/
        ProxyPassReverse http://127.0.0.1:3000/
    </Location>

    # mod_auth_openidc owns the redirect_uri; never proxy it
    <Location /redirect_uri>
        ProxyPass !
    </Location>
</VirtualHost>
```

Claims arrive at the backend as plain-text headers
(`OIDC_CLAIM_sub`, `OIDC_CLAIM_email`, ...), which the backend trusts
blindly — so the backend must be reachable *only* through this Apache,
or a visitor can mint their own headers. When that cannot be
guaranteed, pass the signed ID token instead
(`OIDCPassIdTokenAs serialized`) and have the backend verify it against
`https://sso.example.com/jwks`.

Access can also be gated on claims directly...

```apache
<Location /staff>
    AuthType openid-connect
    Require claim email~@example\.com$
</Location>
```

For logout, register the app's post-logout URI on the client and send
the user to
`https://app.example.com/redirect_uri?logout=<url-encoded post-logout URI>`;
mod_auth_openidc clears its session, calls the sukkal's `/sso/logout`
with the ID token hint, and the sukkal validates the destination
against the registration before redirecting.

If the provider's certificate is self-signed (dev only),
`OIDCSSLValidateServer Off`.

## What it refuses

The hardening in one place: S256-only PKCE and mandatory for public
clients; exact-match redirect URIs; scope allow-lists; single-use codes
and rotated refresh tokens enforced atomically in the store; hashed
grants; no `alg=none`, ever; unsupported client auth methods refused at
the token endpoint; Origin/CSRF checks on the human-facing pages while
the server-to-server endpoints correctly stand open; rate limits on
every place a secret can be guessed; and the grant store at mode 0600
because it holds the hashes of live bearer tokens. The wider trust
model lives in [security.md](security.md).
