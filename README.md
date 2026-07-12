# App-Nisaba
tools for managing user/groups in LDAP

Besides the CLI tools, the dist ships three Mojolicious web apps:

- `mojo_nisaba` — admin UI (users, groups, netgroups, OIDC client registration)
- `mojo_nisaba_selfservice` — user self-service portal (password, TOTP, passkeys)
- `mojo_nisaba_sso` — OpenID Connect provider (authorization code flow with
  PKCE, refresh tokens, revocation/introspection, RP-initiated logout).
  See `perldoc mojo_nisaba_sso` for setup, config keys, and a full Apache
  mod_auth_openidc walkthrough.
