# Nisaba documentation

Nisaba is the Sumerian goddess of writing and accounts — the scribe of
the gods, the lady of the lapis-lazuli tablet. In the world above she
keeps the rolls of the household in LDAP: users, groups, and netgroups,
and beside each name the marks of trust it bears — passwords, SSH
public keys, TOTP secrets, and passkeys. Her sukkal, the OpenID Connect
provider, stands at the gate and vouches for the names on her tablets
before other houses.

- [architecture.md](architecture.md) :: the module, the tablets and how
  they are laid out in LDAP, the CLI tools, the three web apps and their
  shared bones, and where Nisaba sits in the pantheon

- [install.md](install.md) :: dependencies in detail, per-OS install,
  preparing the directory server, and running the web apps at boot

- [configuration.md](configuration.md) :: the `nisabarc` reference — every
  key, its default, and the environment variable overrides

- [usage.md](usage.md) :: the CLI tools — `pluadd`, `plumod`, `plupass`,
  `plurm`, `plgadd`, `plgmod`, `plgrm`, `plgclean`, and `plngmod`

- [web.md](web.md) :: the admin UI, `mojo_nisaba` — managing users,
  groups, netgroups, and registering OIDC clients

- [selfservice.md](selfservice.md) :: the self-service portal,
  `mojo_nisaba_selfservice` — users tending their own passwords, SSH
  keys, TOTP, and passkeys

- [Sukkal.md](Sukkal.md) :: the one at the gate — `mojo_nisaba_sso`, the
  OpenID Connect provider; flows, endpoints, config, and a full Apache
  mod_auth_openidc walkthrough

- [schemas.md](schemas.md) :: the LDAP schemas that ship in `schemas/`,
  what each records, and how to load them

- [security.md](security.md) :: the trust model — what holds the admin
  bind, how the web apps guard themselves, and what to not get wrong
  behind a reverse proxy

- [examples.md](examples.md) :: copy-paste scenarios, from empty
  directory to working SSO

Also...

- `perldoc App::Nisaba`
- `perldoc mojo_nisaba`
- `perldoc mojo_nisaba_selfservice`
- `perldoc mojo_nisaba_sso`
- `perldoc pluadd` (and likewise each of the other CLI tools)
