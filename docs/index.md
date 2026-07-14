# Nisaba documentation

Nisaba is the Sumerian goddess of writing and accounts — the scribe of
the gods, the lady of the lapis-lazuli tablet. In the world above she
keeps the rolls of the household in LDAP: users, groups, and netgroups,
and beside each name the marks of trust it bears — passwords, SSH
public keys, TOTP secrets, and passkeys. Her sukkal, the OpenID Connect
provider, stands at the gate and vouches for the names on her tablets
before other houses.

- [architecture](architecture.md) :: the module, the tablets and how
  they are laid out in LDAP, the CLI tools, the three web apps and their
  shared bones, and where Nisaba sits in the pantheon

- [install](install.md) :: dependencies in detail, per-OS install,
  preparing the directory server, and running the web apps at boot

- [configuration](configuration.md) :: the `nisabarc` reference — every
  key, its default, and the environment variable overrides

- [usage](usage.md) :: the CLI tools — `pluadd`, `plumod`, `plupass`,
  `plurm`, `plgadd`, `plgmod`, `plgrm`, `plgclean`, and `plngmod`

- [web](web.md) :: the admin UI, `mojo_nisaba` — managing users,
  groups, netgroups, and registering OIDC clients

- [selfservice](selfservice.md) :: the self-service portal,
  `mojo_nisaba_selfservice` — users tending their own passwords, SSH
  keys, TOTP, and passkeys

- [Sukkal](Sukkal.md) :: the one at the gate — `mojo_nisaba_sso`, the
  OpenID Connect provider; flows, endpoints, config, and a full Apache
  mod_auth_openidc walkthrough

- [schemas](schemas.md) :: the LDAP schemas that ship in `schemas/`,
  what each records, and how to load them

- [security](security.md) :: the trust model — what holds the admin
  bind, how the web apps guard themselves, and what to not get wrong
  behind a reverse proxy

- [examples](examples.md) :: copy-paste scenarios, from empty
  directory to working SSO

Also...

- [App::Nisaba](https://metacpan.org/pod/App::Nisaba)
- [mojo_nisaba](https://metacpan.org/pod/mojo_nisaba)
- [mojo_nisaba_selfservice](https://metacpan.org/pod/mojo_nisaba_selfservice)
- [mojo_nisaba_sso](https://metacpan.org/pod/mojo_nisaba_sso)
- [pluadd](https://metacpan.org/pod/pluadd) (and likewise each of the other CLI tools)
