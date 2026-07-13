# App-Nisaba

Nisaba is the Sumerian goddess of writing and accounts — the scribe of
the gods, the lady of the lapis-lazuli tablet. Before anything can be
judged, granted, or taken away, someone must keep the rolls of who
exists, what house they belong to, and what marks of trust they carry.
That is Nisaba's work, and scribes closed their tablets with her
praise.

In the world above, Nisaba is a user, group, and netgroup manager for
LDAP. She is the record keeper of the
[LilithSec](https://github.com/LilithSec) pantheon:
[Lilith](https://github.com/LilithSec/Lilith) knows,
[Baphomet](https://github.com/LilithSec/Baphomet) accuses,
[Ereshkigal](https://github.com/LilithSec/Ereshkigal) punishes,
[Lamashtu](https://github.com/LilithSec/Lamashtu) remembers,
[Virani](https://github.com/LilithSec/Virani) reads — and Nisaba
writes. On her tablets live the posixAccount, posixGroup, and
nisNetgroup entries of the household, and beside the names she records
the marks each bears... passwords, SSH public keys, TOTP secrets, and
passkeys.

The dist is one Perl module, a set of CLI tools, and three Mojolicious
web apps...

- `App::Nisaba` — the module all of the below wield; user/group/netgroup
  CRUD, UID/GID allocation, password handling, and plugin hooks
- `pluadd`, `plumod`, `plupass`, `plurm`, `plgadd`, `plgmod`, `plgrm`,
  `plgclean`, `plngmod` — the CLI tools, carrying their names from this
  dist's former life as Plugtools
- `mojo_nisaba` — the admin UI... users, groups, netgroups, and OIDC
  client registration
- `mojo_nisaba_selfservice` — the user self-service portal... password
  changes and resets, SSH keys, TOTP enrollment, passkeys
- `mojo_nisaba_sso` — her sukkal, an OpenID Connect provider; in the old
  stories a sukkal is the vizier who stands at the gate and vouches for
  petitioners before the god, and that is what single sign-on is... see
  [docs/Sukkal.md](docs/Sukkal.md)

Everything reads one INI config, by default `~/.config/nisabarc`...

```ini
server=ldap.example.com
bind=cn=admin,dc=example,dc=com
pass=WhateverYouSetAsApassword
userbase=ou=users,dc=example,dc=com
groupbase=ou=groups,dc=example,dc=com
# the marks and gates, each optional
netgroupbase=ou=netgroups,dc=example,dc=com
oidcbase=ou=oidc,dc=example,dc=com
# required for the web apps, which refuse to start without it
websecret=LongRandomStringFromOpensslRandBase64
```

...and inscribing the rolls looks like this...

```shell
# a new name on the tablet, UID and GID picked automatically
pluadd -u vixen -c 'Vixen Fox' -s /bin/sh

# add her to a group and set her password
plgmod -g wheel -a add -u vixen
plupass -u vixen

# sweep names that no longer exist out of all groups
plgclean

# and raise the admin UI
mojo_nisaba prefork -l http://127.0.0.1:8080
```

## Install

### From source

Dependencies are declared in Makefile.PL, so with
[cpanminus](https://metacpan.org/pod/App::cpanminus)...

```shell
cpanm --installdeps .
perl Makefile.PL
make
make test
make install
```

Passkey/WebAuthn support additionally wants
[Authen::WebAuthn](https://metacpan.org/pod/Authen::WebAuthn), which is
loaded only if present...

```shell
cpanm Authen::WebAuthn
```

### FreeBSD

```shell
pkg install p5-perl-ldap p5-Mojolicious p5-DBI p5-DBD-SQLite p5-CryptX \
    p5-Term-ReadKey p5-Error-Helper p5-File-ShareDir p5-File-BaseDir \
    p5-String-ShellQuote p5-App-cpanminus
cpanm --installdeps .
perl Makefile.PL && make && make test && make install
```

Startup scripts for running the web apps at boot are under
[rc/freebsd/](rc/freebsd/).

### Debian

```shell
apt-get install libnet-ldap-perl libmojolicious-perl libdbi-perl \
    libdbd-sqlite3-perl libcryptx-perl libterm-readkey-perl \
    libfile-sharedir-perl libfile-basedir-perl libstring-shellquote-perl \
    cpanminus
cpanm --installdeps .
perl Makefile.PL && make && make test && make install
```

systemd units, a sysusers fragment, and a tmpfiles fragment are under
[rc/systemd/](rc/systemd/).

### LDAP schemas

TOTP, passkeys, SSH public keys, and OIDC clients each want a schema
loaded into the directory server; the schemas ship in
[schemas/](schemas/) and loading them is covered in
[docs/schemas.md](docs/schemas.md). All of them are optional... without
them Nisaba still keeps plain users, groups, and netgroups.

## Documentation

To continue your journey go to [docs/index.md](docs/index.md).

Also...

- `perldoc App::Nisaba`
- `perldoc mojo_nisaba`
- `perldoc mojo_nisaba_selfservice`
- `perldoc mojo_nisaba_sso`
- `perldoc pluadd` (and likewise each of the other CLI tools)
