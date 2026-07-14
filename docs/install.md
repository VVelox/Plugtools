# Install

## Dependencies

Declared in Makefile.PL. The notable ones...

- `Net::LDAP` (perl-ldap) with `Net::LDAP::posixAccount`,
  `Net::LDAP::posixGroup`, and the SetPassword extension
- `Config::IniHash` and `File::BaseDir` for the config
- `Mojolicious` >= 9.0 and `File::ShareDir` for the web apps
- `DBI` + `DBD::SQLite` for the rate limiter and the SSO grant store
- `Authen::TOTP`, `Imager::QRCode`, and `CryptX` for TOTP and the OIDC
  crypto
- `Term::ReadKey`, `String::ShellQuote`, `Error::Helper`

Optional, loaded only if present...

- `Authen::WebAuthn` — required for passkey login and enrollment; without
  it the passkey features report themselves unavailable and everything
  else works
- `IO::Socket::SSL` — for LDAP StartTLS and for `smtptls`

The test suite additionally wants `Net::LDAP::Server::Test`,
`Test::OpenLDAP` (which needs a real `slapd` on the system), and
`Crypt::JWT`.

## From source

```shell
cpanm --installdeps .
perl Makefile.PL
make
make test
make install
```

### FreeBSD

```shell
pkg install p5-perl-ldap p5-Mojolicious p5-DBI p5-DBD-SQLite p5-CryptX \
    p5-Term-ReadKey p5-Error-Helper p5-File-ShareDir p5-File-BaseDir \
    p5-String-ShellQuote p5-App-cpanminus
cpanm --installdeps .
perl Makefile.PL && make && make test && make install
```

### Debian

```shell
apt-get install libnet-ldap-perl libmojolicious-perl libdbi-perl \
    libdbd-sqlite3-perl libcryptx-perl libterm-readkey-perl \
    libfile-sharedir-perl libfile-basedir-perl libstring-shellquote-perl \
    cpanminus
cpanm --installdeps .
perl Makefile.PL && make && make test && make install
```

## Preparing the directory

Nisaba assumes the base DNs already exist. A minimal layout...

```ldif
dn: ou=users,dc=example,dc=com
objectClass: organizationalUnit
ou: users

dn: ou=groups,dc=example,dc=com
objectClass: organizationalUnit
ou: groups

# only if netgroups are wanted
dn: ou=netgroups,dc=example,dc=com
objectClass: organizationalUnit
ou: netgroups

# only if OIDC is wanted
dn: ou=oidc,dc=example,dc=com
objectClass: organizationalUnit
ou: oidc
```

The `bind` DN in the config needs write access under all of them, plus
the ability to use the password-modify extended operation.

If TOTP, passkeys, SSH keys, or OIDC are wanted, load the matching
schemas from `schemas/` first — see [schemas](schemas.md).

The admin web UI only admits members of the `adminGroup` group (default
`LDAPadmin`), so create it and put yourself in it...

```shell
plgadd -g LDAPadmin
plgmod -g LDAPadmin -a add -u yourname
```

## The config

Write `~/.config/nisabarc` (or point `NISABA_CONFIG` somewhere shared
like `/usr/local/etc/nisabarc`) per
[configuration](configuration.md). For the web apps also generate a
session secret — they refuse to start without one...

```shell
echo "websecret=$(openssl rand -base64 48)" >> /usr/local/etc/nisabarc
chmod 600 /usr/local/etc/nisabarc
```

The config holds the LDAP admin password and the session secret, so
mode 600 owned by the user the apps run as.

## State directory

The web apps keep their SQLite files under `/var/db/nisaba` — the rate
limiter at `web_rate_limiter.sqlite` and the SSO grant store at
`websso.sqlite`. The shipped boot scripts create it; by hand...

```shell
mkdir -p /var/db/nisaba
chown www /var/db/nisaba   # or nisaba:nisaba on Linux
chmod 700 /var/db/nisaba
```

## Running at boot

### FreeBSD

`rc/freebsd/` ships one rc.d script per web app: `mojo_nisaba` (port
8080), `mojo_nisaba_selfservice` (8081), and `mojo_nisaba_sso` (8082),
each running [Hypnotoad](https://docs.mojolicious.org/Mojo/Server/Hypnotoad)
under `daemon(8)` as `www` with syslog output. Copy them into
`/usr/local/etc/rc.d/` and in `rc.conf`...

```shell
mojo_nisaba_enable="YES"
mojo_nisaba_config="/usr/local/etc/nisabarc"
mojo_nisaba_secret="the-websecret-if-not-in-the-config"
mojo_nisaba_listen="http://127.0.0.1:8080"
# Hypnotoad tuning is optional (see configuration.md / rc/README.md):
# mojo_nisaba_workers="4"
# likewise mojo_nisaba_selfservice_* and mojo_nisaba_sso_*
```

`service mojo_nisaba reload` hot-restarts without dropping connections.

### Linux (systemd)

`rc/systemd/` ships `mojo_nisaba.service`,
`mojo_nisaba_selfservice.service`, and `mojo_nisaba_sso.service`, plus
`nisaba.sysusers.conf` (creates the `nisaba` system user) and
`nisaba.tmpfiles.conf` (creates `/var/db/nisaba`, mode 0700). The units
run Hypnotoad, restart on failure, read optional overrides (listen URL,
`NISABA_HYPNOTOAD_*` tuning) from `/usr/local/etc/nisaba/<name>.env`, and
are hardened (`ProtectSystem=strict` with only `/var/db/nisaba`
writable, `MemoryDenyWriteExecute`, syscall filtering).

```shell
cp rc/systemd/*.service /etc/systemd/system/
cp rc/systemd/nisaba.sysusers.conf /etc/sysusers.d/nisaba.conf
cp rc/systemd/nisaba.tmpfiles.conf /etc/tmpfiles.d/nisaba.conf
systemd-sysusers && systemd-tmpfiles --create
systemctl enable --now mojo_nisaba mojo_nisaba_selfservice mojo_nisaba_sso
```

`systemctl reload mojo_nisaba` hot-restarts without dropping
connections. `ExecStart`/`ExecReload` reference `/usr/local/bin/hypnotoad`;
adjust if your Perl installed it elsewhere. Worker counts and the other
Hypnotoad knobs are in [configuration](configuration.md) and
[rc/README.md](../rc/README.md).

## In front of it all

The web apps speak plain HTTP by default and are meant to sit behind a
TLS-terminating reverse proxy (or terminate TLS themselves with a
`NISABA_LISTEN='https://*:8443?cert=...&key=...'` listen URL). If the
proxy speaks plain HTTP to the app *and* the app is reached over plain
HTTP by browsers, set `cookieSecure=0`; otherwise leave it alone. Behind
a proxy also set `passkeyRpId` and (for the SSO) `ssoIssuer` explicitly,
and turn on reverse-proxy header handling (`NISABA_HYPNOTOAD_PROXY=1`) —
see [security](security.md) for why.
