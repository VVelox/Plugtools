# Examples

Copy-paste scenarios, from bare directory to working SSO. All assume
the suffix `dc=example,dc=com` and the config at
`/usr/local/etc/nisabarc` with `NISABA_CONFIG` pointed at it.

## From nothing to a first user

The org units and the admin group, once...

```shell
ldapadd -x -D cn=admin,dc=example,dc=com -W <<'EOF'
dn: ou=users,dc=example,dc=com
objectClass: organizationalUnit
ou: users

dn: ou=groups,dc=example,dc=com
objectClass: organizationalUnit
ou: groups
EOF
```

The config...

```ini
server=ldap.example.com
starttls=1
TLSverify=require
bind=cn=admin,dc=example,dc=com
pass=WhateverYouSetAsApassword
userbase=ou=users,dc=example,dc=com
groupbase=ou=groups,dc=example,dc=com
defaultShell=/bin/sh
createHome=0
```

And the first names on the tablet...

```shell
plgadd -g LDAPadmin
pluadd -u vixen -c 'Vixen Fox'
plupass -u vixen
plgmod -g LDAPadmin -a add -u vixen
```

`vixen` can now log into the admin UI.

## The web apps, minimally

```shell
echo "websecret=$(openssl rand -base64 48)" >> /usr/local/etc/nisabarc
chmod 600 /usr/local/etc/nisabarc

mkdir -p /var/db/nisaba && chmod 700 /var/db/nisaba

NISABA_LISTEN=http://127.0.0.1:8080 hypnotoad /usr/local/bin/mojo_nisaba
NISABA_LISTEN=http://127.0.0.1:8081 hypnotoad /usr/local/bin/mojo_nisaba_selfservice
```

`hypnotoad` (Mojolicious' preforking server) backgrounds itself; re-run
the same line after an upgrade for a zero-downtime restart. Then put a
TLS-terminating proxy in front (see [install.md](install.md) for doing
this properly at boot). For a quick plain-HTTP look during development,
set `cookieSecure=0` and run `mojo_nisaba daemon -l http://127.0.0.1:8080`
in the foreground instead.

## Users who carry SSH keys

Load `schemas/openssh-lpk.schema` into the directory, then per user
from the admin UI, or let users do it themselves in the self-service
portal: enable SSH key storage, paste keys. On the servers that should
honor them, the usual `sssd`/`AuthorizedKeysCommand` LDAP lookup
against `sshPublicKey`.

## Demanding TOTP of the admins

Load the TOTP schema...

```shell
ldapadd -Y EXTERNAL -H ldapi:/// -f schemas/totp-schema.ldif
```

...then each admin, in the self-service portal: enable TOTP, scan the
QR code, verify a code, pocket the scratch codes. From activation on,
the admin UI, the portal, and the SSO all demand the code after the
password.

## A netgroup for production hosts

```ini
# added to nisabarc
netgroupbase=ou=netgroups,dc=example,dc=com
```

```shell
ldapadd -x -D cn=admin,dc=example,dc=com -W <<'EOF'
dn: ou=netgroups,dc=example,dc=com
objectClass: organizationalUnit
ou: netgroups
EOF
```

Create `prod` in the admin UI, then tend it from the shell...

```shell
plngmod -g prod -a triple_add -t 'web01,,example.com'
plngmod -g prod -a triple_add -t 'web02,,example.com'
plngmod -g prod -a description -c 'production hosts'
```

## SSO in front of an internal app

Load `schemas/oidc.schema`, add the base and issuer...

```ini
oidcbase=ou=oidc,dc=example,dc=com
ssoIssuer=https://sso.example.com
```

...create `ou=oidc` like the others, raise `mojo_nisaba_sso` behind
TLS at `sso.example.com`, register a client in the admin UI (redirect
URI `https://app.example.com/redirect_uri`, scopes
`openid profile email`), and configure Apache mod_auth_openidc per the
walkthrough in [Sukkal.md](Sukkal.md#walkthrough-apache-mod_auth_openidc).

Verify from the outside...

```shell
# the discovery document is the smoke test
curl https://sso.example.com/.well-known/openid-configuration | jq .

# and the published signing keys
curl https://sso.example.com/jwks | jq .
```

## When someone locks themselves out

Eight bad passwords in fifteen minutes locks that user+IP pair for
fifteen minutes; the portal answers 429 with a `Retry-After`. Waiting
works. If it must not wait, the limiter state is disposable...

```shell
# nuclear: forget all lockouts (all of them, for everyone)
rm /var/db/nisaba/web_rate_limiter.sqlite
```

...or loosen a scope in the config, e.g. `rateLimitLoginMax=20`, and
restart the app. Do not set `rateLimit=0` anywhere the world can
reach.

## Hanging a hook on account changes

```ini
pluginAddUser=App::Nisaba::Plugins::Dump
pluginDeleteUser=Your::Plugin::That::Archives::Mail
```

Every matching action now calls the module's `plugin` method with the
action's options and arguments — `App::Nisaba::Plugins::Dump` just
prints what it gets and is the template to copy. See
`perldoc App::Nisaba` for the interface.
