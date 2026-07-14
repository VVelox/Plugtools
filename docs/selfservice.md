# The self-service portal — mojo_nisaba_selfservice

Where each name on the tablet tends its own line. Any user may log in,
and sees only their own entry: password, SSH keys, TOTP, passkeys.

```shell
# development
mojo_nisaba_selfservice daemon -l http://127.0.0.1:8081

# production — Hypnotoad (hot restarts, tunable; see configuration.md)
NISABA_LISTEN=http://127.0.0.1:8081 hypnotoad /usr/local/bin/mojo_nisaba_selfservice
```

Like the other web apps it refuses to start without `websecret` (or
`NISABA_SECRET`), and the shipped boot scripts (which run Hypnotoad)
listen on port 8081 — see [install](install.md).

## Logging in

Password login verifies by binding to LDAP *as the user* — the service
account only finds the DN; it never judges the password itself. Then...

- if the account has TOTP active, a code is demanded before the session
  is granted
- accounts with passkeys can skip the password entirely and sign in
  with WebAuthn; if TOTP is also active, the code is still demanded
  after

Every path is rate limited — per user and per IP for passwords and
TOTP, per IP for passkeys — with the limits and lockouts from
[configuration](configuration.md). Blocked attempts get HTTP 429
with a `Retry-After`.

## Forgot password

Only offered when `smtpserver` is configured. The user asks by
username; the portal always answers the same way whether or not the
account exists or has a mail address, and if it does, sends a reset
link to it. The token in the link...

- expires after an hour
- is bound to a fingerprint of the current password, so the moment the
  password changes — by this link or any other means — every
  outstanding reset token dies
- is signed with the session secret

Requests for reset mail are among the most tightly rate limited things
in the portal (3 per user per hour by default) since each one sends
mail outward.

## Password change

For a logged-in user, changing the password demands the current one
again first. The new password goes to the directory via the
password-modify extension, so the LDAP server does the hashing.

## SSH keys

If the [openssh-lpk schema](schemas.md) is loaded, a user can enable
SSH key storage on their entry (adding the `ldapPublicKey`
objectClass), then add and remove `sshPublicKey` values — useful
anywhere `sshd` or `sssd` is set up to fetch keys from LDAP.

## TOTP

Enrollment is verify-before-activate...

1. enable TOTP on the account and generate a secret — shown as a QR
   code and as a setup URL, issuer from `totpissuer`
2. the secret sits *pending* until the user proves the authenticator
   has it by entering a valid code
3. on activation the portal mints single-use scratch codes (up to
   `totpMaxScratchCodes`), shown once — from then on login demands a
   code

Scratch codes can be regenerated later, which voids the old batch.

## Passkeys

If the [passkey schema](schemas.md) is loaded and `Authen::WebAuthn` is
installed, a user can enable passkey storage, then register
credentials — platform biometrics or hardware keys, ES256/EdDSA/RS256,
each with a nickname. Registered passkeys are listed with their
transports and last-use times and can be removed; the user can also set
their own user-verification policy (`required`/`preferred`/
`discouraged`). Discoverable credentials are requested, so passkey
login needs no username typed first.

Behind a reverse proxy, pin `passkeyRpId` to the public hostname —
credentials are scoped to the relying-party ID, and letting it float
with the `Host` header invites mysteries.

## What it will not do

The portal holds the same admin bind the other apps do, but exposes
none of it: no other user's entry can be seen or touched, there is no
group management, and nothing about the account other than the marks
above can be changed. Administration lives in
[the admin UI](web.md).
