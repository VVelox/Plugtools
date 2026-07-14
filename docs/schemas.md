# The LDAP schemas

Everything beyond plain users, groups, and netgroups wants a schema
loaded into the directory server first. They ship in `schemas/` and are
all optional — features whose schema is absent simply report themselves
unavailable. The Nisaba-native ones live under the OID arc
`1.3.6.1.4.1.26481.2.*`.

## totp.schema / totp-schema.ldif

TOTP secrets and MFA policy, arc `...26481.2.8`. A lightly modified
descendant of
[wheelybird/ldap-totp-schema](https://github.com/wheelybird/ldap-totp-schema).

Two auxiliary classes...

- `totpUser` on user entries: `totpSecret` (Base32), `totpStatus`
  (`none`/`pending`/`active`/`disabled`/`bypassed`), `totpScratchCode`
  (multi-valued, single-use), `totpEnrolledDate`, and the parameters
  `totpAlgorithm` (SHA1/SHA256/SHA512), `totpPeriod` (default 30),
  `totpDigits` (6 or 8)
- `mfaGroup` on group entries: `mfaRequired` and `mfaGracePeriodDays`,
  for demanding MFA of a group's members

The same schema is provided twice: `totp.schema` for classic
`slapd.conf` style includes, `totp-schema.ldif` for OpenLDAP's
`cn=config`...

```shell
# cn=config
ldapadd -Y EXTERNAL -H ldapi:/// -f schemas/totp-schema.ldif

# or slapd.conf style
include /usr/local/etc/openldap/schema/totp.schema
```

## passkey.schema

WebAuthn/FIDO2 credentials, arc `...26481.2.9`, inspired by FreeIPA's
passkey attribute and SSSD's passkey provider.

The auxiliary class `passkeyUser` carries...

- `passkeyCredential` — one value per passkey, a pipe-delimited record
  of credential ID, COSE public key, algorithm, sign count, AAGUID,
  transports, backup flags, nickname, and created/last-used timestamps
- `passkeyRpId` — per-user relying party ID override
- `passkeyUserVerification` — per-user UV policy

## oidc.schema

OIDC client registrations and user claims, arc `...26481.2.10`,
modelled on OpenID Connect Core 1.0 and RFC 7591 dynamic client
registration metadata.

- `oidcRelyingParty` (structural) — one entry per registered client
  under `oidcbase`: `oidcClientId` (the RDN), `oidcClientSecret`,
  `oidcRedirectURI`, `oidcScope`, `oidcGrantType`, `oidcResponseType`,
  `oidcTokenEndpointAuthMethod`, `oidcIdTokenSignedResponseAlg`,
  `oidcJwks` (the signing keys), display metadata (`oidcClientName`,
  `oidcLogoURI`, `oidcPolicyURI`, `oidcTosURI`, `oidcContact`),
  behavior (`oidcDefaultMaxAge`, `oidcPostLogoutRedirectURI`), and the
  rest of the RFC 7591 vocabulary for completeness
- `oidcSubject` (auxiliary) — on user entries, the OIDC claims that
  have no inetOrgPerson home: `oidcNickname`, `oidcMiddleName`,
  `oidcPicture`, `oidcProfile`, `oidcWebsite`, `oidcGender`,
  `oidcBirthdate`, `oidcZoneinfo`, `oidcEmailVerified`,
  `oidcPhoneNumberVerified`, `oidcUpdatedAt`, plus `oidcConsentRecord`
  for durable consents

## openssh-lpk.schema

The standard openssh-lpk schema (by Eric AUGE, from Mark Ruijter's
proposal, arc `1.3.6.1.4.1.24552`), included for convenience — your
directory may well have it already. One auxiliary class,
`ldapPublicKey`, carrying multi-valued `sshPublicKey`. This is what
`sshd`/`sssd` LDAP key lookups conventionally expect.

## Loading order and dependencies

None of the Nisaba schemas depend on each other; load whichever
features you want. All of them assume the core and inetOrgPerson
schemas the directory server ships with. After loading, no
configuration is needed on the Nisaba side beyond the feature switches
in [configuration](configuration.md) — the module probes the
directory for what is available.
