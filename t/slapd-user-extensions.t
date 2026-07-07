#!perl
use strict;
use warnings;

# Integration tests for App::Nisaba's schema-dependent user/group extension
# families against a REAL OpenLDAP slapd (see t/lib/NisabaSlapdTest.pm):
#
#   * ldapPublicKey / SSH public keys   (openssh-lpk.schema)
#   * TOTP enrollment + verification    (totp.schema)
#   * MFA group policy                  (totp.schema, mfaGroup)
#   * passkey (WebAuthn) credentials    (passkey.schema)
#   * oidcSubject conversion            (oidc.schema)
#   * userSelfInfo aggregate view
#
# These need a real subschema (the userConvertToLdapPublicKeySelf /
# userConvertToTotp / groupConvertToMfa / userTotpGenerateSecret methods all
# gate on *SchemaAvailable) and real schema enforcement, so they live on the
# slapd harness rather than the in-memory one.

use Test::More;
use Digest::SHA    ();
use File::Basename ();
use File::Spec;
use lib File::Spec->catdir( File::Basename::dirname(__FILE__), 'lib' );
use NisabaSlapdTest;

my ( $env, $skip ) = NisabaSlapdTest::setup();
plan skip_all => $skip if $skip;

my $pt = $env->{pt};
sub pt_try { return NisabaSlapdTest::pt_try( $pt, @_ ) }

END { NisabaSlapdTest::teardown($env) }

alarm(300);
local $SIG{ALRM} = sub { die "test watchdog expired — slapd wedged?\n" };

# ── RFC 6238 helpers (to generate a currently-valid TOTP code) ──────────────

sub _b32_decode {
	my ($b32) = @_;
	my %map;
	my @alphabet = ( 'A' .. 'Z', 2 .. 7 );
	$map{ $alphabet[$_] } = $_ for 0 .. 31;
	$b32 = uc $b32;
	$b32 =~ s/=+\z//;
	my $bits  = join '', map { sprintf '%05b', $map{$_} } split //, $b32;
	my $bytes = '';

	for ( my $i = 0; $i + 8 <= length $bits; $i += 8 ) {
		$bytes .= chr oct '0b' . substr $bits, $i, 8;
	}
	return $bytes;
} ## end sub _b32_decode

sub _totp_now {
	my ( $secret_b32, $digits, $period ) = @_;
	my $key     = _b32_decode($secret_b32);
	my $counter = int( time() / $period );
	my $hmac    = Digest::SHA::hmac_sha1( pack( 'NN', 0, $counter ), $key );
	my $offset  = ord( substr $hmac, -1 ) & 0xf;                               ## no critic (Bangs::ProhibitBitwiseOperators)
	my $code    = ( unpack 'N', substr $hmac, $offset, 4 ) & 0x7fffffff;       ## no critic (Bangs::ProhibitBitwiseOperators)
	return sprintf '%0*d', $digits, $code % ( 10**$digits );
}

# ── Fixtures ────────────────────────────────────────────────────────────────

my ( $ret, $err, $entry, $info );

( $ret, $err ) = pt_try( sub { $pt->addGroup( { group => 'devs', gid => 5000 } ) } );
is( $err, '', 'fixture group added' );
( $ret, $err ) = pt_try( sub { $pt->addUser( { user => 'alice', uid => 6000, group => 'devs' } ) } );
is( $err, '', 'fixture user alice added' );
( $ret, $err ) = pt_try( sub { $pt->addUser( { user => 'bob', uid => 6001, group => 'devs' } ) } );
is( $err, '', 'fixture user bob added' );

sub fetch_user {
	my ($user) = @_;
	my ($e)    = pt_try( sub { $pt->getUserEntry( { user => $user } ) } );
	return $e;
}

sub has_oc {
	my ( $user, $oc ) = @_;
	my %map = map { lc($_) => 1 } fetch_user($user)->get_value('objectClass');
	return $map{ lc $oc } ? 1 : 0;
}

# ── ldapPublicKey / SSH keys ────────────────────────────────────────────────

# Key add before conversion is refused (entry lacks the ldapPublicKey OC).
( $ret, $err ) = pt_try( sub { $pt->userSSHPublicKeyAdd( { user => 'alice', key => 'ssh-ed25519 AAAAC3one' } ) } );
isnt( $err, '', 'SSH key add before conversion fails' );
is( $pt->error, 72, 'unconverted user sets error 72 (noLdapPublicKeySchema)' );

( $ret, $err ) = pt_try( sub { $pt->userConvertToLdapPublicKey( { user => 'alice' } ) } );
is( $err, '', 'userConvertToLdapPublicKey succeeds' );
ok( has_oc( 'alice', 'ldapPublicKey' ), 'ldapPublicKey objectClass added' );

( $ret, $err ) = pt_try( sub { $pt->userConvertToLdapPublicKey( { user => 'alice' } ) } );
isnt( $err, '', 'double lpk conversion fails' );
is( $pt->error, 74, 'sets error 74 (alreadyLdapPublicKey)' );

( $ret, $err ) = pt_try( sub { $pt->userSSHPublicKeyAdd( { user => 'alice', key => 'ssh-ed25519 AAAAC3one' } ) } );
is( $err, '', 'first SSH key added' );
( $ret, $err ) = pt_try( sub { $pt->userSSHPublicKeyAdd( { user => 'alice', key => 'ssh-ed25519 AAAAC3two' } ) } );
is( $err, '', 'second SSH key added' );

( $ret, $err ) = pt_try( sub { $pt->userSSHPublicKeyAdd( { user => 'alice', key => "ssh-rsa AAA\nBBB" } ) } );
isnt( $err, '', 'multi-line SSH key rejected' );
is( $pt->error, 73, 'sets error 73 (noSSHPublicKey)' );

( $ret, $err ) = pt_try( sub { $pt->userSSHPublicKeyRemove( { user => 'alice', key => 'ssh-ed25519 AAAAC3two' } ) } );
is( $err, '', 'SSH key removed' );
$entry = fetch_user('alice');
is_deeply( [ $entry->get_value('sshPublicKey') ], ['ssh-ed25519 AAAAC3one'], 'remaining SSH key intact' );

# Self-service variant gates on subschema discovery (error 72 if the schema
# were missing — it is loaded here, so this exercises the success path).
( $ret, $err ) = pt_try( sub { $pt->userConvertToLdapPublicKeySelf( { user => 'bob' } ) } );
is( $err, '', 'userConvertToLdapPublicKeySelf succeeds (schema detected)' );
ok( has_oc( 'bob', 'ldapPublicKey' ), 'self-service conversion added the objectClass' );

( $ret, $err ) = pt_try( sub { $pt->userSSHPublicKeyAddSelf( { user => 'bob', key => 'ssh-ed25519 AAAAC3bob' } ) } );
is( $err, '', 'userSSHPublicKeyAddSelf succeeds' );
$entry = fetch_user('bob');
is_deeply( [ $entry->get_value('sshPublicKey') ], ['ssh-ed25519 AAAAC3bob'], 'self-service SSH key stored' );

( $ret, $err ) = pt_try( sub { $pt->userSSHPublicKeyRemoveSelf( { user => 'bob', key => 'ssh-ed25519 AAAAC3bob' } ) } );
is( $err, '', 'userSSHPublicKeyRemoveSelf succeeds' );
$entry = fetch_user('bob');
is( $entry->get_value('sshPublicKey'), undef, 'self-service SSH key removed' );

# ── TOTP ────────────────────────────────────────────────────────────────────

( $ret, $err ) = pt_try( sub { $pt->userConvertToTotp( { user => 'alice' } ) } );
is( $err, '', 'userConvertToTotp succeeds (schema gate passed)' );
ok( has_oc( 'alice', 'totpUser' ), 'totpUser objectClass added' );

( $ret, $err ) = pt_try( sub { $pt->userConvertToTotp( { user => 'alice' } ) } );
is( $pt->error, 80, 'double TOTP conversion sets error 80 (alreadyTotpUser)' );

my ($secret);
( $secret, $err ) = pt_try( sub { $pt->userTotpGenerateSecret( { user => 'alice' } ) } );
is( $err, '', 'userTotpGenerateSecret succeeds' );
like( $secret, qr/^[A-Z2-7]+$/i, 'returned secret is Base32' );

( $info, $err ) = pt_try( sub { $pt->userTotpInfoGet( { user => 'alice' } ) } );
is( $err,                    '',        'userTotpInfoGet succeeds' );
is( $info->{hasTotpUser},    1,         'info: hasTotpUser' );
is( $info->{totpSecret},     $secret,   'info: secret stored' );
is( $info->{totpStatus},     'pending', 'info: status pending after enrollment' );
is( $info->{totpAlgorithm},  'SHA1',    'info: default algorithm SHA1' );
is( $info->{totpDigits} + 0, 6,         'info: default digits 6' );
is( $info->{totpPeriod} + 0, 30,        'info: default period 30' );

# Verify with a currently-valid RFC 6238 code computed from the secret.
my $valid_code = _totp_now( $secret, 6, 30 );
( $ret, $err ) = pt_try( sub { $pt->userTotpVerify( { user => 'alice', code => $valid_code } ) } );
is( $err, '', 'userTotpVerify ran' );
is( $ret, 1,  'valid TOTP code verifies' );

# Scratch codes.
my ($codes);
( $codes, $err ) = pt_try( sub { $pt->userTotpScratchCodesReplace( { user => 'alice' } ) } );
is( $err,           '',      'userTotpScratchCodesReplace succeeds' );
is( ref $codes,     'ARRAY', 'replace returns an arrayref of codes' );
is( scalar @$codes, 10,      'default count = totpMaxScratchCodes (10)' );
like( $codes->[0], qr/^\d{6}$/, 'codes have totpDigits length' );

( $ret, $err ) = pt_try( sub { $pt->userTotpScratchCodesReplace( { user => 'alice', count => 12 } ) } );
is( $pt->error, 89, 'count above the limit sets error 89' );

( $ret, $err ) = pt_try( sub { $pt->userTotpScratchCodeAdd( { user => 'alice', code => '123456' } ) } );
is( $pt->error, 89, 'adding beyond the scratch-code limit sets error 89' );

# A wrong code: neither the current TOTP nor any scratch code. Returns undef
# but sets NO error.
my %scratch = map { $_ => 1 } @$codes;
my $wrong   = $valid_code;
do { $wrong = sprintf '%06d', ( $wrong + 1 ) % 1_000_000 } while $scratch{$wrong};
( $ret, $err ) = pt_try( sub { $pt->userTotpVerify( { user => 'alice', code => $wrong } ) } );
is( $err, '', 'invalid code verification is not an error' );
ok( !defined $ret, 'invalid code returns undef' );

# A scratch code verifies once and is consumed by the verification.
my $burn = $codes->[0];
( $ret, $err ) = pt_try( sub { $pt->userTotpVerify( { user => 'alice', code => $burn } ) } );
is( $ret, 1, 'scratch code verifies' );
( $info, $err ) = pt_try( sub { $pt->userTotpInfoGet( { user => 'alice' } ) } );
is( scalar @{ $info->{totpScratchCodes} }, 9, 'used scratch code was consumed' );
( $ret, $err ) = pt_try( sub { $pt->userTotpVerify( { user => 'alice', code => $burn } ) } );
ok( !defined $ret, 'consumed scratch code does not verify again' );

# Setter validation.
( $ret, $err ) = pt_try( sub { $pt->userTotpStatusSet( { user => 'alice', status => 'active' } ) } );
is( $err, '', 'userTotpStatusSet active succeeds' );
( $ret, $err ) = pt_try( sub { $pt->userTotpStatusSet( { user => 'alice', status => 'bogus' } ) } );
is( $pt->error, 82, 'invalid status sets error 82' );
( $ret, $err ) = pt_try( sub { $pt->userTotpAlgorithmSet( { user => 'alice', algorithm => 'SHA256' } ) } );
is( $err, '', 'userTotpAlgorithmSet succeeds' );
( $ret, $err ) = pt_try( sub { $pt->userTotpAlgorithmSet( { user => 'alice', algorithm => 'MD5' } ) } );
is( $pt->error, 86, 'invalid algorithm sets error 86' );
( $ret, $err ) = pt_try( sub { $pt->userTotpDigitsSet( { user => 'alice', digits => 8 } ) } );
is( $err, '', 'userTotpDigitsSet 8 succeeds' );
( $ret, $err ) = pt_try( sub { $pt->userTotpDigitsSet( { user => 'alice', digits => 7 } ) } );
is( $pt->error, 87, 'invalid digits sets error 87' );
( $ret, $err ) = pt_try( sub { $pt->userTotpPeriodSet( { user => 'alice', period => 60 } ) } );
is( $err, '', 'userTotpPeriodSet succeeds' );
( $ret, $err ) = pt_try( sub { $pt->userTotpPeriodSet( { user => 'alice', period => 0 } ) } );
is( $pt->error, 88, 'invalid period sets error 88' );

( $ret, $err ) = pt_try( sub { $pt->userTotpEnrolledDateSet( { user => 'alice' } ) } );
is( $err, '', 'userTotpEnrolledDateSet succeeds' );
( $info, $err ) = pt_try( sub { $pt->userTotpInfoGet( { user => 'alice' } ) } );
like( $info->{totpEnrolledDate}, qr/^\d{14}Z$/, 'enrolled date is GeneralizedTime' );

# Explicit secret set (GenerateSecret covered the auto path above).
( $ret, $err ) = pt_try( sub { $pt->userTotpSecretSet( { user => 'alice', secret => 'JBSWY3DPEHPK3PXP' } ) } );
is( $err, '', 'userTotpSecretSet succeeds' );
( $info, $err ) = pt_try( sub { $pt->userTotpInfoGet( { user => 'alice' } ) } );
is( $info->{totpSecret}, 'JBSWY3DPEHPK3PXP', 'explicit secret stored' );
( $ret, $err ) = pt_try( sub { $pt->userTotpSecretSet( { user => 'alice' } ) } );
is( $pt->error, 81, 'missing secret sets error 81' );

# totpURI is a pure helper (no LDAP).
my ($uri);
( $uri, $err ) = pt_try( sub { $pt->totpURI( { secret => $secret, user => 'alice' } ) } );
is( $err, '', 'totpURI succeeds' );
like( $uri, qr/^otpauth:\/\/totp\//, 'totpURI is an otpauth URI' );
like( $uri, qr/\Q$secret\E/i,        'totpURI carries the secret' );

# totpQRCodeBase64 is likewise LDAP-free: base64 of a PNG of the otpauth URI.
my ($qr);
( $qr, $err ) = pt_try( sub { $pt->totpQRCodeBase64( { secret => $secret, user => 'alice' } ) } );
is( $err, '', 'totpQRCodeBase64 succeeds' );
like( $qr, qr/^[A-Za-z0-9+\/=]+$/, 'QR output is base64' );
require MIME::Base64;
like( MIME::Base64::decode_base64($qr), qr/^\x89PNG/, 'QR decodes to a PNG image' );

# ── userSelfInfo (while TOTP state is populated) ────────────────────────────

( $info, $err ) = pt_try( sub { $pt->userSelfInfo( { user => 'alice' } ) } );
is( $err,                      '',      'userSelfInfo succeeds' );
is( ref $info->{cn},           'ARRAY', 'selfInfo: cn is an arrayref' );
is( ref $info->{sshPublicKey}, 'ARRAY', 'selfInfo: sshPublicKey is an arrayref' );
is_deeply( $info->{sshPublicKey}, ['ssh-ed25519 AAAAC3one'], 'selfInfo: ssh keys listed' );
is( $info->{totpStatus},           'active', 'selfInfo: totpStatus' );
is( $info->{totpScratchCodeCount}, 9,        'selfInfo: scratch codes counted, not listed' );
ok( $info->{objectClasses}{posixaccount}, 'selfInfo: objectClasses map populated' );
ok( !exists $info->{totpSecret},          'selfInfo does NOT expose the TOTP secret' );
ok( !exists $info->{totpScratchCodes},    'selfInfo does NOT expose scratch code values' );

# ── TOTP un-enrollment ──────────────────────────────────────────────────────

( $ret, $err ) = pt_try( sub { $pt->userTotpSecretRemove( { user => 'alice' } ) } );
is( $err, '', 'userTotpSecretRemove succeeds' );
( $info, $err ) = pt_try( sub { $pt->userTotpInfoGet( { user => 'alice' } ) } );
is( $info->{totpSecret}, undef,  'secret cleared' );
is( $info->{totpStatus}, 'none', 'status reset to none' );
is_deeply( $info->{totpScratchCodes}, [], 'scratch codes cleared' );

( $ret, $err ) = pt_try( sub { $pt->userTotpVerify( { user => 'alice', code => '123456' } ) } );
is( $pt->error, 81, 'verify without a secret sets error 81 (noTotpSecret)' );

# ── MFA group policy ────────────────────────────────────────────────────────

( $ret, $err ) = pt_try( sub { $pt->groupConvertToMfa( { group => 'devs' } ) } );
is( $err, '', 'groupConvertToMfa succeeds (schema gate passed)' );
( $ret, $err ) = pt_try( sub { $pt->groupConvertToMfa( { group => 'devs' } ) } );
is( $pt->error, 84, 'double MFA conversion sets error 84 (alreadyMfaGroup)' );

( $ret, $err ) = pt_try( sub { $pt->groupMfaRequiredSet( { group => 'devs', required => 1 } ) } );
is( $err, '', 'groupMfaRequiredSet succeeds' );
( $ret, $err ) = pt_try( sub { $pt->groupMfaGracePeriodSet( { group => 'devs', days => 7 } ) } );
is( $err, '', 'groupMfaGracePeriodSet succeeds' );
( $ret, $err ) = pt_try( sub { $pt->groupMfaGracePeriodSet( { group => 'devs', days => 'x' } ) } );
is( $pt->error, 85, 'non-numeric grace period sets error 85' );

( $info, $err ) = pt_try( sub { $pt->groupMfaInfoGet( { group => 'devs' } ) } );
is( $err,                            '',     'groupMfaInfoGet succeeds' );
is( $info->{hasMfaGroup},            1,      'mfaInfo: hasMfaGroup' );
is( $info->{mfaRequired},            'TRUE', 'mfaInfo: mfaRequired' );
is( $info->{mfaGracePeriodDays} + 0, 7,      'mfaInfo: grace period' );

# ── Passkeys ────────────────────────────────────────────────────────────────

( $ret, $err ) = pt_try( sub { $pt->userConvertToPasskeyUser( { user => 'alice' } ) } );
is( $err, '', 'userConvertToPasskeyUser succeeds' );
ok( has_oc( 'alice', 'passkeyUser' ), 'passkeyUser objectClass added' );
( $ret, $err ) = pt_try( sub { $pt->userConvertToPasskeyUser( { user => 'alice' } ) } );
is( $pt->error, 91, 'double passkey conversion sets error 91 (alreadyPasskeyUser)' );

( $ret, $err ) = pt_try( sub { $pt->userPasskeyRpIdSet( { user => 'alice', rpId => 'example.com' } ) } );
is( $err, '', 'userPasskeyRpIdSet succeeds' );
( $ret, $err ) = pt_try( sub { $pt->userPasskeyUserVerificationSet( { user => 'alice', uv => 'required' } ) } );
is( $err, '', 'userPasskeyUserVerificationSet succeeds' );
( $ret, $err ) = pt_try( sub { $pt->userPasskeyUserVerificationSet( { user => 'alice', uv => 'sometimes' } ) } );
is( $pt->error, 94, 'invalid uv sets error 94' );

# The nickname deliberately contains the delimiter (|) and percent to prove
# the pct-encoding round-trip.
my %cred = (
	user           => 'alice',
	credentialId   => 'credA-id',
	cosePublicKey  => 'coseA-key',
	algorithm      => -7,
	signCount      =>  0,
	transports     => [ 'internal', 'hybrid' ],
	backupEligible => 'TRUE',
	backupState    => 'FALSE',
	nickname       => 'Mac|Book 100%',
);
( $ret, $err ) = pt_try( sub { $pt->userPasskeyCredentialAdd( \%cred ) } );
is( $err, '', 'userPasskeyCredentialAdd succeeds' );

( $ret, $err )
	= pt_try( sub { $pt->userPasskeyCredentialAdd( { user => 'alice', cosePublicKey => 'x', signCount => 0 } ) } );
is( $pt->error, 92, 'missing credentialId sets error 92' );
( $ret, $err )
	= pt_try( sub { $pt->userPasskeyCredentialAdd( { user => 'alice', credentialId => 'credB', signCount => 0 } ) } );
is( $pt->error, 93, 'missing cosePublicKey sets error 93' );
( $ret, $err ) = pt_try( sub { $pt->userPasskeyCredentialAdd( \%cred ) } );
is( $pt->error, 93, 'duplicate credentialId sets error 93' );

( $info, $err ) = pt_try( sub { $pt->userPasskeyInfoGet( { user => 'alice' } ) } );
is( $err,                             '',            'userPasskeyInfoGet succeeds' );
is( $info->{hasPasskeyUser},          1,             'passkeyInfo: hasPasskeyUser' );
is( $info->{passkeyRpId},             'example.com', 'passkeyInfo: rpId' );
is( $info->{passkeyUserVerification}, 'required',    'passkeyInfo: uv' );
is( scalar @{ $info->{credentials} }, 1,             'passkeyInfo: one credential' );
my $c = $info->{credentials}[0];
is( $c->{credentialId},  'credA-id', 'credential: id round-trips' );
is( $c->{signCount} + 0, 0,          'credential: signCount' );
is_deeply( $c->{transports}, [ 'internal', 'hybrid' ], 'credential: transports arrayref' );
is( $c->{nickname}, 'Mac|Book 100%', 'credential: nickname pct-encoding round-trips' );
ok( $c->{createdDate}, 'credential: createdDate set' );

( $ret, $err ) = pt_try(
	sub {
		$pt->userPasskeyCredentialUpdate(
			{ user => 'alice', credentialId => 'credA-id', signCount => 42, backupState => 'TRUE' } );
	}
);
is( $err, '', 'userPasskeyCredentialUpdate succeeds' );
( $info, $err ) = pt_try( sub { $pt->userPasskeyInfoGet( { user => 'alice' } ) } );
$c = $info->{credentials}[0];
is( $c->{signCount} + 0, 42,     'update: signCount bumped' );
is( $c->{backupState},   'TRUE', 'update: backupState changed' );
ok( $c->{lastUsedDate}, 'update: lastUsedDate set' );

my ($found);
( $found, $err ) = pt_try( sub { $pt->userPasskeyFindByCredentialId( { credentialId => 'credA-id' } ) } );
is( $err,                               '',         'userPasskeyFindByCredentialId succeeds' );
is( $found->{user},                     'alice',    'find: resolves the owning user' );
is( $found->{credential}{credentialId}, 'credA-id', 'find: returns the decoded credential' );

( $found, $err ) = pt_try( sub { $pt->userPasskeyFindByCredentialId( { credentialId => 'nosuch' } ) } );
is( $pt->error, 95, 'unknown credential sets error 95' );

( $ret, $err ) = pt_try( sub { $pt->userPasskeyCredentialRemove( { user => 'alice', credentialId => 'credA-id' } ) } );
is( $err, '', 'userPasskeyCredentialRemove succeeds' );
( $info, $err ) = pt_try( sub { $pt->userPasskeyInfoGet( { user => 'alice' } ) } );
is_deeply( $info->{credentials}, [], 'credential removed' );
( $ret, $err ) = pt_try( sub { $pt->userPasskeyCredentialRemove( { user => 'alice', credentialId => 'credA-id' } ) } );
is( $pt->error, 95, 'removing a missing credential sets error 95' );

# ── oidcSubject conversion (idempotent by design) ───────────────────────────

( $ret, $err ) = pt_try( sub { $pt->userConvertToOidcSubject( { user => 'alice' } ) } );
is( $err, '', 'userConvertToOidcSubject succeeds' );
ok( has_oc( 'alice', 'oidcSubject' ), 'oidcSubject objectClass added' );

( $ret, $err ) = pt_try( sub { $pt->userConvertToOidcSubject( { user => 'alice' } ) } );
is( $err, '', 'second oidcSubject conversion is not an error (idempotent)' );
is( $ret, 1,  'idempotent conversion returns 1' );

done_testing;
