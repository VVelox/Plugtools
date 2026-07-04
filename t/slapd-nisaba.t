#!perl
use strict;
use warnings;

# Integration tests for App::Nisaba against a REAL OpenLDAP slapd (spawned by
# Test::OpenLDAP — see t/lib/NisabaSlapdTest.pm). This covers everything the
# in-memory Net::LDAP::Server::Test harness cannot:
#
#   * schema discovery via $ldap->schema (the *SchemaAvailable methods)
#   * the SetPassword extended operation (userSetPass / userSetPassSelf)
#   * real bind authentication (slapd verifies hashed userPassword)
#   * real schema enforcement (undefined attributes rejected by the server)
#
# Skips cleanly when slapd / Test::OpenLDAP / the OS schema files are absent.

use Test::More;
use File::Basename ();
use File::Spec;
use lib File::Spec->catdir( File::Basename::dirname(__FILE__), 'lib' );
use NisabaSlapdTest;

my ( $env, $skip ) = NisabaSlapdTest::setup();
plan skip_all => $skip if $skip;

my $pt = $env->{pt};
sub pt_try { return NisabaSlapdTest::pt_try( $pt, @_ ) }

END { NisabaSlapdTest::teardown($env) }

# slapd startup can take a few seconds; still guard against wedging.
alarm(300);
local $SIG{ALRM} = sub { die "test watchdog expired — slapd wedged?\n" };

# ── connect() over ldapi:// ─────────────────────────────────────────────────

my $ldap_check = $pt->connect;
ok( $ldap_check && !$pt->error, 'App::Nisaba::connect() binds to slapd over ldapi://' );

# ── Schema availability (needs a real subschema subentry) ───────────────────

my ( $ret, $err );

( $ret, $err ) = pt_try( sub { $pt->oidcSchemaAvailable } );
is( $err, '', 'oidcSchemaAvailable ran' );
ok( $ret, 'oidc schema detected via subschema discovery' );

( $ret, $err ) = pt_try( sub { $pt->passkeySchemaAvailable } );
ok( $ret, 'passkey schema detected' );

( $ret, $err ) = pt_try( sub { $pt->totpSchemaAvailable } );
ok( $ret, 'totp schema detected' );

( $ret, $err ) = pt_try( sub { $pt->ldapPublicKeyAvailable } );
ok( $ret, 'openssh-lpk (ldapPublicKey) schema detected' );

# ── CRUD smoke against real schema enforcement ──────────────────────────────

( $ret, $err ) = pt_try( sub { $pt->addGroup( { group => 'devs', gid => 5000 } ) } );
is( $err, '', 'addGroup accepted by real slapd (posixGroup schema-valid)' );

( $ret, $err ) = pt_try(
	sub {
		$pt->addUser(
			{
				user  => 'alice',
				uid   => 6000,
				group => 'devs',
				gecos => 'Alice Wonderland',
				shell => '/bin/sh',
			}
		);
	}
);
is( $err, '', 'addUser accepted by real slapd (posixAccount schema-valid)' );

my ($entry);
( $entry, $err ) = pt_try( sub { $pt->getUserEntry( { user => 'alice' } ) } );
is( $err, '', 'getUserEntry works against slapd' );
is( $entry->get_value('gecos'), 'Alice Wonderland', 'gecos round-trips through slapd' );

( $ret, $err ) = pt_try(
	sub {
		$pt->addNetgroup(
			{ group => 'webservers', triples => ['(www1,,example.com)'] } );
	}
);
is( $err, '', 'addNetgroup accepted by real slapd (nisNetgroup schema-valid)' );

( $ret, $err ) = pt_try(
	sub {
		$pt->addOIDCClient(
			{
				clientId     => 'testapp',
				clientSecret => 's3cret',
				clientName   => 'Test App',
				authMethod   => 'client_secret_basic',
				redirectURIs => ['https://testapp.example.com/callback'],
				scopes       => [ 'openid', 'profile' ],
			}
		);
	}
);
is( $err, '', 'addOIDCClient accepted by real slapd (oidcRelyingParty schema-valid)' );

( $entry, $err ) = pt_try( sub { $pt->getOIDCClientEntry( { clientId => 'testapp' } ) } );
is( $err, '', 'getOIDCClientEntry works against slapd' );
is( $entry->get_value('oidcClientName'), 'Test App', 'OIDC client attrs round-trip' );

# An attribute the schema does not define must be rejected BY THE SERVER —
# this exercises App::Nisaba's LDAP-error handling with a genuine slapd error.
( $ret, $err ) = pt_try(
	sub {
		$pt->oidcClientUpdate(
			{ clientId => 'testapp', attribute => 'noSuchAttribute', value => 'x' } );
	}
);
isnt( $err, '', 'undefined attribute rejected by real schema enforcement' );
is( $pt->error, 34, 'schema violation surfaces as error 34 (updateFailed)' );
like( $err, qr/undefined/i, 'error message carries the slapd schema diagnostic' );

# ── Password lifecycle: SetPassword extended operation ──────────────────────

( $ret, $err ) = pt_try( sub { $pt->userHasPassword( { user => 'alice' } ) } );
is( $err, '', 'userHasPassword ran' );
ok( !$ret, 'new user has no password' );

( $ret, $err ) = pt_try( sub { $pt->userSetPass( { user => 'alice', pass => 'correct horse' } ) } );
is( $err, '', 'userSetPass succeeds (SetPassword extended operation)' );

( $ret, $err ) = pt_try( sub { $pt->userHasPassword( { user => 'alice' } ) } );
ok( $ret, 'user has a password after userSetPass' );

# slapd stores the password hashed; verification is real bind authentication.
( $ret, $err ) = pt_try(
	sub { $pt->userVerifyPassword( { user => 'alice', password => 'correct horse' } ) } );
is( $err, '', 'correct password verifies via real slapd bind' );
is( $ret, 1,  'userVerifyPassword returns 1' );

( $ret, $err ) = pt_try(
	sub { $pt->userVerifyPassword( { user => 'alice', password => 'battery staple' } ) } );
isnt( $err, '', 'wrong password rejected by real slapd bind' );
is( $pt->error, 75, 'wrong password sets error 75 (authFailed)' );

# Self-service variant (also SetPassword extop).
( $ret, $err ) = pt_try(
	sub { $pt->userSetPassSelf( { user => 'alice', pass => 'new-pass-123' } ) } );
is( $err, '', 'userSetPassSelf succeeds' );

( $ret, $err ) = pt_try(
	sub { $pt->userVerifyPassword( { user => 'alice', password => 'new-pass-123' } ) } );
is( $err, '', 'password changed by userSetPassSelf verifies' );

( $ret, $err ) = pt_try(
	sub { $pt->userVerifyPassword( { user => 'alice', password => 'correct horse' } ) } );
isnt( $err, '', 'old password no longer verifies after the change' );

# Remove the password.
( $ret, $err ) = pt_try( sub { $pt->userRemovePassword( { user => 'alice' } ) } );
is( $err, '', 'userRemovePassword succeeds' );

( $ret, $err ) = pt_try( sub { $pt->userHasPassword( { user => 'alice' } ) } );
ok( !$ret, 'password gone after userRemovePassword' );

( $ret, $err ) = pt_try(
	sub { $pt->userVerifyPassword( { user => 'alice', password => 'new-pass-123' } ) } );
isnt( $err, '', 'authentication fails once the password is removed' );

# ── inetOrgPerson conversion against real structural-class rules ────────────
# userConvertToInetOrgPerson swaps the structural class (account →
# inetOrgPerson) by rebuilding the entry; OpenLDAP enforces structural-class
# rules for modify, so this proves the rebuild strategy works on a real
# server.

( $ret, $err ) = pt_try( sub { $pt->userConvertToInetOrgPerson( { user => 'alice' } ) } );
is( $err, '', 'userConvertToInetOrgPerson succeeds against real slapd' );

( $entry, $err ) = pt_try( sub { $pt->getUserEntry( { user => 'alice' } ) } );
my %oc = map { lc($_) => 1 } $entry->get_value('objectClass');
ok( $oc{inetorgperson}, 'entry now carries inetOrgPerson' );
ok( !$oc{account},      'structural class account was dropped' );

( $ret, $err ) = pt_try( sub { $pt->userMailAdd( { user => 'alice', mail => 'alice@example.com' } ) } );
is( $err, '', 'userMailAdd succeeds post-conversion' );
( $ret, $err ) = pt_try( sub { $pt->userSNchange( { user => 'alice', sn => 'Wonderland' } ) } );
is( $err, '', 'userSNchange succeeds post-conversion' );
( $entry, $err ) = pt_try( sub { $pt->getUserEntry( { user => 'alice' } ) } );
is( $entry->get_value('mail'), 'alice@example.com', 'mail round-trips' );
is( $entry->get_value('sn'),   'Wonderland',        'sn round-trips' );

# ── Cleanup on the real server ──────────────────────────────────────────────

( $ret, $err ) = pt_try( sub { $pt->deleteOIDCClient('testapp') } );
is( $err, '', 'deleteOIDCClient works against slapd' );
( $ret, $err ) = pt_try( sub { $pt->deleteNetgroup( { group => 'webservers' } ) } );
is( $err, '', 'deleteNetgroup works against slapd' );
( $ret, $err ) = pt_try( sub { $pt->deleteUser( { user => 'alice' } ) } );
is( $err, '', 'deleteUser works against slapd' );

# alice was the only member of her primary group, so deleteUser's removeGroup
# cascade (on by default) deleted 'devs' too.
( $ret, $err ) = pt_try( sub { $pt->isLDAPgroup('devs') } );
ok( !$ret, 'empty primary group cascade-deleted with the user' );

( $ret, $err ) = pt_try( sub { $pt->getUsers } );
is_deeply( $ret, [], 'no users remain' );
( $ret, $err ) = pt_try( sub { $pt->getGroups } );
is_deeply( $ret, [], 'no groups remain' );

done_testing;
