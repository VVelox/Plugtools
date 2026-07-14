#!perl
use strict;
use warnings;

# LDAP-injection resistance tests against a REAL OpenLDAP slapd (Test::OpenLDAP,
# see t/lib/NisabaSlapdTest.pm). The user-lookup and login paths build LDAP
# search filters from caller-supplied values (the login username, the OIDC
# client_id); if those were interpolated unescaped, filter metacharacters
# (* ( ) \ and filter-breaking sequences like ")(uid=*") would let an attacker
# match arbitrary entries or subvert the filter.
#
# App::Nisaba escapes them with escape_filter_value; this test proves that holds
# against a real directory — including the login BIND path, which the in-memory
# harness (t/ldap-oidc-clients.t already covers client_id escaping there) cannot
# exercise because it does not verify passwords via bind.
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

my ( $ret, $err, $entry );

# ── Seed a user (with a real password) and an OIDC client ────────────────────

( $ret, $err ) = pt_try( sub { $pt->addGroup( { group => 'devs', gid => 5000 } ) } );
is( $err, '', 'addGroup seeds a group' );

( $ret, $err ) = pt_try( sub { $pt->addUser( { user => 'alice', uid => 6000, group => 'devs' } ) } );
is( $err, '', 'addUser seeds alice' );

( $ret, $err ) = pt_try( sub { $pt->userSetPass( { user => 'alice', pass => 'correct horse' } ) } );
is( $err, '', 'userSetPass gives alice a password' );

( $ret, $err ) = pt_try(
	sub {
		$pt->addOIDCClient(
			{
				clientId     => 'testapp',
				clientSecret => 's3cret',
				redirectURIs => ['https://testapp.example.com/callback'],
				scopes       => [ 'openid', 'profile' ],
			}
		);
	}
);
is( $err, '', 'addOIDCClient seeds a client' );

# ── Baselines: the legitimate lookups all resolve ────────────────────────────

( $entry, $err ) = pt_try( sub { $pt->getUserEntry( { user => 'alice' } ) } );
ok( $entry && $entry->get_value('uid') eq 'alice', 'baseline: getUserEntry(alice) resolves' );

( $ret, $err ) = pt_try( sub { $pt->userVerifyPassword( { user => 'alice', password => 'correct horse' } ) } );
is( $ret, 1, 'baseline: userVerifyPassword(alice, correct) succeeds via real bind' );

( $entry, $err ) = pt_try( sub { $pt->getOIDCClientEntry( { clientId => 'testapp' } ) } );
ok( $entry && $entry->get_value('oidcClientId') eq 'testapp', 'baseline: getOIDCClientEntry(testapp) resolves' );

# ── Injection on the user-lookup filter (getUserEntry) ───────────────────────
# A wildcard or filter-breaking username must NOT resolve to a real user, and
# must fail as a plain "not found" (error 17) rather than as an LDAP filter/search
# error — the latter would mean the metacharacters reached slapd's filter parser
# unescaped. getUserEntry reports a miss as error 17 by design, so this is the
# right signal here (unlike getOIDCClientEntry, whose miss is not an error).

for my $inj ( '*', 'alice*', 'a)(uid=alice', '*)(uid=*', 'alice)(objectClass=*' ) {
	( $entry, $err ) = pt_try( sub { $pt->getUserEntry( { user => $inj } ) } );
	is( $entry,     undef, "getUserEntry(user=$inj) does not match a user (metacharacters escaped)" );
	is( $pt->error, 17,    "getUserEntry(user=$inj) is a clean not-found, not a filter/search error" );
}

# Prove the distinction above is real: a genuine search failure (here, a base DN
# that does not exist) is reported as error 32, not masked as a clean not-found
# (17). Without this the error-17 assertions would be meaningless — a filter the
# server rejected would look identical to "no such user".
{
	local $pt->{ini}{''}{userbase} = 'ou=doesnotexist,dc=example,dc=com';
	( $entry, $err ) = pt_try( sub { $pt->getUserEntry( { user => 'alice' } ) } );
	is( $entry,     undef, 'getUserEntry against a missing base returns undef' );
	is( $pt->error, 32,    'a real search failure surfaces as error 32, not masked as not-found (17)' );
}

# ── Injection on the login BIND path (userVerifyPassword) ────────────────────
# Even with alice's REAL password, a wildcard username must not authenticate:
# a broken filter would resolve '*' to alice and then bind successfully.

for my $inj ( '*', 'alice)(uid=*', '*)(uid=*' ) {
	( $ret, $err ) = pt_try( sub { $pt->userVerifyPassword( { user => $inj, password => 'correct horse' } ) } );
	isnt( $ret, 1, "userVerifyPassword(user=$inj) does not authenticate despite a valid password" );
}

# ── Injection on the client-lookup filter (getOIDCClientEntry) ───────────────
# Same class, against a real directory (complements the in-memory coverage in
# t/ldap-oidc-clients.t).

for my $inj ( '*', 'testapp*', '*)(oidcClientId=*', 'testapp)(objectClass=*' ) {
	( $entry, $err ) = pt_try( sub { $pt->getOIDCClientEntry( { clientId => $inj } ) } );
	is( $err,   '',    "getOIDCClientEntry(clientId=$inj) is not a server error" );
	is( $entry, undef, "getOIDCClientEntry(clientId=$inj) does not match a client (metacharacters escaped)" );
}

# ── Injection on the group-lookup filters (findGroupDN / isLDAPgroup) ─────────
# The admin UI resolves groups by name (cn=...); the same escaping must hold.

( $ret, $err ) = pt_try( sub { $pt->findGroupDN('devs') } );
ok( $ret,                     'baseline: findGroupDN(devs) resolves to a DN' );
ok( $pt->isLDAPgroup('devs'), 'baseline: isLDAPgroup(devs) is true' );

for my $inj ( '*', 'devs*', '*)(cn=*', 'devs)(objectClass=*' ) {
	( $ret, $err ) = pt_try( sub { $pt->findGroupDN($inj) } );
	is( $ret, undef, "findGroupDN($inj) does not match a group (metacharacters escaped)" );
	ok( !$pt->isLDAPgroup($inj), "isLDAPgroup($inj) is false (metacharacters escaped)" );
}

# ── Injection on the netgroup-lookup filter (getNetgroupEntry) ────────────────
( $ret, $err ) = pt_try( sub { $pt->addNetgroup( { group => 'ng-team', triples => ['(host1,,example.com)'] } ) } );
is( $err, '', 'addNetgroup seeds a netgroup' );

( $entry, $err ) = pt_try( sub { $pt->getNetgroupEntry( { group => 'ng-team' } ) } );
ok( $entry, 'baseline: getNetgroupEntry(ng-team) resolves' );

for my $inj ( '*', 'ng-team*', '*)(cn=*', 'ng-team)(objectClass=*' ) {
	( $entry, $err ) = pt_try( sub { $pt->getNetgroupEntry( { group => $inj } ) } );
	is( $entry, undef, "getNetgroupEntry($inj) does not match a netgroup (metacharacters escaped)" );
}

done_testing;
