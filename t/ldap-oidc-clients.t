#!perl
use strict;
use warnings;

# Tests App::Nisaba's OIDC client management against a real (in-memory) LDAP
# server via Net::LDAP::Server::Test. Unlike the web tests, which stub the
# whole pt layer, this exercises the actual App::Nisaba code paths: real
# Net::LDAP add/search/modify/delete round-trips, real filter escaping, and
# real LDAP error results (alreadyExists, noSuchAttribute, ...).
#
# The server/config/anchor-connection plumbing lives in t/lib/NisabaLDAPTest.pm
# (see its header comments for the harness gotchas).

use Test::More;
use File::Basename ();
use File::Spec;
use lib File::Spec->catdir( File::Basename::dirname(__FILE__), 'lib' );
use NisabaLDAPTest;

my ( $env, $skip ) = NisabaLDAPTest::setup();
plan skip_all => $skip if $skip;

my $pt = $env->{pt};
sub pt_try { return NisabaLDAPTest::pt_try( $pt, @_ ) }

END { NisabaLDAPTest::teardown($env) }

# Watchdog: if the test server ever wedges, fail loudly instead of hanging
# the whole test run (Net::LDAP requests have no read timeout).
alarm(120);
local $SIG{ALRM} = sub { die "test watchdog expired — LDAP server wedged?\n" };

my $oidcbase = $pt->{ini}{''}{oidcbase};
ok( $pt->oidcbaseConfigured, 'oidcbaseConfigured is true' );

# Prove the real connect() path works against the test server.
my $ldap_check = $pt->connect;
ok( $ldap_check && !$pt->error, 'App::Nisaba::connect() binds to the test LDAP server' );

# ── Empty base ──────────────────────────────────────────────────────────────

my ( $clients, $err ) = pt_try( sub { $pt->getOIDCClients } );
is( $err, '', 'getOIDCClients on empty base succeeds' );
is_deeply( $clients, [], 'getOIDCClients returns an empty arrayref initially' );

# ── addOIDCClient: full round-trip ──────────────────────────────────────────

my %app1 = (
	clientId                 => 'testapp',
	clientSecret             => 's3cret-value',
	clientName               => 'Test Application',
	authMethod               => 'client_secret_basic',
	applicationType          => 'web',
	idTokenSignedResponseAlg => 'RS256',
	clientURI                => 'https://testapp.example.com',
	redirectURIs             => [ 'https://testapp.example.com/callback', 'https://testapp.example.com/cb2' ],
	scopes                   => [ 'openid', 'profile', 'email' ],
	grantTypes               => ['authorization_code'],
	responseTypes            => ['code'],
	contacts                 => ['admin@example.com'],
);

( my $ret, $err ) = pt_try( sub { $pt->addOIDCClient( \%app1 ) } );
is( $err, '', 'addOIDCClient succeeds' );
is( $ret, 1,  'addOIDCClient returns 1' );

my ($entry);
( $entry, $err ) = pt_try( sub { $pt->getOIDCClientEntry( { clientId => 'testapp' } ) } );
is( $err, '', 'getOIDCClientEntry succeeds' );
isa_ok( $entry, 'Net::LDAP::Entry', 'returned entry' );
is( $entry->dn, "oidcClientId=testapp,$oidcbase", 'entry DN is under oidcbase' );
is( $entry->get_value('oidcClientId'),                 'testapp',             'oidcClientId round-trips' );
is( $entry->get_value('oidcClientSecret'),             's3cret-value',        'oidcClientSecret round-trips' );
is( $entry->get_value('oidcClientName'),               'Test Application',    'oidcClientName round-trips' );
is( $entry->get_value('oidcTokenEndpointAuthMethod'),  'client_secret_basic', 'authMethod round-trips' );
is( $entry->get_value('oidcApplicationType'),          'web',                 'applicationType round-trips' );
is( $entry->get_value('oidcIdTokenSignedResponseAlg'), 'RS256',               'signing alg round-trips' );

my @uris = sort $entry->get_value('oidcRedirectURI');
is_deeply(
	\@uris,
	[ 'https://testapp.example.com/callback', 'https://testapp.example.com/cb2' ],
	'multi-valued oidcRedirectURI round-trips'
);
my @scopes = sort $entry->get_value('oidcScope');
is_deeply( \@scopes, [ 'email', 'openid', 'profile' ], 'multi-valued oidcScope round-trips' );

# ── addOIDCClient: error paths ──────────────────────────────────────────────

( $ret, $err ) = pt_try( sub { $pt->addOIDCClient( { clientId => 'testapp' } ) } );
isnt( $err, '', 'adding a duplicate clientId fails' );
is( $pt->error, 98, 'duplicate clientId sets error 98 (oidcClientExists)' );

( $ret, $err ) = pt_try( sub { $pt->addOIDCClient( {} ) } );
isnt( $err, '', 'addOIDCClient without clientId fails' );
is( $pt->error, 99, 'missing clientId sets error 99 (noOidcClientId)' );

# ── Multiple clients ────────────────────────────────────────────────────────

( $ret, $err ) = pt_try(
	sub {
		$pt->addOIDCClient(
			{
				clientId     => 'secondapp',
				redirectURIs => ['https://secondapp.example.com/callback'],
			}
		);
	}
);
is( $err, '', 'second client added' );

( $clients, $err ) = pt_try( sub { $pt->getOIDCClients } );
is( $err, '', 'getOIDCClients succeeds with clients present' );
my @ids = sort map { $_->get_value('oidcClientId') } @{ $clients // [] };
is_deeply( \@ids, [ 'secondapp', 'testapp' ], 'getOIDCClients returns both clients' );

# Lookup of a nonexistent client: no entry, but not an error either.
( $entry, $err ) = pt_try( sub { $pt->getOIDCClientEntry( { clientId => 'nosuchapp' } ) } );
is( $err,   '',    'lookup of unknown client is not an error' );
is( $entry, undef, 'lookup of unknown client returns undef' );

# ── oidcClientUpdate: replace, delete, unknown client ───────────────────────

( $ret, $err ) = pt_try(
	sub {
		$pt->oidcClientUpdate(
			{ clientId => 'testapp', attribute => 'oidcClientName', value => 'Renamed App' } );
	}
);
is( $err, '', 'oidcClientUpdate replace succeeds' );
( $entry, $err ) = pt_try( sub { $pt->getOIDCClientEntry( { clientId => 'testapp' } ) } );
is( $entry->get_value('oidcClientName'), 'Renamed App', 'replace is visible on re-fetch' );

# Empty value deletes the attribute.
( $ret, $err ) = pt_try(
	sub {
		$pt->oidcClientUpdate( { clientId => 'testapp', attribute => 'oidcClientURI', value => '' } );
	}
);
is( $err, '', 'oidcClientUpdate with empty value succeeds (attribute delete)' );
( $entry, $err ) = pt_try( sub { $pt->getOIDCClientEntry( { clientId => 'testapp' } ) } );
is( $entry->get_value('oidcClientURI'), undef, 'attribute deleted by empty-value update' );

( $ret, $err ) = pt_try(
	sub {
		$pt->oidcClientUpdate(
			{ clientId => 'nosuchapp', attribute => 'oidcClientName', value => 'X' } );
	}
);
isnt( $err, '', 'oidcClientUpdate on unknown client fails' );
is( $pt->error, 99, 'unknown client sets error 99' );

# ── Multi-value add/remove ──────────────────────────────────────────────────

( $ret, $err ) = pt_try(
	sub {
		$pt->oidcClientAddMultiValue(
			{
				clientId  => 'secondapp',
				attribute => 'oidcRedirectURI',
				value     => 'https://secondapp.example.com/cb2',
			}
		);
	}
);
is( $err, '', 'oidcClientAddMultiValue succeeds' );
( $entry, $err ) = pt_try( sub { $pt->getOIDCClientEntry( { clientId => 'secondapp' } ) } );
my @second_uris = sort $entry->get_value('oidcRedirectURI');
is( scalar @second_uris, 2, 'redirect URI added (2 values present)' );

# Adding a value that already exists is a real LDAP error (typeOrValueExists).
( $ret, $err ) = pt_try(
	sub {
		$pt->oidcClientAddMultiValue(
			{
				clientId  => 'secondapp',
				attribute => 'oidcRedirectURI',
				value     => 'https://secondapp.example.com/cb2',
			}
		);
	}
);
isnt( $err, '', 'adding a duplicate value fails (typeOrValueExists from the server)' );

( $ret, $err ) = pt_try(
	sub {
		$pt->oidcClientRemoveMultiValue(
			{
				clientId  => 'secondapp',
				attribute => 'oidcRedirectURI',
				value     => 'https://secondapp.example.com/cb2',
			}
		);
	}
);
is( $err, '', 'oidcClientRemoveMultiValue succeeds' );
( $entry, $err ) = pt_try( sub { $pt->getOIDCClientEntry( { clientId => 'secondapp' } ) } );
my @after_remove = $entry->get_value('oidcRedirectURI');
is_deeply(
	[ sort @after_remove ],
	['https://secondapp.example.com/callback'],
	'removed value is gone, original remains'
);

# Removing from an attribute that does not exist is a real LDAP error.
( $ret, $err ) = pt_try(
	sub {
		$pt->oidcClientRemoveMultiValue(
			{ clientId => 'secondapp', attribute => 'oidcContact', value => 'x@example.com' } );
	}
);
isnt( $err, '', 'removing a value from a missing attribute fails (noSuchAttribute)' );

# ── Filter escaping: clientId with LDAP-filter metacharacters ───────────────
# getOIDCClientEntry builds a filter with escape_filter_value; a clientId
# containing ( ) * must round-trip and must NOT act as a wildcard/injection.

my $tricky = 'tricky(app)*name';
( $ret, $err ) = pt_try( sub { $pt->addOIDCClient( { clientId => $tricky } ) } );
is( $err, '', 'client with filter metacharacters in clientId added' );

( $entry, $err ) = pt_try( sub { $pt->getOIDCClientEntry( { clientId => $tricky } ) } );
is( $err, '', 'lookup with metacharacter clientId succeeds' );
is( ( $entry ? $entry->get_value('oidcClientId') : undef ),
	$tricky, 'metacharacter clientId round-trips exactly' );

# The '*' must have been escaped, not treated as a wildcard: a prefix with a
# bare '*' in it must not match the tricky client.
( $entry, $err ) = pt_try( sub { $pt->getOIDCClientEntry( { clientId => 'tricky(app)*' } ) } );
is( $entry, undef, 'metacharacters are escaped, not treated as wildcards' );

# ── deleteOIDCClient ────────────────────────────────────────────────────────

( $ret, $err ) = pt_try( sub { $pt->deleteOIDCClient('testapp') } );
is( $err, '', 'deleteOIDCClient succeeds' );

( $entry, $err ) = pt_try( sub { $pt->getOIDCClientEntry( { clientId => 'testapp' } ) } );
is( $entry, undef, 'deleted client is gone' );

( $clients, $err ) = pt_try( sub { $pt->getOIDCClients } );
@ids = sort map { $_->get_value('oidcClientId') } @{ $clients // [] };
is_deeply( \@ids, [ 'secondapp', $tricky ], 'remaining clients are intact after delete' );

( $ret, $err ) = pt_try( sub { $pt->deleteOIDCClient('testapp') } );
isnt( $err, '', 'deleting a nonexistent client fails' );
is( $pt->error, 99, 'delete of unknown client sets error 99' );

( $ret, $err ) = pt_try( sub { $pt->deleteOIDCClient(undef) } );
isnt( $err, '', 'deleteOIDCClient without a clientId fails' );

# ── oidcbase not configured ─────────────────────────────────────────────────

{
	local $pt->{ini}{''}{oidcbase} = '';
	( $ret, $err ) = pt_try( sub { $pt->getOIDCClients } );
	isnt( $err, '', 'getOIDCClients fails when oidcbase is unset' );
	is( $pt->error, 97, 'unset oidcbase sets error 97 (oidcbaseNotConfigured)' );
}

# Back to normal after the local override.
( $clients, $err ) = pt_try( sub { $pt->getOIDCClients } );
is( $err, '', 'getOIDCClients works again with oidcbase restored' );

done_testing;
