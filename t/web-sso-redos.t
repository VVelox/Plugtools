#!perl
use strict;
use warnings;

# ReDoS / hang watchdog for App::Nisaba::WebSSO, in-process via Test::Mojo. Sends
# pathological inputs across the request-parsing surfaces (scope splitting,
# id_token_hint, Basic auth, oversized params, nested JSON) and asserts each
# request completes within a time budget. Because a CPU-bound catastrophic-
# backtracking regex would block the event loop (so a request-timeout could never
# fire), the bound here is a signal-based alarm() — the correct tool for ReDoS.
#
# Pure Perl, deterministic, no daemon and no external services. A future change
# that introduces a pathological regex over attacker input trips these.

use File::Basename ();
use File::Spec;

BEGIN {
	my $share
		= File::Spec->rel2abs( File::Spec->catdir( File::Basename::dirname(__FILE__), File::Spec->updir, 'share' ) );
	require File::ShareDir;
	no warnings 'redefine';
	*File::ShareDir::dist_dir = sub { $share };

	$ENV{NISABA_SECRET}        = 'test-secret-nisaba' unless defined $ENV{NISABA_SECRET};
	$ENV{NISABA_COOKIE_SECURE} = '0'                  unless defined $ENV{NISABA_COOKIE_SECURE};
	$ENV{NISABA_REQUIRE_PKCE}  = '0'                  unless defined $ENV{NISABA_REQUIRE_PKCE};
	$ENV{NISABA_RATELIMIT}     = '0'                  unless defined $ENV{NISABA_RATELIMIT};
} ## end BEGIN

use Test::More;
use Mojo::URL ();
use FindBin   ();
use lib "$FindBin::Bin/lib";

eval { require App::Nisaba::WebSSO; 1 } or plan skip_all => "App::Nisaba::WebSSO failed to load: $@";

my $STORAGE;
eval {
	require App::Nisaba::WebSSO::Storage;
	$STORAGE = App::Nisaba::WebSSO::Storage->new( { backend => 'SQLite', path => ':memory:' } );
	1;
} or plan skip_all => "App::Nisaba::WebSSO::Storage unavailable (DBD::SQLite?): $@";

eval { require Test::Mojo; 1 } or plan skip_all => "Test::Mojo unavailable: $@";

# alarm() is required for the CPU-bound watchdog.
plan skip_all => 'alarm() not available on this platform'
	unless eval {
		local $SIG{ALRM} = sub { };
		alarm(0);
		1;
	};

use NisabaWebSSOMock;

my $t = Test::Mojo->new('App::Nisaba::WebSSO');
NisabaWebSSOMock::install_stubs( $t->app, storage => $STORAGE );

my $BUDGET = 8;    # seconds; normal responses are single-digit ms

# Run $fn under a signal alarm; assert it returned in time and not with a 500.
sub probe {
	my ( $desc, $fn ) = @_;
	my $tx;
	my $ok = eval {
		local $SIG{ALRM} = sub { die "timeout\n" };
		alarm($BUDGET);
		$tx = $fn->();
		alarm(0);
		1;
	};
	alarm(0);
	if ( !$ok ) {
		ok( 0, "$desc: did NOT complete within ${BUDGET}s — possible ReDoS/hang" );
		return;
	}
	my $code = $tx ? $tx->res->code : undef;
	ok( defined $code && $code != 500,
		"$desc: responded within ${BUDGET}s (HTTP " . ( defined $code ? $code : '?' ) . ')' );
	return;
} ## end sub probe

my $reg  = $NisabaWebSSOMock::REDIRECT_URI;
my $cid  = $NisabaWebSSOMock::CLIENT_ID;
my $big  = 'x' x 200_000;
my $many = join ' ', ('a') x 40_000;

sub authorize {
	my (%o) = @_;
	my $url
		= Mojo::URL->new('/authorize')
		->query(
			{ response_type => 'code', client_id => $cid, redirect_uri => $reg, scope => 'openid', state => 's', %o } );
	return $t->ua->get($url);
}

# ── Pathological inputs across the parsing surfaces ──────────────────────────
probe( 'authorize: one enormous scope token',          sub { authorize( scope => "openid $big" ) } );
probe( 'authorize: tens of thousands of scope tokens', sub { authorize( scope => "openid $many" ) } );
probe( 'authorize: enormous state',                    sub { authorize( state => $big ) } );
probe( 'authorize: enormous redirect_uri', sub { authorize( redirect_uri => "https://x.example.com/$big" ) } );
probe( 'authorize: enormous client_id',    sub { authorize( client_id    => $big ) } );

probe(
	'logout: id_token_hint with 100k dot segments',
	sub { $t->ua->get( Mojo::URL->new('/sso/logout')->query( { id_token_hint => join( '.', ('a') x 100_000 ) } ) ) }
);
probe( 'logout: enormous id_token_hint',
	sub { $t->ua->get( Mojo::URL->new('/sso/logout')->query( { id_token_hint => $big } ) ) } );

probe(
	'token: enormous Basic auth credential',
	sub {
		$t->ua->post(
			'/token',
			{ Authorization => 'Basic ' . ( 'A' x 200_000 ) },
			form => { grant_type => 'authorization_code', code => 'x' }
		);
	}
);
probe( 'userinfo: enormous Bearer token', sub { $t->ua->get( '/userinfo', { Authorization => 'Bearer ' . $big } ) } );
probe(
	'passkey finish: deeply nested JSON',
	sub {
		$t->ua->post(
			'/sso/passkeys/login/finish',
			{ 'Content-Type' => 'application/json' },
			( '[' x 5000 ) . '1' . ( ']' x 5000 )
		);
	}
);

done_testing;
