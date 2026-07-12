#!perl
use strict;
use warnings;

use File::Basename ();
use File::Spec;
use File::Temp ();

BEGIN {
	my $share
		= File::Spec->rel2abs( File::Spec->catdir( File::Basename::dirname(__FILE__), File::Spec->updir, 'share' ) );
	require File::ShareDir;
	no warnings 'redefine';
	*File::ShareDir::dist_dir = sub { $share };

	$ENV{NISABA_SECRET}        = 'test-secret-nisaba' unless defined $ENV{NISABA_SECRET};
	$ENV{NISABA_COOKIE_SECURE} = '0'                  unless defined $ENV{NISABA_COOKIE_SECURE};
} ## end BEGIN
use Test::More;
use Mojo::Util ();
use Test::Mojo;

# ── Unit: the RateLimiter engine ──────────────────────────────────────────────

require_ok('App::Nisaba::WebUtil::RateLimiter');

my $now = 1_000;
my $rl  = App::Nisaba::WebUtil::RateLimiter->new(
	{
		path     => ':memory:',
		now      => sub { $now },
		policies => {
			login  => { max => 3, window => 100, lockout => 60 },
			forgot => { max => 2, window => 100, lockout => 60 },
		},
	}
);

my $allowed = sub { $rl->check(@_)->{allowed} };

ok( $allowed->( 'login', 'alice' ), 'fresh key is allowed' );
$rl->fail( 'login', 'alice' );
$rl->fail( 'login', 'alice' );
ok( $allowed->( 'login', 'alice' ), 'still allowed below threshold' );
$rl->fail( 'login', 'alice' );    # 3rd failure -> lock
ok( !$allowed->( 'login', 'alice' ), 'locked once the threshold is reached' );
is( $rl->check( 'login', 'alice' )->{retry_after}, 60, 'retry_after equals the lockout' );

ok( $allowed->( 'login', 'bob' ), 'a different key is independent' );

$now = 1_040;
is( $rl->check( 'login', 'alice' )->{retry_after}, 20, 'retry_after counts down as time passes' );
$now = 1_061;
ok( $allowed->( 'login', 'alice' ), 'allowed again once the lockout expires' );

# reset clears immediately
$now = 2_000;
$rl->fail( 'login', 'carol' );
$rl->fail( 'login', 'carol' );
$rl->fail( 'login', 'carol' );
ok( !$allowed->( 'login', 'carol' ), 'carol locked' );
$rl->reset( 'login', 'carol' );
ok( $allowed->( 'login', 'carol' ), 'reset clears the lock' );

# window expiry: failures that age out do not accumulate into a lock
$now = 3_000;
$rl->fail( 'login', 'dave' );
$rl->fail( 'login', 'dave' );
$now = 3_200;    # past the 100s window
$rl->fail( 'login', 'dave' );
ok( $allowed->( 'login', 'dave' ), 'failures older than the window do not count toward a lock' );

# hit() mode (request-rate): every call counts, blocks at the threshold
$now = 4_000;
ok( $rl->hit( 'forgot',  'e' )->{allowed}, 'forgot hit 1 allowed' );
ok( !$rl->hit( 'forgot', 'e' )->{allowed}, 'forgot hit 2 reaches the limit and blocks' );

# cleanup removes only expired rows
$now = 100_000;
my $removed = $rl->cleanup;
ok( $removed >= 1, 'cleanup removes expired rows' );

# ── Fail-closed: an unusable store makes new() die ────────────────────────────

my $dir = File::Temp->newdir;
my $bad = eval {
	App::Nisaba::WebUtil::RateLimiter->new( { path => $dir->dirname } );    # a directory is not a DB file
	1;
};
ok( !$bad, 'opening the store at an unusable path fails (caller fails closed)' );

# ── Integration: self-service login is throttled ──────────────────────────────

SKIP: {
	eval { require App::Nisaba::WebSelfService; 1 }
		or skip( "WebSelfService unavailable: $@", 8 );

	my $build = sub {
		my (%ini)   = @_;
		my $t       = Test::Mojo->new('App::Nisaba::WebSelfService');
		my %methods = (
			error              => sub { 0 },
			errorString        => sub { '' },
			errorblank         => sub { },
			userVerifyPassword => sub {
				my ( $s, $a ) = @_;
				die "bad password\n" unless ( $a->{password} // '' ) eq 'correct';
			},
			userSelfInfo           => sub { return { totpStatus => 'inactive' } },
			smtpAvailable          => sub { 0 },                                     # login template renders reset_available
			passkeySchemaAvailable => sub { 0 },
		);
		my $fake = bless { ini => { '' => {%ini} } }, 'FakePT';
		Mojo::Util::monkey_patch( 'FakePT', %methods );
		$t->app->helper( pt => sub { $fake } );

		# same-origin Referer + valid CSRF on every POST
		$t->ua->on(
			start => sub {
				my ( $ua, $tx ) = @_;
				return unless $tx->req->method eq 'POST';
				my $host = $tx->req->url->to_abs->host_port // 'localhost';
				$tx->req->headers->referrer("http://$host/");
				$tx->req->headers->header( 'X-CSRF-Token' => 'testcsrf' );
			}
		);
		$t->app->hook( before_dispatch => sub { $_[0]->session( csrf_token => 'testcsrf' ) } );
		return $t;
	}; ## end $build = sub

	# Enabled, in-memory store, primary (user+ip) limit of 3; IP backstop high.
	my $t = $build->(
		rateLimit           => 1,
		rateLimitPath       => ':memory:',
		rateLimitLoginMax   => 3,
		rateLimitLoginIpMax => 9999,
	);

	# Three bad logins are answered normally (redirect back to the form)...
	$t->post_ok( '/login', form => { user => 'alice', pass => 'nope' } )->status_is(302);
	$t->post_ok( '/login', form => { user => 'alice', pass => 'nope' } )->status_is(302);
	$t->post_ok( '/login', form => { user => 'alice', pass => 'nope' } )->status_is(302);
	# ...the fourth is throttled.
	$t->post_ok( '/login', form => { user => 'alice', pass => 'nope' } )
		->status_is(429)
		->header_exists( 'Retry-After', '429 carries a Retry-After header' );

	# A different user from the same client is unaffected (separate user+ip bucket).
	$t->post_ok( '/login', form => { user => 'bob', pass => 'nope' } )
		->status_isnt( 429, 'a different username is not caught by the per-(user,ip) lock' );

	# Fail-closed: an unusable store denies the guarded endpoint with 503.
	my $bad_dir = File::Temp->newdir;
	my $tc      = $build->( rateLimit => 1, rateLimitPath => $bad_dir->dirname );
	$tc->post_ok( '/login', form => { user => 'alice', pass => 'correct' } )
		->status_is( 503, 'guarded endpoint fails closed when the limiter store is unavailable' );
} ## end SKIP:

# ── Integration: the SSO token endpoint is throttled ──────────────────────────
# Repeated failures (bogus codes, bad client credentials) are counted per
# (client_id, ip); once over the limit the endpoint answers 429 before the
# grant store is even consulted.

SKIP: {
	eval { require App::Nisaba::WebSSO; require App::Nisaba::WebSSO::Storage; 1 }
		or skip( "WebSSO unavailable: $@", 30 );

	# Minimal Net::LDAP::Entry stand-in for a registered OIDC client.
	{

		package FakeSSOEntry;
		sub new { my ( $c, %a ) = @_; return bless { attrs => \%a }, $c }

		sub get_value {
			my ( $self, $attr ) = @_;
			my $v = $self->{attrs}{$attr};
			return () unless defined $v;
			return wantarray ? ( ref $v ? @{$v} : ($v) ) : ( ref $v ? $v->[0] : $v );
		}
	}

	# A confidential client whose successful exchanges can reset the counter.
	my $good_entry = FakeSSOEntry->new(
		oidcClientId                 => 'goodclient',
		oidcClientSecret             => 'good-secret',
		oidcTokenEndpointAuthMethod  => 'client_secret_post',
		oidcIdTokenSignedResponseAlg => 'HS256',
	);

	my $build_sso = sub {
		my (%ini) = @_;
		my $t     = Test::Mojo->new('App::Nisaba::WebSSO');
		my $fake  = bless { ini => { '' => {%ini} } }, 'FakePTSSO';
		Mojo::Util::monkey_patch(
			'FakePTSSO',
			error                  => sub { 0 },
			errorString            => sub { '' },
			errorblank             => sub { },
			passkeySchemaAvailable => sub { 0 },
			getOIDCClientEntry     => sub {
				my ( $s, $a ) = @_;
				return $good_entry if ( $a->{clientId} // '' ) eq 'goodclient';
				return undef;
			},
		);
		$t->app->helper( pt => sub { $fake } );

		my $storage = App::Nisaba::WebSSO::Storage->new( { backend => 'SQLite', path => ':memory:' } );
		no warnings 'redefine';
		$t->app->helper( sso_storage => sub { $storage } );
		return ( $t, $storage );
	}; ## end $build_sso = sub

	my ($t) = $build_sso->(
		rateLimit           => 1,
		rateLimitPath       => ':memory:',
		rateLimitTokenMax   => 3,
		rateLimitTokenIpMax => 9999,
	);

	my %req = ( grant_type => 'authorization_code', code => 'bogus', client_id => 'bruteclient' );

	# Three failed attempts are answered normally (unknown client)...
	for my $n ( 1 .. 3 ) {
		$t->post_ok( '/token', form => {%req} )
			->status_is(401)
			->json_is( '/error' => 'invalid_client', "token failure $n answered normally" );
	}

	# ...the fourth is throttled before touching the grant store.
	$t->post_ok( '/token', form => {%req} )
		->status_is(429)
		->json_is( '/error' => 'too_many_requests', 'token endpoint throttles after repeated failures' )
		->header_exists( 'Retry-After', '429 carries a Retry-After header' );

	# A different client_id from the same IP has its own bucket.
	$t->post_ok( '/token', form => { %req, client_id => 'otherclient' } )
		->status_isnt( 429, 'a different client_id is not caught by the per-(client,ip) lock' );

	# ── Reset on success: a valid exchange clears the client's counter ────────

	my ( $t2, $storage2 ) = $build_sso->(
		rateLimit           => 1,
		rateLimitPath       => ':memory:',
		rateLimitTokenMax   => 3,
		rateLimitTokenIpMax => 9999,
	);

	my %bad_auth = (
		grant_type    => 'authorization_code',
		code          => 'bogus',
		client_id     => 'goodclient',
		client_secret => 'wrong',
	);

	# Two failures (wrong secret)...
	for my $n ( 1 .. 2 ) {
		$t2->post_ok( '/token', form => {%bad_auth} )->status_is( 401, "reset: failure $n answered normally" );
	}

	# ...then a valid exchange (correct secret redeeming a seeded code)...
	$storage2->put(
		'code',
		'goodcode',
		{ client_id => 'goodclient', user => 'alice', scope => 'openid', issued_at => time(), auth_time => time() },
		600,
	);
	$t2->post_ok(
		'/token',
		form => {
			grant_type    => 'authorization_code',
			code          => 'goodcode',
			client_id     => 'goodclient',
			client_secret => 'good-secret',
		}
	)->status_is( 200, 'reset: valid exchange succeeds' );

	# ...after which two more failures are answered normally. Without the
	# reset these would be failures three and four: the second of them would
	# already be blocked.
	for my $n ( 3 .. 4 ) {
		$t2->post_ok( '/token', form => {%bad_auth} )
			->status_is( 401, "reset: post-success failure $n is not throttled" );
	}

	# The counter still works after a reset: one more failure reaches the
	# limit and the next request is blocked.
	$t2->post_ok( '/token', form => {%bad_auth} )->status_is( 401, 'reset: third post-success failure' );
	$t2->post_ok( '/token', form => {%bad_auth} )
		->status_is( 429, 'reset: limit re-engages after enough new failures' );

	# ── Fail-closed: an unusable limiter store denies /token with 503 ─────────

	my $bad_sso_dir = File::Temp->newdir;
	my ($tc) = $build_sso->( rateLimit => 1, rateLimitPath => $bad_sso_dir->dirname );
	$tc->post_ok( '/token', form => { grant_type => 'authorization_code', code => 'x', client_id => 'y' } )
		->status_is( 503, 'token endpoint fails closed when the limiter store is unavailable' );
} ## end SKIP:

done_testing();
