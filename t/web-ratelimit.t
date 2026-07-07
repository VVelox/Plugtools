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

done_testing();
