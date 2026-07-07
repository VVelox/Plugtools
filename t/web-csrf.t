#!perl
use strict;
use warnings;

# Stub File::ShareDir::dist_dir so the web apps can start without the dist
# being installed. Must happen before the web modules are loaded.
use File::Basename ();
use File::Spec;

BEGIN {
	my $share
		= File::Spec->rel2abs( File::Spec->catdir( File::Basename::dirname(__FILE__), File::Spec->updir, 'share' ) );
	require File::ShareDir;
	no warnings 'redefine';
	*File::ShareDir::dist_dir = sub { $share };

	# The web apps now refuse to start without an explicit session secret.
	$ENV{NISABA_SECRET} = 'test-secret-nisaba' unless defined $ENV{NISABA_SECRET};

	# Serve over plain HTTP in tests so the session cookie round-trips.
	$ENV{NISABA_COOKIE_SECURE} = '0' unless defined $ENV{NISABA_COOKIE_SECURE};
} ## end BEGIN
use Test::More;
use Test::Mojo;

eval { require App::Nisaba::WebCSRF };
plan skip_all => "App::Nisaba::WebCSRF failed to load: $@" if $@;

# ── Unit: origin normalization ────────────────────────────────────────────────

is( App::Nisaba::WebCSRF::_normalize_origin( Mojo::URL->new('http://host/path') ),
	'http://host:80', 'default http port folded to 80' );
is( App::Nisaba::WebCSRF::_normalize_origin( Mojo::URL->new('https://host/path') ),
	'https://host:443', 'default https port folded to 443' );
is( App::Nisaba::WebCSRF::_normalize_origin( Mojo::URL->new('http://host:80/') ),
	'http://host:80', 'explicit :80 equals bare http host' );
is( App::Nisaba::WebCSRF::_normalize_origin( Mojo::URL->new('http://host:8080/') ),
	'http://host:8080', 'non-default port preserved' );
is( App::Nisaba::WebCSRF::_normalize_origin( Mojo::URL->new('http://HOST/') ),
	'http://host:80', 'host is lower-cased' );
isnt(
	App::Nisaba::WebCSRF::_normalize_origin( Mojo::URL->new('http://host/') ),
	App::Nisaba::WebCSRF::_normalize_origin( Mojo::URL->new('https://host/') ),
	'scheme is significant (http != https on same host)',
);

# ── Integration: the self-service portal (previously had NO CSRF check) ────────

eval { require App::Nisaba::WebSelfService };
if ($@) {
	done_testing();
	exit 0;
}

my $t = Test::Mojo->new('App::Nisaba::WebSelfService');

# GET is never blocked
$t->get_ok('/login')->status_isnt( 403, 'self-service GET /login is not blocked' );

# POST with no Origin/Referer at all → 403
$t->post_ok('/password')->status_is( 403, 'self-service POST with no origin header is blocked' );

# POST with a cross-origin Referer → 403
$t->ua->once(
	start => sub {
		my ( $ua, $tx ) = @_;
		$tx->req->headers->referrer('http://evil.example.com/attack');
	}
);
$t->post_ok('/password')->status_is( 403, 'self-service POST with cross-origin Referer is blocked' );

# POST with a cross-origin Origin header → 403 (Origin cannot be spoofed by page JS)
$t->ua->once(
	start => sub {
		my ( $ua, $tx ) = @_;
		$tx->req->headers->origin('http://evil.example.com');
	}
);
$t->post_ok('/password')->status_is( 403, 'self-service POST with cross-origin Origin is blocked' );

# Layer 2 (synchronizer token): a matching Origin alone is no longer enough.
# Without the per-session token the request is still blocked.
$t->ua->once(
	start => sub {
		my ( $ua, $tx ) = @_;
		my $origin = $tx->req->url->to_abs->scheme . '://' . $tx->req->url->to_abs->host_port;
		$tx->req->headers->origin($origin);
	}
);
$t->post_ok('/password')->status_is( 403, 'matching Origin but no CSRF token is still blocked' );

# Seed a known session token; matching Origin + matching token now satisfies both
# layers and falls through to the require_login bridge (a redirect, not a 403).
$t->app->hook( before_dispatch => sub { $_[0]->session( csrf_token => 'tok123' ) } );
$t->ua->once(
	start => sub {
		my ( $ua, $tx ) = @_;
		my $origin = $tx->req->url->to_abs->scheme . '://' . $tx->req->url->to_abs->host_port;
		$tx->req->headers->origin($origin);
		$tx->req->headers->header( 'X-CSRF-Token' => 'tok123' );
	}
);
$t->post_ok('/password')->status_isnt( 403, 'matching Origin and valid CSRF token passes both layers' );

# And the token in a form field (not just the header) is accepted.
$t->ua->once(
	start => sub {
		my ( $ua, $tx ) = @_;
		my $origin = $tx->req->url->to_abs->scheme . '://' . $tx->req->url->to_abs->host_port;
		$tx->req->headers->origin($origin);
	}
);
$t->post_ok( '/password', form => { csrf_token => 'tok123' } )
	->status_isnt( 403, 'CSRF token supplied as a form field is accepted' );

done_testing();
