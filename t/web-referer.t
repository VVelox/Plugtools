#!perl
use strict;
use warnings;

use FindBin ();
use lib "$FindBin::Bin/lib";
use NisabaWebTest;
use Test::More;
use Test::Mojo;

# Skip if the web module itself won't load (e.g. missing Mojolicious)
eval { require App::Nisaba::Web };
if ($@) {
	plan skip_all => "App::Nisaba::Web failed to load: $@";
}

plan tests => 6;

my $t = Test::Mojo->new('App::Nisaba::Web');

# ── GET requests are never blocked ────────────────────────────────────────────

$t->get_ok('/users')->status_isnt( 403, 'GET with no Referer is not blocked' );

# ── POST with no Referer → 403 ────────────────────────────────────────────────

$t->post_ok('/users')->status_is( 403, 'POST with no Referer is blocked' );

# ── POST with a Referer from a different host → 403 ──────────────────────────

$t->ua->on(
	start => sub {
		my ( $ua, $tx ) = @_;
		$tx->req->headers->referrer('http://evil.example.com/attack');
	}
);

$t->post_ok('/users')->status_is( 403, 'POST with mismatched Referer host is blocked' );

# Remove the hook so further requests are unaffected
$t->ua->unsubscribe('start');

done_testing;
