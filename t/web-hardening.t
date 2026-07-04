#!perl
use strict;
use warnings;

# Stub File::ShareDir::dist_dir so the web app can start without the dist
# being installed. Must happen before the web modules are loaded.
use File::Basename ();
use File::Spec;
BEGIN {
	my $share = File::Spec->rel2abs(
		File::Spec->catdir( File::Basename::dirname(__FILE__), File::Spec->updir, 'share' )
	);
	require File::ShareDir;
	no warnings 'redefine';
	*File::ShareDir::dist_dir = sub { $share };

	# The web apps refuse to start without an explicit session secret.
	$ENV{NISABA_SECRET} = 'test-secret-nisaba' unless defined $ENV{NISABA_SECRET};

	# NOTE: deliberately do NOT set NISABA_COOKIE_SECURE here — this test checks
	# the secure-by-default behaviour and then the explicit opt-out.
}
use Test::More;

# ── secure_compare ────────────────────────────────────────────────────────────

require_ok('App::Nisaba::WebUtil');
App::Nisaba::WebUtil->import('secure_compare');

ok( secure_compare( 'abc',        'abc' ),        'equal strings compare true' );
ok( !secure_compare( 'abc',       'abd' ),        'different same-length strings compare false' );
ok( !secure_compare( 'abc',       'abcd' ),       'different-length strings compare false' );
ok( !secure_compare( '',          'x' ),          'empty vs non-empty compare false' );
ok( secure_compare( '',           '' ),           'two empty strings compare true' );
ok( !secure_compare( undef,       'x' ),          'undef operand compares false' );
ok( secure_compare( "\x00a\xff",  "\x00a\xff" ),  'binary-safe equal compare true' );

# ── session cookie flags ──────────────────────────────────────────────────────

SKIP: {
	eval { require Test::Mojo; require App::Nisaba::WebSelfService; 1 }
		or skip( "Mojolicious / WebSelfService unavailable: $@", 4 );

	# Default (no NISABA_COOKIE_SECURE): cookie must be Secure + SameSite=Lax.
	{
		local $ENV{NISABA_COOKIE_SECURE};
		delete $ENV{NISABA_COOKIE_SECURE};
		my $t = Test::Mojo->new('App::Nisaba::WebSelfService');
		$t->get_ok('/login')
		  ->header_like( 'Set-Cookie' => qr/;\s*secure/i,          'session cookie is Secure by default' )
		  ->header_like( 'Set-Cookie' => qr/;\s*SameSite=Lax/i,    'session cookie is SameSite=Lax' );
	}

	# Opt-out: NISABA_COOKIE_SECURE=0 drops the Secure flag (plain-HTTP dev).
	{
		local $ENV{NISABA_COOKIE_SECURE} = '0';
		my $t = Test::Mojo->new('App::Nisaba::WebSelfService');
		$t->get_ok('/login')
		  ->header_unlike( 'Set-Cookie' => qr/;\s*secure/i, 'NISABA_COOKIE_SECURE=0 drops the Secure flag' );
	}
}

done_testing();
