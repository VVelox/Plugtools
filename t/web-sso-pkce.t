#!perl
use strict;
use warnings;

use FindBin ();
use lib "$FindBin::Bin/lib";
use NisabaWebTest;
use Test::More;
use Mojo::Util ();
use Test::Mojo;

eval { require App::Nisaba::WebSSO };
plan skip_all => "App::Nisaba::WebSSO failed to load: $@" if $@;

my $pubapp = FakeEntry->new(
	oidcClientId                => 'pubapp',
	oidcRedirectURI             => 'https://pub.example.com/cb',
	oidcTokenEndpointAuthMethod => 'none',                         # public: no client secret
);

my $confapp = FakeEntry->new(
	oidcClientId                => 'confapp',
	oidcRedirectURI             => 'https://conf.example.com/cb',
	oidcClientSecret            => 'sekret',
	oidcTokenEndpointAuthMethod => 'client_secret_basic',
);

# Build a WebSSO app whose client registry knows pubapp/confapp. $ini lets a
# test control ssoRequirePkce.
sub _build_app {
	my (%ini) = @_;
	my $t = Test::Mojo->new('App::Nisaba::WebSSO');

	my %methods = (
		error              => sub { 0 },
		errorString        => sub { '' },
		errorblank         => sub { },
		getOIDCClientEntry => sub {
			my ( $s, $a ) = @_;
			my $id = $a->{clientId} // '';
			return $pubapp  if $id eq 'pubapp';
			return $confapp if $id eq 'confapp';
			return undef;
		},
	);
	my $fake = bless { ini => { '' => {%ini} } }, 'FakePT';
	Mojo::Util::monkey_patch( 'FakePT', %methods );
	$t->app->helper( pt => sub { $fake } );
	return $t;
} ## end sub _build_app

my $PUB  = 'https://pub.example.com/cb';
my $CONF = 'https://conf.example.com/cb';

# A syntactically valid code_challenge (RFC 7636: 43-128 unreserved chars).
my $CHALLENGE = 'a' x 43;

sub _authorize {
	my ( $client, $redirect, %extra ) = @_;
	my $q = "client_id=$client&redirect_uri=$redirect&response_type=code&scope=openid";
	$q .= "&$_=$extra{$_}" for sort keys %extra;
	return "/authorize?$q";
}

# ── Enforcement ON (default) ──────────────────────────────────────────────────

my $t = _build_app();

# Public client, no PKCE → rejected back to the client with invalid_request.
$t->get_ok( _authorize( 'pubapp', $PUB, state => 'p1' ) )
	->status_is(302)
	->header_like( Location => qr{^\Q$PUB\E\?},           'public/no-PKCE error returns to the client' )
	->header_like( Location => qr{error=invalid_request}, 'public client without PKCE is rejected' );

# Public client, S256 PKCE → allowed, proceeds to login.
$t->get_ok( _authorize( 'pubapp', $PUB, state => 'p2', code_challenge => $CHALLENGE, code_challenge_method => 'S256' ) )
	->status_is(302)
	->header_like( Location => qr{/sso/login}, 'public client with S256 PKCE proceeds to login' );

# Public client, plain PKCE → rejected (S256 required).
$t->get_ok(
	_authorize( 'pubapp', $PUB, state => 'p3', code_challenge => $CHALLENGE, code_challenge_method => 'plain' ) )
	->status_is(302)
	->header_like( Location => qr{error=invalid_request}, 'public client with plain PKCE is rejected' );

# Public client, code_challenge but no method (defaults to plain) → rejected.
$t->get_ok( _authorize( 'pubapp', $PUB, state => 'p4', code_challenge => $CHALLENGE ) )
	->status_is(302)
	->header_like( Location => qr{error=invalid_request}, 'public client defaulting to plain is rejected' );

# Confidential client, no PKCE → allowed (it authenticates with its secret).
$t->get_ok( _authorize( 'confapp', $CONF, state => 'c1' ) )
	->status_is(302)
	->header_like( Location => qr{/sso/login}, 'confidential client without PKCE is allowed' );

# ── Escape hatch: ssoRequirePkce=0 relaxes the requirement ────────────────────

my $t_off = _build_app( ssoRequirePkce => 0 );

$t_off->get_ok( _authorize( 'pubapp', $PUB, state => 'off1' ) )
	->status_is(302)
	->header_like( Location => qr{/sso/login}, 'ssoRequirePkce=0 lets a public client skip PKCE' );

done_testing();
