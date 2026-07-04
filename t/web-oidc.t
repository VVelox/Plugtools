#!perl
use strict;
use warnings;

# Stub File::ShareDir::dist_dir so the web app can start without the dist
# being installed. Must happen before App::Nisaba::Web is loaded.
use File::Basename ();
use File::Spec;
BEGIN {
	my $share = File::Spec->rel2abs(
		File::Spec->catdir( File::Basename::dirname(__FILE__), File::Spec->updir, 'share' )
	);
	require File::ShareDir;
	no warnings 'redefine';
	*File::ShareDir::dist_dir = sub { $share };

	$ENV{NISABA_SECRET}        = 'test-secret-nisaba' unless defined $ENV{NISABA_SECRET};
	$ENV{NISABA_COOKIE_SECURE} = '0'                  unless defined $ENV{NISABA_COOKIE_SECURE};
}
use Test::More;
use Test::Mojo;

eval { require App::Nisaba::Web };
plan skip_all => "App::Nisaba::Web failed to load: $@" if $@;

# ── Fake client entry ─────────────────────────────────────────────────────────
{

	package FakeEntry;
	sub new { my ( $c, %a ) = @_; return bless { attrs => \%a }, $c }
	sub get_value {
		my ( $self, $attr ) = @_;
		my $v = $self->{attrs}{$attr};
		return () unless defined $v;
		return wantarray ? ( ref $v ? @{$v} : ($v) ) : ( ref $v ? $v->[0] : $v );
	}
}

# A client that has both a secret and a signing key, so RS256/HS256 updates are
# not vetoed for lack of key material.
my $client = FakeEntry->new(
	oidcClientId                 => 'testclient',
	oidcClientSecret             => 'sekret',
	oidcJwks                     => '{"keys":[{"kty":"RSA","kid":"k1"}]}',
	oidcTokenEndpointAuthMethod  => 'client_secret_basic',
	oidcIdTokenSignedResponseAlg => 'RS256',
);

my @added;      # addOIDCClient calls
my @updated;    # oidcClientUpdate calls

sub _install_stubs {
	my ($app) = @_;
	my %methods = (
		error              => sub { 0 },
		errorString        => sub { '' },
		errorblank         => sub { },
		addOIDCClient      => sub { my ( $s, $a ) = @_; push @added, $a; return 1 },
		getOIDCClientEntry => sub { return $client },
		oidcClientUpdate   => sub { my ( $s, $a ) = @_; push @updated, $a; return 1 },
	);
	my $fake = bless { ini => { '' => {} } }, 'FakePT';
	for my $name ( keys %methods ) {
		no strict 'refs';
		no warnings 'redefine';
		*{"FakePT::$name"} = $methods{$name};
	}
	$app->helper( pt => sub { $fake } );
}

my $t = Test::Mojo->new('App::Nisaba::Web');
_install_stubs( $t->app );

$t->ua->on(
	start => sub {
		my ( $ua, $tx ) = @_;
		return unless $tx->req->method eq 'POST';
		my $host = $tx->req->url->to_abs->host_port // 'localhost';
		$tx->req->headers->referrer("http://$host/");
		$tx->req->headers->header( 'X-CSRF-Token' => 'testcsrf' );
	}
);
$t->app->hook( before_dispatch => sub { $_[0]->session( admin_user => 'admin', csrf_token => 'testcsrf' ) } );

# ── create: signingAlg=none is rejected ───────────────────────────────────────

@added = ();
$t->post_ok( '/oidc',
	form => { clientType => 'confidential', signingAlg => 'none', redirectURIs => 'https://app.example.com/cb' } )
	->status_is(302)
	->header_like( Location => qr{/oidc/add}, 'create with signingAlg=none is bounced back to the add form' );
is( scalar(@added), 0, 'no OIDC client was created with alg=none' );

# ── update: alg=none is rejected, no write performed ──────────────────────────

@updated = ();
$t->post_ok( '/oidc/testclient', form => { action => 'idTokenSignedResponseAlg', value => 'none' } )
	->status_is(302)
	->header_like( Location => qr{/oidc/testclient}, 'update alg=none redirects back to the client' );
is( scalar(@updated), 0, 'no update was written for alg=none' );

# ── update: clearing the alg is rejected (would fall back to unsigned) ─────────

@updated = ();
$t->post_ok( '/oidc/testclient', form => { action => 'idTokenSignedResponseAlg', value => '' } )
	->status_is(302)
	->header_like( Location => qr{/oidc/testclient}, 'clearing the alg is rejected' );
is( scalar(@updated), 0, 'no update was written when clearing the alg' );

# ── update: RS256 is accepted and written ─────────────────────────────────────

@updated = ();
$t->post_ok( '/oidc/testclient', form => { action => 'idTokenSignedResponseAlg', value => 'RS256' } )
	->status_is(302);
is( scalar(@updated),          1,       'RS256 update is written' );
is( $updated[0]{attribute},    'oidcIdTokenSignedResponseAlg', 'correct attribute updated' );
is( $updated[0]{value},        'RS256', 'RS256 stored as the signing algorithm' );

done_testing();
