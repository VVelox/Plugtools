#!perl
use strict;
use warnings;

# Stub File::ShareDir::dist_dir so the web app can start without the dist
# being installed. Must happen before App::Nisaba::Web is loaded.
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
} ## end BEGIN
use Test::More;
use Mojo::Util ();
use Test::Mojo;

eval { require App::Nisaba::Web };
plan skip_all => "App::Nisaba::Web failed to load: $@" if $@;

# ── Fake client entry ─────────────────────────────────────────────────────────
{

	package FakeEntry;
	sub new        { my ( $c, %a ) = @_; return bless { attrs => \%a }, $c }
	sub dn         { return 'oidcClientId=testclient,ou=oidc,dc=example,dc=com' }
	sub attributes { return keys %{ $_[0]->{attrs} } }

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
	oidcClientId     => 'testclient',
	oidcClientSecret => 'sekret',
	oidcJwks         =>
		'{"keys":[{"kty":"RSA","n":"oldmodulus","e":"AQAB","kid":"k1","use":"sig","alg":"RS256","d":"oldpriv"}]}',
	oidcTokenEndpointAuthMethod  => 'client_secret_basic',
	oidcIdTokenSignedResponseAlg => 'RS256',
);

my @added;            # addOIDCClient calls
my @updated;          # oidcClientUpdate calls
my @multi_added;      # oidcClientAddMultiValue calls
my @multi_removed;    # oidcClientRemoveMultiValue calls
my @deleted;          # deleteOIDCClient calls

sub _install_stubs {
	my ($app) = @_;
	my %methods = (
		error                      => sub { 0 },
		errorString                => sub { '' },
		errorblank                 => sub { },
		oidcbaseConfigured         => sub { 1 },
		netgroupbaseConfigured     => sub { 0 },
		addOIDCClient              => sub { my ( $s, $a ) = @_; push @added, $a; return 1 },
		getOIDCClientEntry         => sub { return $client },
		oidcClientUpdate           => sub { my ( $s, $a ) = @_; push @updated, $a; return 1 },
		oidcClientAddMultiValue    => sub { my ( $s, $a ) = @_; push @multi_added, $a; return 1 },
		oidcClientRemoveMultiValue => sub { my ( $s, $a ) = @_; push @multi_removed, $a; return 1 },
		deleteOIDCClient           => sub { push @deleted, $_[1]; return 1 },
	);
	my $fake = bless { ini => { '' => {} } }, 'FakePT';
	Mojo::Util::monkey_patch( 'FakePT', %methods );
	$app->helper( pt => sub { $fake } );
} ## end sub _install_stubs

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
$t->post_ok( '/oidc/testclient', form => { action => 'idTokenSignedResponseAlg', value => 'RS256' } )->status_is(302);
is( scalar(@updated),       1,                              'RS256 update is written' );
is( $updated[0]{attribute}, 'oidcIdTokenSignedResponseAlg', 'correct attribute updated' );
is( $updated[0]{value},     'RS256',                        'RS256 stored as the signing algorithm' );

# ── update: unimplemented token endpoint auth methods are rejected ────────────

for my $method (qw(private_key_jwt client_secret_jwt bogus_method)) {
	@updated = ();
	$t->post_ok( '/oidc/testclient', form => { action => 'authMethod', value => $method } )
		->status_is(302)
		->header_like( Location => qr{/oidc/testclient}, "auth method '$method' bounces back to the client" );
	is( scalar(@updated), 0, "no update written for unimplemented auth method '$method'" );
}

# ── update: regenerateKeys rotates instead of replacing ───────────────────────
# The new private key goes first; the previous key is retained as a
# public-only entry so already-issued ID tokens keep verifying.

@updated = ();
$t->post_ok( '/oidc/testclient', form => { action => 'regenerateKeys' } )->status_is(302);
my ($jwks_update) = grep { $_->{attribute} eq 'oidcJwks' } @updated;
ok( $jwks_update, 'regenerateKeys wrote a new oidcJwks' );
my $rotated = Mojo::JSON::decode_json( $jwks_update->{value} );
is( scalar @{ $rotated->{keys} }, 2, 'rotated JWKS keeps the previous key' );
ok( defined $rotated->{keys}[0]{d}, 'new first key holds private material' );
isnt( $rotated->{keys}[0]{kid}, 'k1', 'new key has a fresh kid' );
is( $rotated->{keys}[1]{kid}, 'k1',         'previous key is retained' );
is( $rotated->{keys}[1]{n},   'oldmodulus', 'previous public modulus is retained' );
ok( !defined $rotated->{keys}[1]{d}, 'previous key is stripped to public components' );

# ── update: rotation retains at most two previous keys ────────────────────────

$client->{attrs}{oidcJwks} = Mojo::JSON::encode_json(
	{
		keys => [
			{ kty => 'RSA', n => 'n1', e => 'AQAB', kid => 'r1', d => 'priv1' },
			{ kty => 'RSA', n => 'n2', e => 'AQAB', kid => 'r2' },
			{ kty => 'RSA', n => 'n3', e => 'AQAB', kid => 'r3' },
		]
	}
);
@updated = ();
$t->post_ok( '/oidc/testclient', form => { action => 'regenerateKeys' } )->status_is(302);
my ($cap_update) = grep { $_->{attribute} eq 'oidcJwks' } @updated;
my $capped = Mojo::JSON::decode_json( $cap_update->{value} );
is( scalar @{ $capped->{keys} }, 3, 'rotation caps the set at the new key plus two previous' );
is_deeply(
	[ map { $_->{kid} } @{ $capped->{keys} }[ 1, 2 ] ],
	[ 'r1', 'r2' ],
	'the two newest previous keys are retained; the oldest is dropped'
);

# ── create: confidential client success ───────────────────────────────────────

@added   = ();
@updated = ();
$t->post_ok(
	'/oidc',
	form => {
		clientType   => 'confidential',
		signingAlg   => 'RS256',
		clientName   => 'My App',
		redirectURIs => "https://app.example.com/cb\nhttps://app.example.com/cb2",
		scopes       => 'openid profile email',
		grantTypes   => 'authorization_code refresh_token',
	}
)->status_is( 200, 'create renders the client page directly' );

is( scalar(@added), 1, 'one client created' );
like( $added[0]{clientId},     qr/^[a-z0-9]{24}$/,      'client ID is auto-generated' );
like( $added[0]{clientSecret}, qr/^[A-Za-z0-9_-]{48}$/, 'confidential client gets a generated secret' );
is( $added[0]{authMethod},               'client_secret_basic', 'confidential default auth method' );
is( $added[0]{idTokenSignedResponseAlg}, 'RS256',               'signing algorithm stored' );
is_deeply(
	$added[0]{redirectURIs},
	[ 'https://app.example.com/cb', 'https://app.example.com/cb2' ],
	'redirect URIs parsed one per line'
);
is_deeply( $added[0]{scopes},     [qw(openid profile email)],             'scopes stored as the allow-list' );
is_deeply( $added[0]{grantTypes}, [qw(authorization_code refresh_token)], 'grant types stored' );

my ($create_jwks) = grep { $_->{attribute} eq 'oidcJwks' } @updated;
ok( $create_jwks,                                                           'create generates a signing key pair' );
ok( defined Mojo::JSON::decode_json( $create_jwks->{value} )->{keys}[0]{d}, 'generated JWKS holds private material' );
like( $t->tx->res->body, qr/\Q$added[0]{clientSecret}\E/, 'the one-time client secret is shown in the response' );

# ── create: public client gets no secret ─────────────────────────────────────

@added = ();
$t->post_ok( '/oidc',
	form => { clientType => 'public', signingAlg => 'RS256', redirectURIs => 'https://spa.example.com/cb' } )
	->status_is(200);
is( scalar(@added), 1, 'public client created' );
ok( !exists $added[0]{clientSecret}, 'public client has no secret' );
is( $added[0]{authMethod}, 'none', 'public client auth method is none' );

# ── create: HS256 for a public client is vetoed ──────────────────────────────

@added = ();
$t->post_ok( '/oidc',
	form => { clientType => 'public', signingAlg => 'HS256', redirectURIs => 'https://spa.example.com/cb' } )
	->status_is(302)
	->header_like( Location => qr{/oidc/add}, 'HS256 for a public client bounces back to the add form' );
is( scalar(@added), 0, 'no public HS256 client was created' );

# ── create: redirect URIs are validated ──────────────────────────────────────

@added = ();
$t->post_ok( '/oidc', form => { clientType => 'confidential', signingAlg => 'RS256', redirectURIs => 'not-a-uri' } )
	->status_is(302)
	->header_like( Location => qr{/oidc/add}, 'a relative redirect URI is rejected' );
is( scalar(@added), 0, 'no client created with an invalid redirect URI' );

@added = ();
$t->post_ok( '/oidc', form => { clientType => 'confidential', signingAlg => 'RS256', redirectURIs => '' } )
	->status_is(302)
	->header_like( Location => qr{/oidc/add}, 'at least one redirect URI is required' );
is( scalar(@added), 0, 'no client created without redirect URIs' );

# ── update: clearing the secret is vetoed while depended upon ─────────────────

@updated = ();
$t->post_ok( '/oidc/testclient', form => { action => 'clientSecret', value => '' } )
	->status_is(302)
	->header_like( Location => qr{/oidc/testclient}, 'clearing a depended-upon secret is rejected' );
is( scalar(@updated), 0, 'no update written when clearing the secret' );

# ── update: regenerateSecret writes a fresh secret ────────────────────────────

@updated = ();
$t->post_ok( '/oidc/testclient', form => { action => 'regenerateSecret' } )
	->status_is( 200, 'regenerateSecret renders the client page directly' );
my ($sec_update) = grep { $_->{attribute} eq 'oidcClientSecret' } @updated;
ok( $sec_update, 'regenerateSecret wrote a new secret' );
like( $sec_update->{value}, qr/^[A-Za-z0-9_-]{48}$/,      'new secret has the expected shape' );
like( $t->tx->res->body,    qr/\Q$sec_update->{value}\E/, 'the one-time secret is shown in the response' );

# ── update: multi-value add/remove actions ────────────────────────────────────

@multi_added = ();
$t->post_ok( '/oidc/testclient', form => { action => 'redirectURI_add', value => 'https://new.example.com/cb' } )
	->status_is(302);
is( $multi_added[0]{attribute}, 'oidcRedirectURI',            'redirectURI_add targets the right attribute' );
is( $multi_added[0]{value},     'https://new.example.com/cb', 'redirectURI_add passes the value' );

@multi_removed = ();
$t->post_ok( '/oidc/testclient', form => { action => 'scope_remove', value => 'email' } )->status_is(302);
is( $multi_removed[0]{attribute}, 'oidcScope', 'scope_remove targets the right attribute' );
is( $multi_removed[0]{value},     'email',     'scope_remove passes the value' );

@multi_added = ();
$t->post_ok( '/oidc/testclient',
	form => { action => 'postLogoutRedirectURI_add', value => 'https://app.example.com/bye' } )->status_is(302);
is( $multi_added[0]{attribute}, 'oidcPostLogoutRedirectURI', 'postLogoutRedirectURI_add targets the right attribute' );

# ── delete ────────────────────────────────────────────────────────────────────

@deleted = ();
$t->post_ok('/oidc/testclient/delete')
	->status_is(302)
	->header_like( Location => qr{/oidc$}, 'delete redirects to the client index' );
is_deeply( \@deleted, ['testclient'], 'deleteOIDCClient called for the right client' );

done_testing();
