#!perl
use strict;
use warnings;

# Stub File::ShareDir::dist_dir so the web app can start without the dist
# being installed. Must happen before App::Nisaba::WebSSO is loaded.
use File::Basename ();
use File::Spec;
BEGIN {
	my $share = File::Spec->rel2abs(
		File::Spec->catdir( File::Basename::dirname(__FILE__), File::Spec->updir, 'share' )
	);
	require File::ShareDir;
	no warnings 'redefine';
	*File::ShareDir::dist_dir = sub { $share };
}

use Test::More;
use Test::Mojo;
use Mojo::JSON qw(decode_json);
use MIME::Base64 ();
use Digest::SHA qw(sha256);

eval { require App::Nisaba::WebSSO };
if ($@) {
	plan skip_all => "App::Nisaba::WebSSO failed to load: $@";
}

# ── Fake Net::LDAP::Entry ─────────────────────────────────────────────────────

{
	package FakeEntry;
	sub new {
		my ( $class, %attrs ) = @_;
		return bless { attrs => \%attrs, _dn => delete $attrs{_dn} // '' }, $class;
	}
	sub dn         { return $_[0]->{_dn} }
	sub attributes { return keys %{ $_[0]->{attrs} } }
	sub get_value {
		my ( $self, $attr ) = @_;
		my $v = $self->{attrs}{$attr};
		return () unless defined $v;
		return wantarray ? ( ref $v ? @{$v} : ($v) ) : ( ref $v ? $v->[0] : $v );
	}
}

# ── Fake OIDC client entry ────────────────────────────────────────────────────

my $client_public = FakeEntry->new(
	_dn             => 'oidcClientId=testapp,ou=oidc,dc=example,dc=com',
	oidcClientId    => 'testapp',
	oidcClientName  => 'Test Application',
	oidcRedirectURI => ['https://testapp.example.com/callback'],
	oidcScope       => [ 'openid', 'profile', 'email' ],
	oidcGrantType   => ['authorization_code'],
	oidcResponseType => ['code'],
	oidcApplicationType      => 'web',
	oidcTokenEndpointAuthMethod => 'none',
	oidcClientURI   => 'https://testapp.example.com',
	oidcPolicyURI   => 'https://testapp.example.com/privacy',
	oidcTosURI      => 'https://testapp.example.com/tos',
);

my $client_confidential = FakeEntry->new(
	_dn              => 'oidcClientId=secretapp,ou=oidc,dc=example,dc=com',
	oidcClientId     => 'secretapp',
	oidcClientName   => 'Secret App',
	oidcClientSecret => 's3cret',
	oidcRedirectURI  => ['https://secretapp.example.com/callback'],
	oidcScope        => [ 'openid', 'profile' ],
	oidcGrantType    => ['authorization_code'],
	oidcResponseType => ['code'],
	oidcApplicationType      => 'web',
	oidcTokenEndpointAuthMethod => 'client_secret_basic',
);

# ── Fake user entry ──────────────────────────────────────────────────────────

my $usr_alice = FakeEntry->new(
	_dn               => 'uid=alice,ou=users,dc=example,dc=com',
	uid               => 'alice',
	uidNumber         => '1000',
	gidNumber         => '1000',
	homeDirectory     => '/home/alice',
	loginShell        => '/bin/bash',
	gecos             => 'Alice Wonderland',
	displayName       => 'Alice Wonderland',
	givenName         => 'Alice',
	sn                => 'Wonderland',
	mail              => 'alice@example.com',
	telephoneNumber   => '+1-555-0100',
	preferredLanguage => 'en',
	objectClass       => [ 'posixAccount', 'inetOrgPerson', 'person', 'organizationalPerson', 'oidcSubject' ],
	oidcNickname      => 'ally',
	oidcGender        => 'female',
	oidcBirthdate     => '1990-01-15',
	oidcZoneinfo      => 'America/New_York',
	oidcEmailVerified => 'TRUE',
	oidcPhoneNumberVerified => 'FALSE',
	street            => '123 Main St',
	l                 => 'Anytown',
	st                => 'NY',
	postalCode        => '12345',
	c                 => 'US',
);

# ── Stub helper installer ─────────────────────────────────────────────────────

sub _install_stubs {
	my ( $app, %overrides ) = @_;

	my %defaults = (
		error                        => sub { 0 },
		errorString                  => sub { '' },
		errorblank                   => sub { },
		oidcbaseConfigured           => sub { 1 },
		passkeySchemaAvailable       => sub { 0 },
		getOIDCClientEntry           => sub {
			my ( $self, $args ) = @_;
			return $client_public       if ( $args->{clientId} // '' ) eq 'testapp';
			return $client_confidential if ( $args->{clientId} // '' ) eq 'secretapp';
			return undef;
		},
		userVerifyPassword           => sub {
			my ( $self, $args ) = @_;
			die "bad password\n"
				unless ( $args->{user} // '' ) eq 'alice'
				&& ( $args->{password} // '' ) eq 'correct';
		},
		userSelfInfo                 => sub {
			return { totpStatus => 'inactive' };
		},
		getUserEntry                 => sub {
			my ( $self, $args ) = @_;
			return $usr_alice if ( $args->{user} // '' ) eq 'alice';
			return undef;
		},
		userTotpVerify               => sub {
			my ( $self, $args ) = @_;
			return ( $args->{code} // '' ) eq '123456' ? 1 : 0;
		},
	);

	my %methods = ( %defaults, %overrides );

	my $fake_pt = bless {
		ini => {
			'' => {
				ssoIssuer        => 'http://localhost',
				ssoTokenLifetime => 3600,
				ssoCodeLifetime  => 600,
				passkeyRpId      => '',
				passkeyUserVerification => 'preferred',
			},
		},
	}, 'FakePT';
	for my $name ( keys %methods ) {
		no strict 'refs';
		no warnings 'redefine';
		*{"FakePT::$name"} = $methods{$name};
	}

	$app->helper( pt => sub { $fake_pt } );
}

# Add a same-host Referer to every POST so the middleware check passes
# (except for /token which is exempt)
sub _add_referer_hook {
	my $t = shift;
	$t->ua->on(
		start => sub {
			my ( $ua, $tx ) = @_;
			return unless $tx->req->method eq 'POST';
			return if $tx->req->url->path eq '/token';
			my $host = $tx->req->url->to_abs->host_port // 'localhost';
			$tx->req->headers->referrer("http://$host/");
		}
	);
}

# b64url helpers for PKCE tests
sub _b64url_encode {
	my ($data) = @_;
	my $b64 = MIME::Base64::encode_base64( $data, '' );
	$b64 =~ tr|+/|-_|;
	$b64 =~ s/=+$//;
	return $b64;
}

my $t = Test::Mojo->new('App::Nisaba::WebSSO');
_install_stubs( $t->app );
_add_referer_hook($t);

# ── Discovery ────────────────────────────────────────────────────────────────

$t->get_ok('/.well-known/openid-configuration')
  ->status_is(200)
  ->json_is( '/issuer' => 'http://localhost' )
  ->json_is( '/authorization_endpoint' => 'http://localhost/authorize' )
  ->json_is( '/token_endpoint'         => 'http://localhost/token' )
  ->json_is( '/userinfo_endpoint'      => 'http://localhost/userinfo' )
  ->json_has('/scopes_supported')
  ->json_has('/response_types_supported')
  ->json_has('/claims_supported')
  ->json_has('/code_challenge_methods_supported');

# ── Authorization: unknown client ────────────────────────────────────────────

$t->get_ok('/authorize?client_id=bogus&redirect_uri=https://x.example.com/cb&response_type=code&scope=openid')
  ->status_is(200)
  ->content_like( qr/Unknown Client/, 'unknown client shows error page' );

# ── Authorization: invalid redirect_uri ──────────────────────────────────────

$t->get_ok('/authorize?client_id=testapp&redirect_uri=https://evil.example.com/steal&response_type=code&scope=openid')
  ->status_is(200)
  ->content_like( qr/Invalid Redirect URI/, 'mismatched redirect_uri shows error page' );

# ── Authorization: unsupported response_type ─────────────────────────────────

$t->get_ok('/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=token&scope=openid&state=s1')
  ->status_is(302)
  ->header_like( Location => qr/error=unsupported_response_type/, 'unsupported response_type redirects with error' )
  ->header_like( Location => qr/state=s1/, 'state is preserved in error redirect' );

# ── Authorization: missing openid scope ──────────────────────────────────────

$t->get_ok('/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=profile&state=s2')
  ->status_is(302)
  ->header_like( Location => qr/error=invalid_scope/, 'missing openid scope redirects with error' );

# ── Authorization: valid request redirects to login ──────────────────────────

$t->get_ok('/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid+profile+email&state=xyz&nonce=n1')
  ->status_is(302)
  ->header_like( Location => qr{/sso/login}, 'valid authorize redirects to login' );

# ── Login form: no authz session → error ─────────────────────────────────────

# Clear session first
$t->reset_session;
$t->get_ok('/sso/login')
  ->status_is(200)
  ->content_like( qr/No Authorization Request/, 'login without authz session shows error' );

# ── Login form: with authz session → renders ─────────────────────────────────

# Start a proper authorization flow first
$t->get_ok('/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid+profile+email&state=xyz&nonce=n1')
  ->status_is(302);
$t->get_ok('/sso/login')
  ->status_is(200)
  ->content_like( qr/Sign In/, 'login form renders after authorize' );

# ── Login: invalid credentials ───────────────────────────────────────────────

$t->post_ok( '/sso/login', form => { user => 'alice', pass => 'wrong' } )
  ->status_is(302)
  ->header_like( Location => qr{/sso/login}, 'bad password redirects back to login' );

# ── Login: valid credentials → redirects to consent ──────────────────────────

$t->post_ok( '/sso/login', form => { user => 'alice', pass => 'correct' } )
  ->status_is(302)
  ->header_like( Location => qr{/sso/consent}, 'good credentials redirect to consent' );

# ── Consent form: renders with client info ───────────────────────────────────

$t->get_ok('/sso/consent')
  ->status_is(200)
  ->content_like( qr/Test Application/,        'consent shows client name' )
  ->content_like( qr/alice/,                   'consent shows username' )
  ->content_like( qr/openid/,                  'consent shows openid scope' )
  ->content_like( qr/profile/,                 'consent shows profile scope' )
  ->content_like( qr/email/,                   'consent shows email scope' )
  ->content_like( qr/Privacy Policy/,          'consent shows policy link' )
  ->content_like( qr/Terms of Service/,        'consent shows ToS link' );

# ── Consent: deny ────────────────────────────────────────────────────────────

# Need to start a fresh flow for deny test
$t->reset_session;
$t->get_ok('/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid&state=deny1')
  ->status_is(302);
$t->post_ok( '/sso/login', form => { user => 'alice', pass => 'correct' } )
  ->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'deny' } )
  ->status_is(302)
  ->header_like( Location => qr/error=access_denied/, 'deny redirects with access_denied' )
  ->header_like( Location => qr/state=deny1/,         'deny preserves state' );

# ── Full authorization code flow ─────────────────────────────────────────────

$t->reset_session;
_install_stubs( $t->app );

# Step 1: Authorize
$t->get_ok('/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid+profile+email&state=flow1&nonce=nonce1')
  ->status_is(302)
  ->header_like( Location => qr{/sso/login}, 'flow: authorize redirects to login' );

# Step 2: Login
$t->post_ok( '/sso/login', form => { user => 'alice', pass => 'correct' } )
  ->status_is(302)
  ->header_like( Location => qr{/sso/consent}, 'flow: login redirects to consent' );

# Step 3: Consent (allow)
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )
  ->status_is(302);

# Extract code and state from redirect
my $redirect_url = $t->tx->res->headers->location;
like( $redirect_url, qr{^https://testapp\.example\.com/callback}, 'flow: redirect goes to callback URI' );
my $redirect_parsed = Mojo::URL->new($redirect_url);
my $auth_code = $redirect_parsed->query->param('code');
my $ret_state = $redirect_parsed->query->param('state');
ok( defined $auth_code && $auth_code ne '', 'flow: authorization code returned' );
is( $ret_state, 'flow1', 'flow: state preserved' );

# Step 4: Token exchange
$t->post_ok( '/token', form => {
	grant_type   => 'authorization_code',
	code         => $auth_code,
	redirect_uri => 'https://testapp.example.com/callback',
	client_id    => 'testapp',
})
  ->status_is(200)
  ->json_has('/access_token')
  ->json_is( '/token_type' => 'Bearer' )
  ->json_has('/expires_in')
  ->json_has('/id_token')
  ->json_is( '/scope' => 'openid profile email' );

my $token_resp   = $t->tx->res->json;
my $access_token = $token_resp->{access_token};
my $id_token     = $token_resp->{id_token};

# Verify ID token structure (alg=none JWT: header.payload.)
like( $id_token, qr/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.$/, 'id_token is alg=none JWT' );
my @jwt_parts   = split /\./, $id_token;
my $jwt_payload = decode_json( MIME::Base64::decode_base64( $jwt_parts[1] ) );
is( $jwt_payload->{iss}, 'http://localhost',  'id_token iss correct' );
is( $jwt_payload->{sub}, 'alice',             'id_token sub correct' );
is( $jwt_payload->{aud}, 'testapp',           'id_token aud correct' );
is( $jwt_payload->{nonce}, 'nonce1',          'id_token nonce correct' );
ok( defined $jwt_payload->{iat},              'id_token has iat' );
ok( defined $jwt_payload->{exp},              'id_token has exp' );
ok( defined $jwt_payload->{auth_time},        'id_token has auth_time' );
is( $jwt_payload->{name}, 'Alice Wonderland', 'id_token has profile name' );
is( $jwt_payload->{email}, 'alice@example.com', 'id_token has email' );

# Step 5: UserInfo with Bearer token
$t->get_ok( '/userinfo', { Authorization => "Bearer $access_token" } )
  ->status_is(200)
  ->json_is( '/sub'                => 'alice' )
  ->json_is( '/name'               => 'Alice Wonderland' )
  ->json_is( '/given_name'         => 'Alice' )
  ->json_is( '/family_name'        => 'Wonderland' )
  ->json_is( '/preferred_username' => 'alice' )
  ->json_is( '/email'              => 'alice@example.com' )
  ->json_is( '/nickname'           => 'ally' )
  ->json_is( '/gender'             => 'female' )
  ->json_is( '/birthdate'          => '1990-01-15' )
  ->json_is( '/zoneinfo'           => 'America/New_York' )
  ->json_is( '/locale'             => 'en' );

# Check email_verified is JSON true
my $userinfo = $t->tx->res->json;
is( $userinfo->{email_verified}, Mojo::JSON->true, 'email_verified is true' );

# ── Token endpoint: authorization code is one-time use ───────────────────────

$t->post_ok( '/token', form => {
	grant_type   => 'authorization_code',
	code         => $auth_code,
	redirect_uri => 'https://testapp.example.com/callback',
	client_id    => 'testapp',
})
  ->status_is(400)
  ->json_is( '/error' => 'invalid_grant', 'code reuse returns invalid_grant' );

# ── Token endpoint: unsupported grant_type ───────────────────────────────────

$t->post_ok( '/token', form => { grant_type => 'client_credentials' } )
  ->status_is(400)
  ->json_is( '/error' => 'unsupported_grant_type' );

# ── Token endpoint: wrong client_id ──────────────────────────────────────────

$t->reset_session;
_install_stubs( $t->app );

# Do a full flow to get a code
$t->get_ok('/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid&state=s3')
  ->status_is(302);
$t->post_ok( '/sso/login', form => { user => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $code2 = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');

$t->post_ok( '/token', form => {
	grant_type   => 'authorization_code',
	code         => $code2,
	client_id    => 'wrong_client',
})
  ->status_is(400)
  ->json_is( '/error' => 'invalid_grant', 'wrong client_id returns invalid_grant' );

# ── Token endpoint: confidential client with wrong secret ────────────────────

$t->reset_session;
_install_stubs( $t->app );

$t->get_ok('/authorize?client_id=secretapp&redirect_uri=https://secretapp.example.com/callback&response_type=code&scope=openid&state=s4')
  ->status_is(302);
$t->post_ok( '/sso/login', form => { user => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $code3 = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');

$t->post_ok( '/token', form => {
	grant_type    => 'authorization_code',
	code          => $code3,
	client_id     => 'secretapp',
	client_secret => 'wrongsecret',
})
  ->status_is(401)
  ->json_is( '/error' => 'invalid_client', 'wrong secret returns invalid_client' );

# ── Token endpoint: confidential client with correct secret ──────────────────

$t->reset_session;
_install_stubs( $t->app );

$t->get_ok('/authorize?client_id=secretapp&redirect_uri=https://secretapp.example.com/callback&response_type=code&scope=openid&state=s5')
  ->status_is(302);
$t->post_ok( '/sso/login', form => { user => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $code4 = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');

$t->post_ok( '/token', form => {
	grant_type    => 'authorization_code',
	code          => $code4,
	client_id     => 'secretapp',
	client_secret => 's3cret',
})
  ->status_is(200)
  ->json_has('/access_token', 'correct secret gets access_token');

# ── Token endpoint: client_secret_basic via Authorization header ─────────────

$t->reset_session;
_install_stubs( $t->app );

$t->get_ok('/authorize?client_id=secretapp&redirect_uri=https://secretapp.example.com/callback&response_type=code&scope=openid&state=s6')
  ->status_is(302);
$t->post_ok( '/sso/login', form => { user => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $code5 = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');

my $basic_auth = 'Basic ' . MIME::Base64::encode_base64( 'secretapp:s3cret', '' );
$t->post_ok( '/token',
	{ Authorization => $basic_auth },
	form => {
		grant_type   => 'authorization_code',
		code         => $code5,
	}
)
  ->status_is(200)
  ->json_has('/access_token', 'client_secret_basic auth works' );

# ── PKCE: S256 ───────────────────────────────────────────────────────────────

$t->reset_session;
_install_stubs( $t->app );

my $code_verifier  = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
my $code_challenge = _b64url_encode( sha256($code_verifier) );

$t->get_ok("/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid&state=pkce1&code_challenge=$code_challenge&code_challenge_method=S256")
  ->status_is(302);
$t->post_ok( '/sso/login', form => { user => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $pkce_code = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');

# Token with correct verifier
$t->post_ok( '/token', form => {
	grant_type    => 'authorization_code',
	code          => $pkce_code,
	client_id     => 'testapp',
	redirect_uri  => 'https://testapp.example.com/callback',
	code_verifier => $code_verifier,
})
  ->status_is(200)
  ->json_has('/access_token', 'PKCE S256 with correct verifier succeeds' );

# ── PKCE: S256 wrong verifier ────────────────────────────────────────────────

$t->reset_session;
_install_stubs( $t->app );

$t->get_ok("/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid&state=pkce2&code_challenge=$code_challenge&code_challenge_method=S256")
  ->status_is(302);
$t->post_ok( '/sso/login', form => { user => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $pkce_code2 = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');

$t->post_ok( '/token', form => {
	grant_type    => 'authorization_code',
	code          => $pkce_code2,
	client_id     => 'testapp',
	code_verifier => 'wrong-verifier-value',
})
  ->status_is(400)
  ->json_like( '/error_description' => qr/PKCE/, 'wrong PKCE verifier fails' );

# ── PKCE: missing code_verifier when challenge was sent ──────────────────────

$t->reset_session;
_install_stubs( $t->app );

$t->get_ok("/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid&state=pkce3&code_challenge=$code_challenge&code_challenge_method=S256")
  ->status_is(302);
$t->post_ok( '/sso/login', form => { user => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $pkce_code3 = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');

$t->post_ok( '/token', form => {
	grant_type => 'authorization_code',
	code       => $pkce_code3,
	client_id  => 'testapp',
})
  ->status_is(400)
  ->json_like( '/error_description' => qr/code_verifier/, 'missing code_verifier fails' );

# ── PKCE: plain method ──────────────────────────────────────────────────────

$t->reset_session;
_install_stubs( $t->app );

my $plain_verifier = 'my-plain-verifier-string';

$t->get_ok("/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid&state=pkce4&code_challenge=$plain_verifier&code_challenge_method=plain")
  ->status_is(302);
$t->post_ok( '/sso/login', form => { user => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $pkce_code4 = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');

$t->post_ok( '/token', form => {
	grant_type    => 'authorization_code',
	code          => $pkce_code4,
	client_id     => 'testapp',
	code_verifier => $plain_verifier,
})
  ->status_is(200)
  ->json_has('/access_token', 'PKCE plain method succeeds' );

# ── UserInfo: no token → 401 ────────────────────────────────────────────────

$t->reset_session;
_install_stubs( $t->app );

$t->get_ok('/userinfo')
  ->status_is(401)
  ->json_is( '/error' => 'invalid_token' );

# ── UserInfo: invalid token → 401 ───────────────────────────────────────────

$t->get_ok( '/userinfo', { Authorization => 'Bearer bogus_token_value' } )
  ->status_is(401)
  ->json_is( '/error' => 'invalid_token' );

# ── UserInfo: phone scope ───────────────────────────────────────────────────

$t->reset_session;
_install_stubs( $t->app );

$t->get_ok('/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid+phone&state=phone1')
  ->status_is(302);
$t->post_ok( '/sso/login', form => { user => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $phone_code = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');

$t->post_ok( '/token', form => {
	grant_type => 'authorization_code',
	code       => $phone_code,
	client_id  => 'testapp',
})
  ->status_is(200);
my $phone_token = $t->tx->res->json->{access_token};

$t->get_ok( '/userinfo', { Authorization => "Bearer $phone_token" } )
  ->status_is(200)
  ->json_is( '/sub'          => 'alice' )
  ->json_is( '/phone_number' => '+1-555-0100' );

my $phone_info = $t->tx->res->json;
is( $phone_info->{phone_number_verified}, Mojo::JSON->false, 'phone_number_verified is false' );
# profile scope was not requested, so name should not be present
ok( !exists $phone_info->{name}, 'name not returned without profile scope' );

# ── UserInfo: address scope ──────────────────────────────────────────────────

$t->reset_session;
_install_stubs( $t->app );

$t->get_ok('/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid+address&state=addr1')
  ->status_is(302);
$t->post_ok( '/sso/login', form => { user => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $addr_code = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');

$t->post_ok( '/token', form => {
	grant_type => 'authorization_code',
	code       => $addr_code,
	client_id  => 'testapp',
})
  ->status_is(200);
my $addr_token = $t->tx->res->json->{access_token};

$t->get_ok( '/userinfo', { Authorization => "Bearer $addr_token" } )
  ->status_is(200)
  ->json_is( '/address/street_address' => '123 Main St' )
  ->json_is( '/address/locality'       => 'Anytown' )
  ->json_is( '/address/region'         => 'NY' )
  ->json_is( '/address/postal_code'    => '12345' )
  ->json_is( '/address/country'        => 'US' );

# ── TOTP flow ────────────────────────────────────────────────────────────────

$t->reset_session;
_install_stubs(
	$t->app,
	userSelfInfo => sub { return { totpStatus => 'active' } },
);

$t->get_ok('/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid&state=totp1')
  ->status_is(302);

# Login with valid password → should redirect to TOTP challenge, not consent
$t->post_ok( '/sso/login', form => { user => 'alice', pass => 'correct' } )
  ->status_is(302)
  ->header_like( Location => qr{/sso/totp}, 'TOTP user redirected to TOTP challenge' );

# TOTP challenge form renders
$t->get_ok('/sso/totp')
  ->status_is(200)
  ->content_like( qr/TOTP|authenticator/i, 'TOTP challenge form renders' );

# Wrong TOTP code
$t->post_ok( '/sso/totp', form => { code => '000000' } )
  ->status_is(302)
  ->header_like( Location => qr{/sso/totp}, 'wrong TOTP code redirects back' );

# Correct TOTP code → consent
$t->post_ok( '/sso/totp', form => { code => '123456' } )
  ->status_is(302)
  ->header_like( Location => qr{/sso/consent}, 'correct TOTP code redirects to consent' );

# ── TOTP challenge form without pending user → redirect to login ─────────

$t->reset_session;
_install_stubs( $t->app );

$t->get_ok('/sso/totp')
  ->status_is(302)
  ->header_like( Location => qr{/sso/login}, 'TOTP form without pending user redirects to login' );

$t->post_ok( '/sso/totp', form => { code => '123456' } )
  ->status_is(302)
  ->header_like( Location => qr{/sso/login}, 'TOTP post without pending user redirects to login' );

# ── Consent form without authz session → error ──────────────────────────────

$t->reset_session;
_install_stubs( $t->app );

$t->get_ok('/sso/consent')
  ->status_is(200)
  ->content_like( qr/No Authorization Request/, 'consent without authz shows error' );

# ── Consent form without user session → redirect to login ───────────────────

$t->reset_session;
_install_stubs( $t->app );

# Set up authz session only (no user)
$t->get_ok('/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid&state=nouser')
  ->status_is(302);
$t->get_ok('/sso/consent')
  ->status_is(302)
  ->header_like( Location => qr{/sso/login}, 'consent without user redirects to login' );

# ── Consent POST without sessions → redirect to login ───────────────────────

$t->reset_session;
_install_stubs( $t->app );

$t->post_ok( '/sso/consent', form => { decision => 'allow' } )
  ->status_is(302)
  ->header_like( Location => qr{/sso/login}, 'consent POST without session redirects to login' );

# ── Already-authenticated user skips login ───────────────────────────────────

$t->reset_session;
_install_stubs( $t->app );

# First, do a normal login to establish sso_user session
$t->get_ok('/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid&state=pre1')
  ->status_is(302);
$t->post_ok( '/sso/login', form => { user => 'alice', pass => 'correct' } )
  ->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )
  ->status_is(302);

# Second authorize with existing sso_user session → straight to consent
$t->get_ok('/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid&state=pre2')
  ->status_is(302)
  ->header_like( Location => qr{/sso/consent}, 'already-authenticated user skips login' );

# ── Token endpoint: redirect_uri mismatch ────────────────────────────────────

$t->reset_session;
_install_stubs( $t->app );

$t->get_ok('/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid&state=ruri1')
  ->status_is(302);
$t->post_ok( '/sso/login', form => { user => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $ruri_code = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');

$t->post_ok( '/token', form => {
	grant_type   => 'authorization_code',
	code         => $ruri_code,
	client_id    => 'testapp',
	redirect_uri => 'https://different.example.com/other',
})
  ->status_is(400)
  ->json_like( '/error_description' => qr/redirect_uri/, 'redirect_uri mismatch returns error' );

# ── Referer check on SSO POST routes ────────────────────────────────────────

{
	# Temporarily remove referer hook to test the protection
	my $t2 = Test::Mojo->new('App::Nisaba::WebSSO');
	_install_stubs( $t2->app );

	$t2->post_ok('/sso/login')
	  ->status_is(403)
	  ->content_like( qr/Forbidden/, 'POST without Referer is rejected' );
}

# ── Token endpoint is exempt from Referer check ─────────────────────────────

{
	my $t3 = Test::Mojo->new('App::Nisaba::WebSSO');
	_install_stubs( $t3->app );

	# Token endpoint should not 403, just 400 for bad grant_type
	$t3->post_ok( '/token', form => { grant_type => 'bogus' } )
	  ->status_is(400)
	  ->json_is( '/error' => 'unsupported_grant_type', 'token endpoint exempt from Referer check' );
}

# ── UserInfo: openid-only scope returns minimal claims ───────────────────────

$t->reset_session;
_install_stubs( $t->app );

$t->get_ok('/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid&state=min1')
  ->status_is(302);
$t->post_ok( '/sso/login', form => { user => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $min_code = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');

$t->post_ok( '/token', form => {
	grant_type => 'authorization_code',
	code       => $min_code,
	client_id  => 'testapp',
})->status_is(200);
my $min_token = $t->tx->res->json->{access_token};

$t->get_ok( '/userinfo', { Authorization => "Bearer $min_token" } )
  ->status_is(200)
  ->json_is( '/sub' => 'alice' );

my $min_info = $t->tx->res->json;
ok( !exists $min_info->{name},         'openid-only: no name' );
ok( !exists $min_info->{email},        'openid-only: no email' );
ok( !exists $min_info->{phone_number}, 'openid-only: no phone' );
ok( !exists $min_info->{address},      'openid-only: no address' );

done_testing;
