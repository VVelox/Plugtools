#!perl
use strict;
use warnings;

use FindBin ();
use lib "$FindBin::Bin/lib";
use NisabaWebTest qw(no_pkce no_rate_limit);

use Test::More;
use Mojo::Util ();
use Test::Mojo;
use Mojo::JSON   qw(decode_json);
use MIME::Base64 ();
use Digest::SHA  qw(sha256);
use Crypt::PK::RSA;

eval { require App::Nisaba::WebSSO };
if ($@) {
	plan skip_all => "App::Nisaba::WebSSO failed to load: $@";
}

# Shared in-memory grant store for the whole run. Codes/tokens now live in a
# server-side store (not the session cookie), so this stands in for the real
# SQLite store. A single instance is shared across every test app via the
# sso_storage helper installed in _install_stubs, mirroring how a real store is
# shared across worker processes — and proving the flow works without relying
# on the browser session.
my $TEST_STORAGE;
eval {
	require App::Nisaba::WebSSO::Storage;
	$TEST_STORAGE = App::Nisaba::WebSSO::Storage->new( { backend => 'SQLite', path => ':memory:' } );
	1;
} or do {
	plan skip_all => "App::Nisaba::WebSSO::Storage unavailable (DBD::SQLite?): $@";
};

# RSA signing key for the public test client. A public client has no shared
# secret, so it signs ID tokens with RS256 using a stored key pair — the shape a
# real registration produces. The provider now refuses to issue unsigned tokens,
# so every client that completes a token exchange must have a working alg.
my $testapp_rsa = Crypt::PK::RSA->new;
$testapp_rsa->generate_key( 256, 65537 );    # 2048-bit
my $testapp_jwk = decode_json( $testapp_rsa->export_key_jwk('private') );
$testapp_jwk->{kid} = 'testapp-kid';
$testapp_jwk->{use} = 'sig';
$testapp_jwk->{alg} = 'RS256';
my $testapp_jwks_json = Mojo::JSON::encode_json( { keys => [$testapp_jwk] } );

# ── Fake OIDC client entry ────────────────────────────────────────────────────

my $client_public = FakeEntry->new(
	_dn                          => 'oidcClientId=testapp,ou=oidc,dc=example,dc=com',
	oidcClientId                 => 'testapp',
	oidcClientName               => 'Test Application',
	oidcRedirectURI              => ['https://testapp.example.com/callback'],
	oidcScope                    => [ 'openid', 'profile', 'email', 'phone', 'address' ],
	oidcGrantType                => ['authorization_code'],
	oidcResponseType             => ['code'],
	oidcApplicationType          => 'web',
	oidcTokenEndpointAuthMethod  => 'none',
	oidcIdTokenSignedResponseAlg => 'RS256',
	oidcJwks                     => $testapp_jwks_json,
	oidcClientURI                => 'https://testapp.example.com',
	oidcPolicyURI                => 'https://testapp.example.com/privacy',
	oidcTosURI                   => 'https://testapp.example.com/tos',
);

my $client_confidential = FakeEntry->new(
	_dn                          => 'oidcClientId=secretapp,ou=oidc,dc=example,dc=com',
	oidcClientId                 => 'secretapp',
	oidcClientName               => 'Secret App',
	oidcClientSecret             => 's3cret',
	oidcIdTokenSignedResponseAlg => 'HS256',
	oidcRedirectURI              => ['https://secretapp.example.com/callback'],
	oidcScope                    => [ 'openid',             'profile' ],
	oidcGrantType                => [ 'authorization_code', 'refresh_token' ],
	oidcResponseType             => ['code'],
	oidcApplicationType          => 'web',
	oidcTokenEndpointAuthMethod  => 'client_secret_basic',
);

# A client explicitly configured for alg=none. The admin UI no longer allows
# this, but such an entry can still exist in LDAP; the provider must refuse to
# issue a token for it rather than emit an unsigned one.
my $client_none = FakeEntry->new(
	_dn                          => 'oidcClientId=nonealg,ou=oidc,dc=example,dc=com',
	oidcClientId                 => 'nonealg',
	oidcRedirectURI              => ['https://nonealg.example.com/cb'],
	oidcScope                    => ['openid'],
	oidcGrantType                => ['authorization_code'],
	oidcResponseType             => ['code'],
	oidcTokenEndpointAuthMethod  => 'none',
	oidcIdTokenSignedResponseAlg => 'none',
);

# ── Fake user entry ──────────────────────────────────────────────────────────

my $usr_alice = FakeEntry->new(
	_dn                     => 'uid=alice,ou=users,dc=example,dc=com',
	uid                     => 'alice',
	uidNumber               => '1000',
	gidNumber               => '1000',
	homeDirectory           => '/home/alice',
	loginShell              => '/bin/bash',
	gecos                   => 'Alice Wonderland',
	displayName             => 'Alice Wonderland',
	givenName               => 'Alice',
	sn                      => 'Wonderland',
	mail                    => 'alice@example.com',
	telephoneNumber         => '+1-555-0100',
	preferredLanguage       => 'en',
	objectClass             => [ 'posixAccount', 'inetOrgPerson', 'person', 'organizationalPerson', 'oidcSubject' ],
	oidcNickname            => 'ally',
	oidcGender              => 'female',
	oidcBirthdate           => '1990-01-15',
	oidcZoneinfo            => 'America/New_York',
	oidcEmailVerified       => 'TRUE',
	oidcPhoneNumberVerified => 'FALSE',
	street                  => '123 Main St',
	l                       => 'Anytown',
	st                      => 'NY',
	postalCode              => '12345',
	c                       => 'US',
);

# ── Stub helper installer ─────────────────────────────────────────────────────

sub _install_stubs {
	my ( $app, %overrides ) = @_;

	my %defaults = (
		error                  => sub { 0 },
		errorString            => sub { '' },
		errorblank             => sub { },
		oidcbaseConfigured     => sub { 1 },
		passkeySchemaAvailable => sub { 0 },
		getOIDCClientEntry     => sub {
			my ( $self, $args ) = @_;
			return $client_public       if ( $args->{clientId} // '' ) eq 'testapp';
			return $client_confidential if ( $args->{clientId} // '' ) eq 'secretapp';
			return undef;
		},
		userVerifyPassword => sub {
			my ( $self, $args ) = @_;
			die "bad password\n"
				unless ( $args->{user} // '' ) eq 'alice'
				&& ( $args->{password} // '' ) eq 'correct';
		},
		userSelfInfo => sub {
			return { totpStatus => 'inactive' };
		},
		getUserEntry => sub {
			my ( $self, $args ) = @_;
			return $usr_alice if ( $args->{user} // '' ) eq 'alice';
			return undef;
		},
		userTotpVerify => sub {
			my ( $self, $args ) = @_;
			return ( $args->{code} // '' ) eq '123456' ? 1 : 0;
		},
	);

	my %methods = ( %defaults, %overrides );

	my $fake_pt = bless {
		ini => {
			'' => {
				ssoIssuer               => 'http://localhost',
				ssoTokenLifetime        => 3600,
				ssoCodeLifetime         => 600,
				passkeyRpId             => '',
				passkeyUserVerification => 'preferred',
			},
		},
		},
		'FakePT';
	Mojo::Util::monkey_patch( 'FakePT', %methods );

	$app->helper( pt => sub { $fake_pt } );

	# Use the shared in-memory grant store rather than the default on-disk
	# SQLite path. A single instance is reused so codes/tokens persist across
	# requests within the run, the way a real shared store would.
	no warnings 'redefine';
	$app->helper( sso_storage => sub { $TEST_STORAGE } );

	# Seed a known CSRF token into every request's session so the synchronizer-
	# token check accepts the 'testcsrf' header the UA hooks send. Added once per
	# app (guarded) since _install_stubs may run more than once for an instance.
	unless ( $app->{_csrf_test_seeded}++ ) {
		$app->hook( before_dispatch => sub { $_[0]->session( csrf_token => 'testcsrf' ) } );
	}
} ## end sub _install_stubs

# Add a same-host Referer to every POST so the middleware check passes.
# The OIDC protocol endpoints (/token and /userinfo) are exempt from the
# Referer check and are called by RPs without a browser Referer, so we do not
# add one for them — exercising the real server-to-server request shape.
sub _add_referer_hook {
	my $t = shift;
	$t->ua->on(
		start => sub {
			my ( $ua, $tx ) = @_;
			return unless $tx->req->method eq 'POST';
			return if $tx->req->url->path eq '/token';
			return if $tx->req->url->path eq '/userinfo';
			my $host = $tx->req->url->to_abs->host_port // 'localhost';
			$tx->req->headers->referrer("http://$host/");
			$tx->req->headers->header( 'X-CSRF-Token' => 'testcsrf' );
		}
	);
} ## end sub _add_referer_hook

# b64url helpers for PKCE tests
sub _b64url_encode {
	my ($data) = @_;
	my $b64 = MIME::Base64::encode_base64( $data, '' );
	$b64 =~ tr|+/|-_|;
	$b64 =~ s/=+$//;
	return $b64;
}

sub _b64url_decode {
	my ($b64u) = @_;
	$b64u =~ tr|-_|+/|;
	while ( length($b64u) % 4 ) { $b64u .= '=' }
	return MIME::Base64::decode_base64($b64u);
}

my $t = Test::Mojo->new('App::Nisaba::WebSSO');
_install_stubs( $t->app );
_add_referer_hook($t);

# ── Discovery ────────────────────────────────────────────────────────────────

$t->get_ok('/.well-known/openid-configuration')
	->status_is(200)
	->json_is( '/issuer'                 => 'http://localhost' )
	->json_is( '/authorization_endpoint' => 'http://localhost/authorize' )
	->json_is( '/token_endpoint'         => 'http://localhost/token' )
	->json_is( '/userinfo_endpoint'      => 'http://localhost/userinfo' )
	->json_has('/scopes_supported')
	->json_has('/response_types_supported')
	->json_has('/claims_supported')
	->json_has('/code_challenge_methods_supported');

# Discovery advertises only secure options: no alg:none for id tokens, only S256 PKCE.
my $disco = $t->tx->res->json;
is_deeply( $disco->{code_challenge_methods_supported}, ['S256'], 'discovery advertises only S256 PKCE' );
ok(
	!grep( { $_ eq 'none' } @{ $disco->{id_token_signing_alg_values_supported} } ),
	'discovery does not advertise alg:none for id tokens',
);

# ── Authorization: unknown client ────────────────────────────────────────────

$t->get_ok('/authorize?client_id=bogus&redirect_uri=https://x.example.com/cb&response_type=code&scope=openid')
	->status_is(200)
	->content_like( qr/Unknown Client/, 'unknown client shows error page' );

# ── Authorization: invalid redirect_uri ──────────────────────────────────────

$t->get_ok('/authorize?client_id=testapp&redirect_uri=https://evil.example.com/steal&response_type=code&scope=openid')
	->status_is(200)
	->content_like( qr/Invalid Redirect URI/, 'mismatched redirect_uri shows error page' );

# ── Authorization: unsupported response_type ─────────────────────────────────

$t->get_ok(
	'/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=token&scope=openid&state=s1'
	)
	->status_is(302)
	->header_like( Location => qr/error=unsupported_response_type/, 'unsupported response_type redirects with error' )
	->header_like( Location => qr/state=s1/,                        'state is preserved in error redirect' );

# ── Authorization: missing openid scope ──────────────────────────────────────

$t->get_ok(
	'/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=profile&state=s2'
)->status_is(302)->header_like( Location => qr/error=invalid_scope/, 'missing openid scope redirects with error' );

# ── Authorization: valid request redirects to login ──────────────────────────

$t->get_ok(
	'/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid+profile+email&state=xyz&nonce=n1'
)->status_is(302)->header_like( Location => qr{/sso/login}, 'valid authorize redirects to login' );

# ── Authorization: POST is supported (OIDC Core 3.1.2.1) ─────────────────────

$t->post_ok(
	'/authorize',
	form => {
		client_id     => 'testapp',
		redirect_uri  => 'https://testapp.example.com/callback',
		response_type => 'code',
		scope         => 'openid',
		state         => 'post1',
	}
)->status_is(302)->header_like( Location => qr{/sso/login}, 'POST authorize works like GET' );

# ── Authorization: oversized opaque parameters are rejected ──────────────────
# The pending request lives in the ~4 KB session cookie; unbounded state or
# nonce would overflow it and drop the whole session.

my $huge = 'x' x 1025;
$t->get_ok( '/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback'
		. "&response_type=code&scope=openid&state=$huge" )
	->status_is(302)
	->header_like( Location => qr/error=invalid_request/, 'an oversized state is rejected' );

my $huge_nonce = 'x' x 513;
$t->get_ok( '/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback'
		. "&response_type=code&scope=openid&state=s&nonce=$huge_nonce" )
	->status_is(302)
	->header_like( Location => qr/error=invalid_request/, 'an oversized nonce is rejected' );

# ── Authorization: malformed code_challenge (RFC 7636 ABNF) ──────────────────

$t->get_ok( '/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback'
		. '&response_type=code&scope=openid&state=cc1&code_challenge=tooshort&code_challenge_method=S256' )
	->status_is(302)
	->header_like( Location => qr/error=invalid_request/, 'a code_challenge shorter than 43 chars is rejected' );

# ── Authorization: scope is carried de-duplicated ────────────────────────────
# A scope's meaning is a set; repeats must not bloat the session cookie or the
# stored grants.

$t->reset_session;
$t->get_ok( '/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback'
		. '&response_type=code&scope=openid+openid+profile+openid&state=dd1' )->status_is(302);
$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $dd_code = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');
$t->post_ok(
	'/token',
	form => {
		grant_type   => 'authorization_code',
		code         => $dd_code,
		client_id    => 'testapp',
		redirect_uri => 'https://testapp.example.com/callback',
	}
)->status_is(200)->json_is( '/scope' => 'openid profile', 'duplicate scope values are collapsed' );

# ── Login form: no authz session → error ─────────────────────────────────────

# Clear session first
$t->reset_session;
$t->get_ok('/sso/login')
	->status_is(200)
	->content_like( qr/No Authorization Request/, 'login without authz session shows error' );

# ── Login form: with authz session → renders ─────────────────────────────────

# Start a proper authorization flow first
$t->get_ok(
	'/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid+profile+email&state=xyz&nonce=n1'
)->status_is(302);
$t->get_ok('/sso/login')->status_is(200)->content_like( qr/Sign In/, 'login form renders after authorize' );

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
	->content_like( qr/Test Application/, 'consent shows client name' )
	->content_like( qr/alice/,            'consent shows username' )
	->content_like( qr/openid/,           'consent shows openid scope' )
	->content_like( qr/profile/,          'consent shows profile scope' )
	->content_like( qr/email/,            'consent shows email scope' )
	->content_like( qr/Privacy Policy/,   'consent shows policy link' )
	->content_like( qr/Terms of Service/, 'consent shows ToS link' );

# ── Consent: deny ────────────────────────────────────────────────────────────

# Need to start a fresh flow for deny test
$t->reset_session;
$t->get_ok(
	'/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid&state=deny1'
)->status_is(302);
$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'deny' } )
	->status_is(302)
	->header_like( Location => qr/error=access_denied/, 'deny redirects with access_denied' )
	->header_like( Location => qr/state=deny1/,         'deny preserves state' );

# ── Full authorization code flow ─────────────────────────────────────────────

$t->reset_session;
_install_stubs( $t->app );

# Step 1: Authorize
$t->get_ok(
	'/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid+profile+email&state=flow1&nonce=nonce1'
)->status_is(302)->header_like( Location => qr{/sso/login}, 'flow: authorize redirects to login' );

# Step 2: Login
$t->post_ok( '/sso/login', form => { user => 'alice', pass => 'correct' } )
	->status_is(302)
	->header_like( Location => qr{/sso/consent}, 'flow: login redirects to consent' );

# Step 3: Consent (allow)
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);

# Extract code and state from redirect
my $redirect_url = $t->tx->res->headers->location;
like( $redirect_url, qr{^https://testapp\.example\.com/callback}, 'flow: redirect goes to callback URI' );
my $redirect_parsed = Mojo::URL->new($redirect_url);
my $auth_code       = $redirect_parsed->query->param('code');
my $ret_state       = $redirect_parsed->query->param('state');
ok( defined $auth_code && $auth_code ne '', 'flow: authorization code returned' );
is( $ret_state, 'flow1', 'flow: state preserved' );

# Step 4: Token exchange
$t->post_ok(
	'/token',
	form => {
		grant_type   => 'authorization_code',
		code         => $auth_code,
		redirect_uri => 'https://testapp.example.com/callback',
		client_id    => 'testapp',
	}
	)
	->status_is(200)
	->json_has('/access_token')
	->json_is( '/token_type' => 'Bearer' )
	->json_has('/expires_in')
	->json_has('/id_token')
	->json_is( '/scope' => 'openid profile email' );

my $token_resp   = $t->tx->res->json;
my $access_token = $token_resp->{access_token};
my $id_token     = $token_resp->{id_token};

# Verify ID token structure (RS256 JWT: header.payload.signature)
like( $id_token, qr/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/, 'id_token is a signed (RS256) JWT', );
my @jwt_parts   = split /\./, $id_token;
my $jwt_payload = decode_json( MIME::Base64::decode_base64( $jwt_parts[1] ) );
is( $jwt_payload->{iss},   'http://localhost', 'id_token iss correct' );
is( $jwt_payload->{sub},   'alice',            'id_token sub correct' );
is( $jwt_payload->{aud},   'testapp',          'id_token aud correct' );
is( $jwt_payload->{nonce}, 'nonce1',           'id_token nonce correct' );
ok( defined $jwt_payload->{iat},       'id_token has iat' );
ok( defined $jwt_payload->{exp},       'id_token has exp' );
ok( defined $jwt_payload->{auth_time}, 'id_token has auth_time' );
is( $jwt_payload->{name},  'Alice Wonderland',  'id_token has profile name' );
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

$t->post_ok(
	'/token',
	form => {
		grant_type   => 'authorization_code',
		code         => $auth_code,
		redirect_uri => 'https://testapp.example.com/callback',
		client_id    => 'testapp',
	}
)->status_is(400)->json_is( '/error' => 'invalid_grant', 'code reuse returns invalid_grant' );

# ── Token endpoint: unsupported grant_type ───────────────────────────────────

$t->post_ok( '/token', form => { grant_type => 'client_credentials' } )
	->status_is(400)
	->json_is( '/error' => 'unsupported_grant_type' );

# ── Token endpoint: wrong client_id ──────────────────────────────────────────

$t->reset_session;
_install_stubs( $t->app );

# Do a full flow to get a code
$t->get_ok(
	'/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid&state=s3'
)->status_is(302);
$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $code2 = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');

$t->post_ok(
	'/token',
	form => {
		grant_type   => 'authorization_code',
		code         => $code2,
		client_id    => 'wrong_client',
		redirect_uri => 'https://testapp.example.com/callback',
	}
)->status_is(401)->json_is( '/error' => 'invalid_client', 'unknown client_id fails client authentication' );

# ── Token endpoint: confidential client with wrong secret ────────────────────

$t->reset_session;
_install_stubs( $t->app );

$t->get_ok(
	'/authorize?client_id=secretapp&redirect_uri=https://secretapp.example.com/callback&response_type=code&scope=openid&state=s4'
)->status_is(302);
$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $code3 = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');

$t->post_ok(
	'/token',
	form => {
		grant_type    => 'authorization_code',
		code          => $code3,
		client_id     => 'secretapp',
		client_secret => 'wrongsecret',
		redirect_uri  => 'https://secretapp.example.com/callback',
	}
)->status_is(401)->json_is( '/error' => 'invalid_client', 'wrong secret returns invalid_client' );

# ── Token endpoint: registered auth method binds the transport ───────────────
# secretapp is registered client_secret_basic; the correct secret sent as a
# body parameter (client_secret_post transport) must be rejected.

$t->reset_session;
_install_stubs( $t->app );

$t->get_ok(
	'/authorize?client_id=secretapp&redirect_uri=https://secretapp.example.com/callback&response_type=code&scope=openid&state=s5'
)->status_is(302);
$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $code4 = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');

$t->post_ok(
	'/token',
	form => {
		grant_type    => 'authorization_code',
		code          => $code4,
		client_id     => 'secretapp',
		client_secret => 's3cret',
		redirect_uri  => 'https://secretapp.example.com/callback',
	}
)->status_is(401)->json_is(
	'/error' => 'invalid_client',
	'correct secret via the wrong transport (post for a basic client) is rejected'
);

# ── Token endpoint: client_secret_basic via Authorization header ─────────────

$t->reset_session;
_install_stubs( $t->app );

$t->get_ok(
	'/authorize?client_id=secretapp&redirect_uri=https://secretapp.example.com/callback&response_type=code&scope=openid&state=s6'
)->status_is(302);
$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $code5 = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');

my $basic_auth = 'Basic ' . MIME::Base64::encode_base64( 'secretapp:s3cret', '' );
$t->post_ok(
	'/token',
	{ Authorization => $basic_auth },
	form => {
		grant_type   => 'authorization_code',
		code         => $code5,
		redirect_uri => 'https://secretapp.example.com/callback',
	}
)->status_is(200)->json_has( '/access_token', 'client_secret_basic auth works' );

# ── PKCE: S256 ───────────────────────────────────────────────────────────────

$t->reset_session;
_install_stubs( $t->app );

my $code_verifier  = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
my $code_challenge = _b64url_encode( sha256($code_verifier) );

$t->get_ok(
	"/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid&state=pkce1&code_challenge=$code_challenge&code_challenge_method=S256"
)->status_is(302);
$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $pkce_code = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');

# Token with correct verifier
$t->post_ok(
	'/token',
	form => {
		grant_type    => 'authorization_code',
		code          => $pkce_code,
		client_id     => 'testapp',
		redirect_uri  => 'https://testapp.example.com/callback',
		code_verifier => $code_verifier,
	}
)->status_is(200)->json_has( '/access_token', 'PKCE S256 with correct verifier succeeds' );

# ── PKCE: S256 wrong verifier ────────────────────────────────────────────────

$t->reset_session;
_install_stubs( $t->app );

$t->get_ok(
	"/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid&state=pkce2&code_challenge=$code_challenge&code_challenge_method=S256"
)->status_is(302);
$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $pkce_code2 = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');

$t->post_ok(
	'/token',
	form => {
		grant_type    => 'authorization_code',
		code          => $pkce_code2,
		client_id     => 'testapp',
		redirect_uri  => 'https://testapp.example.com/callback',
		code_verifier => 'wrong-verifier-value',
	}
)->status_is(400)->json_like( '/error_description' => qr/PKCE/, 'wrong PKCE verifier fails' );

# ── PKCE: missing code_verifier when challenge was sent ──────────────────────

$t->reset_session;
_install_stubs( $t->app );

$t->get_ok(
	"/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid&state=pkce3&code_challenge=$code_challenge&code_challenge_method=S256"
)->status_is(302);
$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $pkce_code3 = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');

$t->post_ok(
	'/token',
	form => {
		grant_type   => 'authorization_code',
		code         => $pkce_code3,
		client_id    => 'testapp',
		redirect_uri => 'https://testapp.example.com/callback',
	}
)->status_is(400)->json_like( '/error_description' => qr/code_verifier/, 'missing code_verifier fails' );

# ── PKCE: plain method ──────────────────────────────────────────────────────

$t->reset_session;
_install_stubs( $t->app );

# RFC 7636: a code_challenge (and so a plain verifier) must be 43-128 chars.
my $plain_verifier = 'my-plain-verifier-string-that-is-long-enough-to-satisfy-rfc7636';

$t->get_ok(
	"/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid&state=pkce4&code_challenge=$plain_verifier&code_challenge_method=plain"
)->status_is(302);
$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $pkce_code4 = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');

$t->post_ok(
	'/token',
	form => {
		grant_type    => 'authorization_code',
		code          => $pkce_code4,
		client_id     => 'testapp',
		redirect_uri  => 'https://testapp.example.com/callback',
		code_verifier => $plain_verifier,
	}
)->status_is(200)->json_has( '/access_token', 'PKCE plain method succeeds' );

# ── UserInfo: no token → 401 ────────────────────────────────────────────────

$t->reset_session;
_install_stubs( $t->app );

$t->get_ok('/userinfo')->status_is(401)->json_is( '/error' => 'invalid_token' );

# ── UserInfo: invalid token → 401 ───────────────────────────────────────────

$t->get_ok( '/userinfo', { Authorization => 'Bearer bogus_token_value' } )
	->status_is(401)
	->json_is( '/error' => 'invalid_token' );

# ── UserInfo: phone scope ───────────────────────────────────────────────────

$t->reset_session;
_install_stubs( $t->app );

$t->get_ok(
	'/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid+phone&state=phone1'
)->status_is(302);
$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $phone_code = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');

$t->post_ok(
	'/token',
	form => {
		grant_type   => 'authorization_code',
		code         => $phone_code,
		client_id    => 'testapp',
		redirect_uri => 'https://testapp.example.com/callback',
	}
)->status_is(200);
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

$t->get_ok(
	'/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid+address&state=addr1'
)->status_is(302);
$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $addr_code = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');

$t->post_ok(
	'/token',
	form => {
		grant_type   => 'authorization_code',
		code         => $addr_code,
		client_id    => 'testapp',
		redirect_uri => 'https://testapp.example.com/callback',
	}
)->status_is(200);
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
_install_stubs( $t->app, userSelfInfo => sub { return { totpStatus => 'active' } }, );

$t->get_ok(
	'/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid&state=totp1'
)->status_is(302);

# Login with valid password → should redirect to TOTP challenge, not consent
$t->post_ok( '/sso/login', form => { user => 'alice', pass => 'correct' } )
	->status_is(302)
	->header_like( Location => qr{/sso/totp}, 'TOTP user redirected to TOTP challenge' );

# TOTP challenge form renders
$t->get_ok('/sso/totp')->status_is(200)->content_like( qr/TOTP|authenticator/i, 'TOTP challenge form renders' );

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
$t->get_ok(
	'/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid&state=nouser'
)->status_is(302);
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
$t->get_ok(
	'/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid&state=pre1'
)->status_is(302);
$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);

# Second authorize with an existing session and an already-granted consent →
# no UI at all: straight back to the client with a code.
$t->get_ok(
	'/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid&state=pre2'
)->status_is(302)->header_like(
	Location => qr{^https://testapp\.example\.com/callback},
	'already-authenticated, already-consented user skips login and consent'
)->header_like( Location => qr/state=pre2/, 'skipped flow still returns the request state' );

# ── Token endpoint: redirect_uri mismatch ────────────────────────────────────

$t->reset_session;
_install_stubs( $t->app );

$t->get_ok(
	'/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid&state=ruri1'
)->status_is(302);
$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $ruri_code = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');

$t->post_ok(
	'/token',
	form => {
		grant_type   => 'authorization_code',
		code         => $ruri_code,
		client_id    => 'testapp',
		redirect_uri => 'https://different.example.com/other',
	}
)->status_is(400)->json_like( '/error_description' => qr/redirect_uri/, 'redirect_uri mismatch returns error' );

# ── Referer check on SSO POST routes ────────────────────────────────────────

{
	# Temporarily remove referer hook to test the protection
	my $t2 = Test::Mojo->new('App::Nisaba::WebSSO');
	_install_stubs( $t2->app );

	$t2->post_ok('/sso/login')->status_is(403)->content_like( qr/Forbidden/, 'POST without Referer is rejected' );
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

$t->get_ok(
	'/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid&state=min1'
)->status_is(302);
$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $min_code = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');

$t->post_ok(
	'/token',
	form => {
		grant_type   => 'authorization_code',
		code         => $min_code,
		client_id    => 'testapp',
		redirect_uri => 'https://testapp.example.com/callback',
	}
)->status_is(200);
my $min_token = $t->tx->res->json->{access_token};

$t->get_ok( '/userinfo', { Authorization => "Bearer $min_token" } )->status_is(200)->json_is( '/sub' => 'alice' );

my $min_info = $t->tx->res->json;
ok( !exists $min_info->{name},         'openid-only: no name' );
ok( !exists $min_info->{email},        'openid-only: no email' );
ok( !exists $min_info->{phone_number}, 'openid-only: no phone' );
ok( !exists $min_info->{address},      'openid-only: no address' );

# ── RS256 ID token signing ──────────────────────────────────────────────────

# Generate a real RSA key pair for the test client
use Crypt::PK::RSA;
my $test_rsa = Crypt::PK::RSA->new;
$test_rsa->generate_key( 256, 65537 );    # 2048-bit

my $priv_jwk = Mojo::JSON::decode_json( $test_rsa->export_key_jwk('private') );
$priv_jwk->{kid} = 'test-rs256-kid';
$priv_jwk->{use} = 'sig';
$priv_jwk->{alg} = 'RS256';
my $rs256_jwks_json = Mojo::JSON::encode_json( { keys => [$priv_jwk] } );

my $client_rs256 = FakeEntry->new(
	_dn                          => 'oidcClientId=rs256app,ou=oidc,dc=example,dc=com',
	oidcClientId                 => 'rs256app',
	oidcClientName               => 'RS256 App',
	oidcRedirectURI              => ['https://rs256app.example.com/callback'],
	oidcScope                    => [ 'openid', 'profile', 'email' ],
	oidcGrantType                => ['authorization_code'],
	oidcResponseType             => ['code'],
	oidcApplicationType          => 'web',
	oidcTokenEndpointAuthMethod  => 'none',
	oidcIdTokenSignedResponseAlg => 'RS256',
	oidcJwks                     => $rs256_jwks_json,
	oidcPostLogoutRedirectURI    => ['https://rs256app.example.com/loggedout'],
);

$t->reset_session;
_install_stubs(
	$t->app,
	getOIDCClientEntry => sub {
		my ( $self, $args ) = @_;
		return $client_rs256        if ( $args->{clientId} // '' ) eq 'rs256app';
		return $client_public       if ( $args->{clientId} // '' ) eq 'testapp';
		return $client_confidential if ( $args->{clientId} // '' ) eq 'secretapp';
		return undef;
	},
);

$t->get_ok(
	'/authorize?client_id=rs256app&redirect_uri=https://rs256app.example.com/callback&response_type=code&scope=openid+profile+email&state=rs1&nonce=rsnonce1'
)->status_is(302);
$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $rs256_code = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');

$t->post_ok(
	'/token',
	form => {
		grant_type   => 'authorization_code',
		code         => $rs256_code,
		redirect_uri => 'https://rs256app.example.com/callback',
		client_id    => 'rs256app',
	}
)->status_is(200)->json_has('/id_token');

my $rs256_id_token = $t->tx->res->json->{id_token};

# RS256 JWT must have three non-empty parts (header.payload.signature)
my @rs256_parts = split /\./, $rs256_id_token;
is( scalar @rs256_parts, 3, 'RS256 id_token has 3 parts' );
ok( length( $rs256_parts[2] ) > 0, 'RS256 id_token has non-empty signature' );

# Verify header
my $rs256_header = Mojo::JSON::decode_json( MIME::Base64::decode_base64( $rs256_parts[0] ) );
is( $rs256_header->{alg}, 'RS256',          'RS256 header alg is RS256' );
is( $rs256_header->{typ}, 'JWT',            'RS256 header typ is JWT' );
is( $rs256_header->{kid}, 'test-rs256-kid', 'RS256 header has correct kid' );

# Verify payload claims
my $rs256_payload = Mojo::JSON::decode_json( MIME::Base64::decode_base64( $rs256_parts[1] ) );
is( $rs256_payload->{iss},   'http://localhost',  'RS256 id_token iss correct' );
is( $rs256_payload->{sub},   'alice',             'RS256 id_token sub correct' );
is( $rs256_payload->{aud},   'rs256app',          'RS256 id_token aud correct' );
is( $rs256_payload->{nonce}, 'rsnonce1',          'RS256 id_token nonce correct' );
is( $rs256_payload->{name},  'Alice Wonderland',  'RS256 id_token has profile name' );
is( $rs256_payload->{email}, 'alice@example.com', 'RS256 id_token has email' );
ok( defined $rs256_payload->{iat},                 'RS256 id_token has iat' );
ok( defined $rs256_payload->{exp},                 'RS256 id_token has exp' );
ok( $rs256_payload->{exp} > $rs256_payload->{iat}, 'RS256 id_token exp > iat' );

# Verify the RSA signature using the public key
my $rs256_signing_input = "$rs256_parts[0].$rs256_parts[1]";
my $rs256_sig_bytes     = _b64url_decode( $rs256_parts[2] );
my $verify_rsa          = Crypt::PK::RSA->new;
$verify_rsa->import_key( \( $test_rsa->export_key_pem('public') ) );
ok( $verify_rsa->verify_message( $rs256_sig_bytes, $rs256_signing_input, 'SHA256', 'v1.5' ),
	'RS256 signature verifies with public key' );

# ── RS256 JWKS endpoint serves public key ───────────────────────────────────

# Override getOIDCClients to return the RS256 client for /jwks
_install_stubs(
	$t->app,
	getOIDCClientEntry => sub {
		my ( $self, $args ) = @_;
		return $client_rs256        if ( $args->{clientId} // '' ) eq 'rs256app';
		return $client_public       if ( $args->{clientId} // '' ) eq 'testapp';
		return $client_confidential if ( $args->{clientId} // '' ) eq 'secretapp';
		return undef;
	},
	getOIDCClients => sub { return [$client_rs256] },
);

$t->get_ok('/jwks')->status_is(200)->json_has('/keys');

my $jwks_resp = $t->tx->res->json;
ok( @{ $jwks_resp->{keys} } >= 1, 'JWKS has at least one key' );
my $pub_jwk = $jwks_resp->{keys}[0];
is( $pub_jwk->{kty}, 'RSA',            'JWKS key type is RSA' );
is( $pub_jwk->{kid}, 'test-rs256-kid', 'JWKS key has correct kid' );
is( $pub_jwk->{use}, 'sig',            'JWKS key use is sig' );
is( $pub_jwk->{alg}, 'RS256',          'JWKS key alg is RS256' );
ok( defined $pub_jwk->{n},  'JWKS key has modulus n' );
ok( defined $pub_jwk->{e},  'JWKS key has exponent e' );
ok( !defined $pub_jwk->{d}, 'JWKS key does NOT expose private exponent d' );
ok( !defined $pub_jwk->{p}, 'JWKS key does NOT expose prime p' );
ok( !defined $pub_jwk->{q}, 'JWKS key does NOT expose prime q' );

# Verify the ID token signature using the key from the JWKS endpoint
my $jwks_verify_rsa = Crypt::PK::RSA->new;
$jwks_verify_rsa->import_key($pub_jwk);
ok( $jwks_verify_rsa->verify_message( $rs256_sig_bytes, $rs256_signing_input, 'SHA256', 'v1.5' ),
	'RS256 signature verifies with JWKS endpoint public key' );

# ── HS256 ID token signing ──────────────────────────────────────────────────

my $hs256_secret = 'super-secret-hmac-key-for-testing-hs256';

my $client_hs256 = FakeEntry->new(
	_dn                          => 'oidcClientId=hs256app,ou=oidc,dc=example,dc=com',
	oidcClientId                 => 'hs256app',
	oidcClientName               => 'HS256 App',
	oidcClientSecret             => $hs256_secret,
	oidcRedirectURI              => ['https://hs256app.example.com/callback'],
	oidcScope                    => [ 'openid', 'profile', 'email' ],
	oidcGrantType                => ['authorization_code'],
	oidcResponseType             => ['code'],
	oidcApplicationType          => 'web',
	oidcTokenEndpointAuthMethod  => 'client_secret_basic',
	oidcIdTokenSignedResponseAlg => 'HS256',
	oidcPostLogoutRedirectURI    => ['https://hs256app.example.com/loggedout'],
);

$t->reset_session;
_install_stubs(
	$t->app,
	getOIDCClientEntry => sub {
		my ( $self, $args ) = @_;
		return $client_hs256        if ( $args->{clientId} // '' ) eq 'hs256app';
		return $client_public       if ( $args->{clientId} // '' ) eq 'testapp';
		return $client_confidential if ( $args->{clientId} // '' ) eq 'secretapp';
		return undef;
	},
);

$t->get_ok(
	'/authorize?client_id=hs256app&redirect_uri=https://hs256app.example.com/callback&response_type=code&scope=openid+profile+email&state=hs1&nonce=hsnonce1'
)->status_is(302);
$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $hs256_code = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');

my $hs256_basic = 'Basic ' . MIME::Base64::encode_base64( "hs256app:$hs256_secret", '' );
$t->post_ok(
	'/token',
	{ Authorization => $hs256_basic },
	form => {
		grant_type   => 'authorization_code',
		code         => $hs256_code,
		redirect_uri => 'https://hs256app.example.com/callback',
	}
)->status_is(200)->json_has('/id_token');

my $hs256_id_token = $t->tx->res->json->{id_token};

# HS256 JWT must have three non-empty parts
my @hs256_parts = split /\./, $hs256_id_token;
is( scalar @hs256_parts, 3, 'HS256 id_token has 3 parts' );
ok( length( $hs256_parts[2] ) > 0, 'HS256 id_token has non-empty signature' );

# Verify header
my $hs256_header = Mojo::JSON::decode_json( MIME::Base64::decode_base64( $hs256_parts[0] ) );
is( $hs256_header->{alg}, 'HS256', 'HS256 header alg is HS256' );
is( $hs256_header->{typ}, 'JWT',   'HS256 header typ is JWT' );

# Verify payload claims
my $hs256_payload = Mojo::JSON::decode_json( MIME::Base64::decode_base64( $hs256_parts[1] ) );
is( $hs256_payload->{iss},   'http://localhost',  'HS256 id_token iss correct' );
is( $hs256_payload->{sub},   'alice',             'HS256 id_token sub correct' );
is( $hs256_payload->{aud},   'hs256app',          'HS256 id_token aud correct' );
is( $hs256_payload->{nonce}, 'hsnonce1',          'HS256 id_token nonce correct' );
is( $hs256_payload->{name},  'Alice Wonderland',  'HS256 id_token has profile name' );
is( $hs256_payload->{email}, 'alice@example.com', 'HS256 id_token has email' );

# Verify the HMAC-SHA256 signature using the client secret
my $hs256_signing_input = "$hs256_parts[0].$hs256_parts[1]";
my $hs256_expected_sig  = Digest::SHA::hmac_sha256( $hs256_signing_input, $hs256_secret );
my $hs256_actual_sig    = _b64url_decode( $hs256_parts[2] );
is( $hs256_actual_sig, $hs256_expected_sig, 'HS256 signature matches HMAC-SHA256 with client secret' );

# ── HS256: wrong secret does not verify ─────────────────────────────────────

my $hs256_wrong_sig = Digest::SHA::hmac_sha256( $hs256_signing_input, 'wrong-secret' );
isnt( $hs256_actual_sig, $hs256_wrong_sig, 'HS256 signature does not match with wrong secret' );

# ── Authorization code expiration ───────────────────────────────────────────

# Get a code with normal lifetime, then shrink ssoCodeLifetime to 0 before
# exchanging it so the server considers it immediately expired.
$t->reset_session;
_install_stubs( $t->app );

$t->get_ok(
	'/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid&state=exp1'
)->status_is(302);
$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $exp_code = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');

# Set ssoCodeLifetime to -1 so any code age exceeds it
$t->app->helper(
	pt => sub {
		my $fake_pt = bless {
			ini => {
				'' => {
					ssoIssuer               => 'http://localhost',
					ssoTokenLifetime        => 3600,
					ssoCodeLifetime         => -1,
					passkeyRpId             => '',
					passkeyUserVerification => 'preferred',
				},
			},
			},
			'FakePT';
		return $fake_pt;
	}
);

$t->post_ok(
	'/token',
	form => {
		grant_type   => 'authorization_code',
		code         => $exp_code,
		client_id    => 'testapp',
		redirect_uri => 'https://testapp.example.com/callback',
	}
	)
	->status_is(400)
	->json_is( '/error' => 'invalid_grant' )
	->json_like( '/error_description' => qr/expired/i, 'expired code returns invalid_grant with expiry message' );

# ── Access token expiration ─────────────────────────────────────────────────

$t->reset_session;
_install_stubs( $t->app );

$t->get_ok(
	'/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid&state=tokexp1'
)->status_is(302);
$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $tokexp_code = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');

$t->post_ok(
	'/token',
	form => {
		grant_type   => 'authorization_code',
		code         => $tokexp_code,
		client_id    => 'testapp',
		redirect_uri => 'https://testapp.example.com/callback',
	}
)->status_is(200);
my $tokexp_token = $t->tx->res->json->{access_token};

# Verify the token works first
$t->get_ok( '/userinfo', { Authorization => "Bearer $tokexp_token" } )
	->status_is(200)
	->json_is( '/sub' => 'alice', 'token works before expiry' );

# Set ssoTokenLifetime to -1 so any token age exceeds it
$t->app->helper(
	pt => sub {
		my $fake_pt = bless {
			ini => {
				'' => {
					ssoIssuer               => 'http://localhost',
					ssoTokenLifetime        => -1,
					ssoCodeLifetime         => 600,
					passkeyRpId             => '',
					passkeyUserVerification => 'preferred',
				},
			},
			},
			'FakePT';
		return $fake_pt;
	}
);

$t->get_ok( '/userinfo', { Authorization => "Bearer $tokexp_token" } )
	->status_is(401)
	->json_is( '/error' => 'invalid_token', 'expired token returns invalid_token' );

# Verify the token was cleaned up from the session (subsequent request also 401)
$t->get_ok( '/userinfo', { Authorization => "Bearer $tokexp_token" } )
	->status_is(401)
	->json_is( '/error' => 'invalid_token', 'expired token cleaned from session' );

# ── client_secret_post in isolation ─────────────────────────────────────────
# A client registered client_secret_post authenticates with the secret as a
# form parameter — and only that way.

my $client_post = FakeEntry->new(
	_dn                          => 'oidcClientId=postapp,ou=oidc,dc=example,dc=com',
	oidcClientId                 => 'postapp',
	oidcClientName               => 'Post App',
	oidcClientSecret             => 'p0st-s3cret',
	oidcIdTokenSignedResponseAlg => 'HS256',
	oidcRedirectURI              => ['https://postapp.example.com/callback'],
	oidcScope                    => ['openid'],
	oidcGrantType                => ['authorization_code'],
	oidcResponseType             => ['code'],
	oidcApplicationType          => 'web',
	oidcTokenEndpointAuthMethod  => 'client_secret_post',
);

sub _install_stubs_postapp {
	my ($app) = @_;
	_install_stubs(
		$app,
		getOIDCClientEntry => sub {
			my ( $self, $args ) = @_;
			return $client_post if ( $args->{clientId} // '' ) eq 'postapp';
			return undef;
		},
	);
} ## end sub _install_stubs_postapp

my $get_postapp_code = sub {
	$t->reset_session;
	$t->get_ok( '/authorize?client_id=postapp&redirect_uri=https://postapp.example.com/callback'
			. '&response_type=code&scope=openid&state=csp1' )->status_is(302);
	$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
	$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
	return Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');
};

_install_stubs_postapp( $t->app );

# Wrong secret via form parameter
my $csp_code = $get_postapp_code->();
$t->post_ok(
	'/token',
	form => {
		grant_type    => 'authorization_code',
		code          => $csp_code,
		client_id     => 'postapp',
		client_secret => 'wrongsecret',
		redirect_uri  => 'https://postapp.example.com/callback',
	}
)->status_is(401)->json_is( '/error' => 'invalid_client', 'client_secret_post: wrong secret rejected' );

# Correct secret via form parameter (need a new code since previous was consumed)
my $csp_code2 = $get_postapp_code->();
$t->post_ok(
	'/token',
	form => {
		grant_type    => 'authorization_code',
		code          => $csp_code2,
		client_id     => 'postapp',
		client_secret => 'p0st-s3cret',
		redirect_uri  => 'https://postapp.example.com/callback',
	}
	)
	->status_is(200)
	->json_has( '/access_token', 'client_secret_post: correct secret accepted via form param' )
	->json_is( '/token_type' => 'Bearer' );

# Correct secret via the Basic header is the wrong transport for this client.
my $csp_code3  = $get_postapp_code->();
my $post_basic = 'Basic ' . MIME::Base64::encode_base64( 'postapp:p0st-s3cret', '' );
$t->post_ok(
	'/token',
	{ Authorization => $post_basic },
	form => {
		grant_type   => 'authorization_code',
		code         => $csp_code3,
		redirect_uri => 'https://postapp.example.com/callback',
	}
)->status_is(401)->json_is( '/error' => 'invalid_client', 'client_secret_post: Basic transport is rejected' );

_install_stubs( $t->app );

# ── client_secret_basic: malformed Authorization header ─────────────────────

$t->reset_session;
_install_stubs( $t->app );

$t->get_ok(
	'/authorize?client_id=secretapp&redirect_uri=https://secretapp.example.com/callback&response_type=code&scope=openid&state=malauth1'
)->status_is(302);
$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $malauth_code = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');

# Send a Basic auth header with wrong credentials
my $bad_basic = 'Basic ' . MIME::Base64::encode_base64( 'secretapp:wrongpassword', '' );
$t->post_ok(
	'/token',
	{ Authorization => $bad_basic },
	form => {
		grant_type   => 'authorization_code',
		code         => $malauth_code,
		redirect_uri => 'https://secretapp.example.com/callback',
	}
)->status_is(401)->json_is( '/error' => 'invalid_client', 'client_secret_basic: wrong secret in header rejected' );

# ── Discovery: JWKS URI ────────────────────────────────────────────────────

$t->get_ok('/.well-known/openid-configuration')
	->status_is(200)
	->json_is( '/jwks_uri' => 'http://localhost/jwks', 'discovery includes jwks_uri' )
	->json_has('/id_token_signing_alg_values_supported');

my $disc     = $t->tx->res->json;
my $alg_list = $disc->{id_token_signing_alg_values_supported};
ok( ( grep { $_ eq 'RS256' } @$alg_list ), 'discovery advertises RS256' );
ok( ( grep { $_ eq 'HS256' } @$alg_list ), 'discovery advertises HS256' );
ok( !( grep { $_ eq 'none' } @$alg_list ), 'discovery does not advertise alg:none' );

# ── UserInfo via POST ───────────────────────────────────────────────────────

$t->reset_session;
_install_stubs( $t->app );

$t->get_ok(
	'/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid+profile&state=uipost1'
)->status_is(302);
$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $uipost_code = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');

$t->post_ok(
	'/token',
	form => {
		grant_type   => 'authorization_code',
		code         => $uipost_code,
		client_id    => 'testapp',
		redirect_uri => 'https://testapp.example.com/callback',
	}
)->status_is(200);
my $uipost_token = $t->tx->res->json->{access_token};

# POST to /userinfo with Bearer token (OIDC Core 5.3.1 allows GET and POST).
# The referer hook does NOT add a Referer for /userinfo, so this also proves
# the endpoint is exempt from the CSRF Referer check (RP server-to-server call).
$t->post_ok( '/userinfo', { Authorization => "Bearer $uipost_token" } )
	->status_is(200)
	->json_is( '/sub'  => 'alice',            'UserInfo POST: sub correct' )
	->json_is( '/name' => 'Alice Wonderland', 'UserInfo POST: name correct' );

# ── UserInfo POST without Referer is allowed even with no referer hook ───────
# A fresh client with no referer hook at all must still reach POST /userinfo.

{
	my $t_api = Test::Mojo->new('App::Nisaba::WebSSO');
	_install_stubs( $t_api->app );

	# Browser steps need a Referer; add it only for the login/consent POSTs.
	$t_api->ua->on(
		start => sub {
			my ( $ua, $tx ) = @_;
			return unless $tx->req->method eq 'POST';
			return if $tx->req->url->path eq '/token';
			return if $tx->req->url->path eq '/userinfo';
			my $host = $tx->req->url->to_abs->host_port // 'localhost';
			$tx->req->headers->referrer("http://$host/");
			$tx->req->headers->header( 'X-CSRF-Token' => 'testcsrf' );
		}
	);

	$t_api->get_ok(
		'/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid+profile&state=apiui1'
	)->status_is(302);
	$t_api->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
	$t_api->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
	my $api_code = Mojo::URL->new( $t_api->tx->res->headers->location )->query->param('code');

	$t_api->post_ok(
		'/token',
		form => {
			grant_type   => 'authorization_code',
			code         => $api_code,
			client_id    => 'testapp',
			redirect_uri => 'https://testapp.example.com/callback',
		}
	)->status_is(200);
	my $api_token = $t_api->tx->res->json->{access_token};

	# No Referer on this POST — must NOT be 403
	$t_api->post_ok( '/userinfo', { Authorization => "Bearer $api_token" } )
		->status_is(200)
		->json_is( '/sub' => 'alice', 'POST /userinfo works without a Referer header' );
}

# ── expires_in is a JSON number even when config provides a string ──────────
# Config::IniHash yields strings; RFC 6749 5.1 requires expires_in to be a number.

$t->reset_session;
_install_stubs( $t->app );
$t->app->helper(
	pt => sub {
		my $fake_pt = bless {
			ini => {
				'' => {
					ssoIssuer               => 'http://localhost',
					ssoTokenLifetime        => '1800',               # string, as it would come from INI
					ssoCodeLifetime         => '600',
					passkeyRpId             => '',
					passkeyUserVerification => 'preferred',
				},
			},
			},
			'FakePT';
		return $fake_pt;
	}
);

$t->get_ok(
	'/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid&state=numexp1'
)->status_is(302);
$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $numexp_code = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');

$t->post_ok(
	'/token',
	form => {
		grant_type   => 'authorization_code',
		code         => $numexp_code,
		client_id    => 'testapp',
		redirect_uri => 'https://testapp.example.com/callback',
	}
)->status_is(200);
like( $t->tx->res->body, qr/"expires_in":1800(?:[,}])/, 'expires_in serialized as a JSON number, not a string' );

# ── Authorize: missing response_type → invalid_request (RFC 6749 4.1.2.1) ───

$t->reset_session;
_install_stubs( $t->app );

$t->get_ok('/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&scope=openid&state=nort1')
	->status_is(302)
	->header_like( Location => qr/error=invalid_request/, 'missing response_type is invalid_request' )
	->header_like( Location => qr/state=nort1/,           'state preserved on missing response_type' );

# ── auth_time reflects actual login, not token issuance (OIDC Core 2) ────────
# Log in once, wait, then run a second authorize that skips login (already
# authenticated). The ID token's auth_time must be the original login time,
# strictly earlier than the token's iat.

$t->reset_session;
_install_stubs( $t->app );

# First cycle: authenticate (sets sso_user + sso_auth_time)
$t->get_ok(
	'/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid&state=at1'
)->status_is(302);
$t->post_ok( '/sso/login', form => { user => 'alice', pass => 'correct' } )
	->status_is(302)
	->header_like( Location => qr{/sso/consent}, 'auth_time: first login reaches consent' );

sleep 1;    # ensure token issuance lands in a later second than login

# Second cycle: already authenticated → straight to consent, then issue a token
$t->get_ok(
	'/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid&state=at2'
)->status_is(302)->header_like( Location => qr{/sso/consent}, 'auth_time: second authorize skips login' );
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $at_code = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');

$t->post_ok(
	'/token',
	form => {
		grant_type   => 'authorization_code',
		code         => $at_code,
		client_id    => 'testapp',
		redirect_uri => 'https://testapp.example.com/callback',
	}
)->status_is(200);
my $at_id_token = $t->tx->res->json->{id_token};
my @at_parts    = split /\./, $at_id_token;
my $at_payload  = decode_json( MIME::Base64::decode_base64( $at_parts[1] ) );

ok( defined $at_payload->{auth_time}, 'auth_time present' );
ok( $at_payload->{auth_time} < $at_payload->{iat},
	'auth_time is the original login time, strictly earlier than token iat' );

# ── Token endpoint: 401 via Basic auth carries WWW-Authenticate (RFC 6749 5.2) ──

$t->reset_session;
_install_stubs( $t->app );

$t->get_ok(
	'/authorize?client_id=secretapp&redirect_uri=https://secretapp.example.com/callback&response_type=code&scope=openid&state=wwwauth1'
)->status_is(302);
$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $wwwauth_code = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');

my $wwwauth_bad = 'Basic ' . MIME::Base64::encode_base64( 'secretapp:wrongsecret', '' );
$t->post_ok(
	'/token',
	{ Authorization => $wwwauth_bad },
	form => {
		grant_type   => 'authorization_code',
		code         => $wwwauth_code,
		redirect_uri => 'https://secretapp.example.com/callback',
	}
	)
	->status_is(401)
	->json_is( '/error' => 'invalid_client' )
	->header_like( 'WWW-Authenticate' => qr/^Basic/, 'failed Basic auth carries WWW-Authenticate' );

# ── Authorize: unsupported code_challenge_method rejected (RFC 7636 4.3) ─────

$t->reset_session;
_install_stubs( $t->app );

$t->get_ok(
	'/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid&state=ccm1&code_challenge=abc123&code_challenge_method=BOGUS'
	)
	->status_is(302)
	->header_like( Location => qr/error=invalid_request/, 'unsupported code_challenge_method rejected' )
	->header_like( Location => qr/state=ccm1/,            'state preserved on ccm error' );

# ── ID token: RS256 client with no key fails closed (no alg=none downgrade) ──

my $client_rs256_nokey = FakeEntry->new(
	_dn                          => 'oidcClientId=rs256nokey,ou=oidc,dc=example,dc=com',
	oidcClientId                 => 'rs256nokey',
	oidcClientName               => 'RS256 No Key App',
	oidcRedirectURI              => ['https://rs256nokey.example.com/callback'],
	oidcScope                    => [ 'openid', 'profile' ],
	oidcGrantType                => ['authorization_code'],
	oidcResponseType             => ['code'],
	oidcApplicationType          => 'web',
	oidcTokenEndpointAuthMethod  => 'none',
	oidcIdTokenSignedResponseAlg => 'RS256',
	# deliberately no oidcJwks
);

$t->reset_session;
_install_stubs(
	$t->app,
	getOIDCClientEntry => sub {
		my ( $self, $args ) = @_;
		return $client_rs256_nokey if ( $args->{clientId} // '' ) eq 'rs256nokey';
		return $client_public      if ( $args->{clientId} // '' ) eq 'testapp';
		return undef;
	},
);

$t->get_ok(
	'/authorize?client_id=rs256nokey&redirect_uri=https://rs256nokey.example.com/callback&response_type=code&scope=openid+profile&state=nokey1'
)->status_is(302);
$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $nokey_code = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');

$t->post_ok(
	'/token',
	form => {
		grant_type   => 'authorization_code',
		code         => $nokey_code,
		client_id    => 'rs256nokey',
		redirect_uri => 'https://rs256nokey.example.com/callback',
	}
)->status_is(500)->json_is( '/error' => 'server_error', 'RS256 without key fails closed, no alg=none downgrade' );

# ── Shared store enables true server-to-server redemption (no shared cookie) ──
# This is the whole point of the external store: the relying party's back end
# redeems the code and calls UserInfo from separate processes that have no
# access to the browser's session cookie. Each Test::Mojo below is an
# independent UA/app sharing only the grant store.

{
	# Browser UA: authenticate and obtain an authorization code.
	my $t_browser = Test::Mojo->new('App::Nisaba::WebSSO');
	_install_stubs( $t_browser->app );
	_add_referer_hook($t_browser);

	$t_browser->get_ok(
		'/authorize?client_id=secretapp&redirect_uri=https://secretapp.example.com/callback&response_type=code&scope=openid+profile&state=s2s1'
	)->status_is(302);
	$t_browser->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
	$t_browser->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
	my $s2s_code = Mojo::URL->new( $t_browser->tx->res->headers->location )->query->param('code');
	ok( $s2s_code, 's2s: browser obtained an authorization code' );

	# RP back end: a completely separate UA/app with no cookies from the browser.
	my $t_rp = Test::Mojo->new('App::Nisaba::WebSSO');
	_install_stubs( $t_rp->app );

	my $rp_basic = 'Basic ' . MIME::Base64::encode_base64( 'secretapp:s3cret', '' );
	$t_rp->post_ok(
		'/token',
		{ Authorization => $rp_basic },
		form => {
			grant_type   => 'authorization_code',
			code         => $s2s_code,
			redirect_uri => 'https://secretapp.example.com/callback',
		}
	)->status_is(200)->json_has( '/access_token', 's2s: RP redeemed code with no browser cookie' );
	my $s2s_token = $t_rp->tx->res->json->{access_token};

	# UserInfo from yet another cookieless request.
	my $t_rp2 = Test::Mojo->new('App::Nisaba::WebSSO');
	_install_stubs( $t_rp2->app );
	$t_rp2->get_ok( '/userinfo', { Authorization => "Bearer $s2s_token" } )
		->status_is(200)
		->json_is( '/sub' => 'alice', 's2s: UserInfo resolved token with no browser cookie' );

	# The code is single-use: a replay (even by the RP) is rejected.
	$t_rp->post_ok(
		'/token',
		{ Authorization => $rp_basic },
		form => {
			grant_type   => 'authorization_code',
			code         => $s2s_code,
			redirect_uri => 'https://secretapp.example.com/callback',
		}
	)->status_is(400)->json_is( '/error' => 'invalid_grant', 's2s: code replay rejected (one-time use)' );
}

# ── Storage module contract (white box) ─────────────────────────────────────

{
	my $s = App::Nisaba::WebSSO::Storage->new( { backend => 'SQLite', path => ':memory:' } );

	# put / get round-trip
	$s->put( 'code', 'abc', { user => 'bob', n => 1 }, 600 );
	my $got = $s->get( 'code', 'abc' );
	is( ref $got,     'HASH', 'storage get returns a hashref' );
	is( $got->{user}, 'bob',  'storage round-trips data' );
	is( $got->{n},    1,      'storage round-trips numbers' );
	ok( $s->get( 'code', 'abc' ), 'storage get is non-destructive' );

	# consume is single-use
	my $c = $s->consume( 'code', 'abc' );
	is( $c->{user},                   'bob', 'storage consume returns data' );
	is( $s->consume( 'code', 'abc' ), undef, 'storage consume is single-use' );
	is( $s->get( 'code', 'abc' ),     undef, 'storage consume deleted the entry' );

	# kind namespacing: same raw key, different kinds
	$s->put( 'code',  'k', { which => 'code' },  600 );
	$s->put( 'token', 'k', { which => 'token' }, 600 );
	is( $s->get( 'code',  'k' )->{which}, 'code',  'storage namespaces by kind (code)' );
	is( $s->get( 'token', 'k' )->{which}, 'token', 'storage namespaces by kind (token)' );

	# delete
	$s->delete( 'token', 'k' );
	is( $s->get( 'token', 'k' ), undef, 'storage delete removes the entry' );

	# keys are hashed at rest, never stored in the clear
	$s->put( 'code', 'plaintext-secret-code', { x => 1 }, 600 );
	my ($leak)
		= $s->{backend}{dbh}
		->selectrow_array(q{SELECT COUNT(*) FROM oidc_store WHERE skey LIKE '%plaintext-secret-code%'});
	is( $leak, 0, 'storage does not persist the raw key' );
	ok( defined $s->get( 'code', 'plaintext-secret-code' ), 'hashed key still resolves' );

	# backend honors absolute expiry and cleanup (tested directly, no sleeps)
	my $b = $s->{backend};
	$b->put( 'expkey', 'blob', time() - 1 );
	is( $b->get('expkey'), undef, 'backend honors past expiry on get' );

	$b->put( 'gc-expired', 'x', time() - 5 );
	$b->put( 'gc-live',    'y', time() + 600 );
	my $removed = $b->cleanup;
	ok( $removed >= 1,              'backend cleanup removes expired rows' );
	ok( defined $b->get('gc-live'), 'backend cleanup keeps live rows' );
}

# ── Logout / end-session (OIDC RP-Initiated Logout) ─────────────────────────

# Discovery advertises the end-session endpoint
$t->reset_session;
_install_stubs( $t->app );
$t->get_ok('/.well-known/openid-configuration')
	->status_is(200)
	->json_is( '/end_session_endpoint' => 'http://localhost/sso/logout', 'discovery advertises end_session_endpoint' );

# GET /sso/logout with no id_token_hint → confirmation page (anti logout-CSRF)
$t->get_ok('/sso/logout')
	->status_is(200)
	->content_like( qr/Sign Out/i, 'logout without hint shows a confirmation page' );

# POST /sso/logout clears the SSO session
$t->reset_session;
_install_stubs( $t->app );

# Establish an SSO session.
$t->get_ok(
	'/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid&state=lo1'
)->status_is(302);
$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);

# Session is active: a second authorize completes without any login UI.
$t->get_ok(
	'/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid&state=lo2'
	)
	->status_is(302)
	->header_like( Location => qr{^https://testapp\.example\.com/callback}, 'logout: session active before logout' );

# Log out.
$t->post_ok('/sso/logout')->status_is(200)->content_like( qr/signed out/i, 'logout: logged-out page shown' );

# Session gone: a fresh authorize now requires login again.
$t->get_ok(
	'/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid&state=lo3'
)->status_is(302)->header_like( Location => qr{/sso/login}, 'logout cleared the SSO session' );

# RP-initiated logout with a verifiable id_token_hint. First mint a real RS256
# ID token to use as the hint.
$t->reset_session;
_install_stubs(
	$t->app,
	getOIDCClientEntry => sub {
		my ( $self, $args ) = @_;
		return $client_rs256  if ( $args->{clientId} // '' ) eq 'rs256app';
		return $client_public if ( $args->{clientId} // '' ) eq 'testapp';
		return undef;
	},
);

$t->get_ok(
	'/authorize?client_id=rs256app&redirect_uri=https://rs256app.example.com/callback&response_type=code&scope=openid&state=lo4'
)->status_is(302);
$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $lo_code = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');
$t->post_ok(
	'/token',
	form => {
		grant_type   => 'authorization_code',
		code         => $lo_code,
		client_id    => 'rs256app',
		redirect_uri => 'https://rs256app.example.com/callback',
	}
)->status_is(200);
my $lo_id_token = $t->tx->res->json->{id_token};
ok( $lo_id_token, 'logout: obtained an RS256 id_token for the hint' );

# Verified hint + registered post_logout_redirect_uri → 302 with state, no prompt.
$t->get_ok(
	"/sso/logout?id_token_hint=$lo_id_token&post_logout_redirect_uri=https://rs256app.example.com/loggedout&state=xyz789"
)->status_is(302)->header_is(
	Location => 'https://rs256app.example.com/loggedout?state=xyz789',
	'verified hint redirects to registered post_logout_redirect_uri with state'
);

# Verified hint + UNREGISTERED post_logout_redirect_uri → no redirect (open-redirect defense).
$t->reset_session;
_install_stubs(
	$t->app,
	getOIDCClientEntry => sub {
		my ( $self, $args ) = @_;
		return $client_rs256  if ( $args->{clientId} // '' ) eq 'rs256app';
		return $client_public if ( $args->{clientId} // '' ) eq 'testapp';
		return undef;
	},
);
$t->get_ok("/sso/logout?id_token_hint=$lo_id_token&post_logout_redirect_uri=https://evil.example.com/steal")
	->status_is(200)
	->content_like( qr/signed out/i, 'unregistered post_logout_redirect_uri is not honored' );

# POST with client_id (no hint) + registered URI → 302 after confirmation.
$t->reset_session;
_install_stubs(
	$t->app,
	getOIDCClientEntry => sub {
		my ( $self, $args ) = @_;
		return $client_rs256  if ( $args->{clientId} // '' ) eq 'rs256app';
		return $client_public if ( $args->{clientId} // '' ) eq 'testapp';
		return undef;
	},
);
$t->post_ok(
	'/sso/logout',
	form => {
		client_id                => 'rs256app',
		post_logout_redirect_uri => 'https://rs256app.example.com/loggedout',
		state                    => 'st42',
	}
)->status_is(302)->header_is(
	Location => 'https://rs256app.example.com/loggedout?state=st42',
	'POST logout with client_id redirects to registered URI'
);

# A forged/unsigned hint is not treated as verified: GET falls back to the
# confirmation page rather than logging out silently.
$t->reset_session;
_install_stubs( $t->app );
my $forged = _b64url_encode('{"alg":"none","typ":"JWT"}') . '.'
	. _b64url_encode('{"iss":"http://localhost","aud":"testapp","sub":"alice"}') . '.';
$t->get_ok("/sso/logout?id_token_hint=$forged&post_logout_redirect_uri=https://testapp.example.com/callback")
	->status_is(200)
	->content_like( qr/Sign Out/i, 'unsigned id_token_hint requires confirmation' );

# A validly signed hint for a DIFFERENT user must not silently log the current
# user out: an attacker can always obtain an ID token for their own account
# and embed it in a crafted link. The victim gets the confirmation page and
# keeps their session.
$t->reset_session;
_install_stubs( $t->app );

# Sign hints locally with testapp's key (the same key material the provider
# verifies against).
my $sign_hint = sub {
	my ($user) = @_;
	my $hint_header = _b64url_encode('{"alg":"RS256","typ":"JWT","kid":"testapp-kid"}');
	my $hint_payload
		= _b64url_encode(
			Mojo::JSON::encode_json( { iss => 'http://localhost', aud => 'testapp', sub => $user, iat => time() } ) );
	my $hint_sig = _b64url_encode( $testapp_rsa->sign_message( "$hint_header.$hint_payload", 'SHA256', 'v1.5' ) );
	return "$hint_header.$hint_payload.$hint_sig";
};

# Establish alice's SSO session.
$t->get_ok(
	'/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid&state=fl1'
)->status_is(302);
$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);

# Mallory's own (validly signed) token does not force alice out.
my $mallory_hint = $sign_hint->('mallory');
$t->get_ok("/sso/logout?id_token_hint=$mallory_hint")
	->status_is(200)
	->content_like( qr/Sign Out/i, q{another user's verified hint gets the confirmation page, not a logout} );
$t->get_ok(
	'/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid&state=fl2'
	)
	->status_is(302)
	->header_like( Location => qr{^https://testapp\.example\.com/callback}, q{alice's session survived the attempt} );

# A client_id parameter conflicting with the hint's audience also demands
# confirmation (RP-Initiated Logout 1.0: they MUST correspond).
my $alice_hint = $sign_hint->('alice');
$t->get_ok("/sso/logout?id_token_hint=$alice_hint&client_id=secretapp")
	->status_is(200)
	->content_like( qr/Sign Out/i, 'client_id conflicting with the hint audience requires confirmation' );

# The session user's own verified hint still logs out silently.
$t->get_ok("/sso/logout?id_token_hint=$alice_hint")
	->status_is(200)
	->content_like( qr/signed out/i, q{the session user's own verified hint logs out without confirmation} );
$t->get_ok(
	'/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid&state=fl3'
)->status_is(302)->header_like( Location => qr{/sso/login}, 'the matching hint really ended the session' );

# ── Token endpoint: client resolution fails closed ──────────────────────────
# The secret check depends on the client entry, so the token endpoint must
# refuse to proceed when the client cannot be resolved — a lookup error is a
# server_error and a vanished client is invalid_client. It must never fall
# through with authentication unchecked.

# A lookup that errors out (e.g. LDAP down between code issuance and
# redemption) → server_error.
$t->reset_session;
_install_stubs( $t->app );
$t->get_ok(
	'/authorize?client_id=secretapp&redirect_uri=https://secretapp.example.com/callback&response_type=code&scope=openid&state=fc1'
)->status_is(302);
$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $fc_code1 = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');

_install_stubs( $t->app, getOIDCClientEntry => sub { die "LDAP unavailable\n" } );
$t->post_ok(
	'/token',
	form => {
		grant_type    => 'authorization_code',
		code          => $fc_code1,
		client_id     => 'secretapp',
		client_secret => 's3cret',
		redirect_uri  => 'https://secretapp.example.com/callback',
	}
	)
	->status_is(500)
	->json_is( '/error' => 'server_error', 'client lookup error at token time fails closed with server_error' );

# A client deregistered since the code was issued → invalid_client, even when
# the caller presents the (formerly) correct secret.
$t->reset_session;
_install_stubs( $t->app );
$t->get_ok(
	'/authorize?client_id=secretapp&redirect_uri=https://secretapp.example.com/callback&response_type=code&scope=openid&state=fc2'
)->status_is(302);
$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $fc_code2 = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');

_install_stubs( $t->app, getOIDCClientEntry => sub { return undef } );
$t->post_ok(
	'/token',
	form => {
		grant_type    => 'authorization_code',
		code          => $fc_code2,
		client_id     => 'secretapp',
		client_secret => 's3cret',
		redirect_uri  => 'https://secretapp.example.com/callback',
	}
	)
	->status_is(401)
	->json_is( '/error' => 'invalid_client', 'client gone at token time fails closed with invalid_client' );

_install_stubs( $t->app );

# ── Unregistered signing alg defaults to RS256 (OIDC Core 2) ────────────────
# A client entry with no oidcIdTokenSignedResponseAlg gets RS256, the spec
# default — provided it has a usable key. Without key material it still fails
# closed rather than emitting an unsigned token.

# Signs with the same key pair as testapp so the signature can be verified here.
my $client_default_alg = FakeEntry->new(
	_dn                         => 'oidcClientId=defaultalg,ou=oidc,dc=example,dc=com',
	oidcClientId                => 'defaultalg',
	oidcRedirectURI             => ['https://defaultalg.example.com/cb'],
	oidcScope                   => ['openid'],
	oidcGrantType               => ['authorization_code'],
	oidcResponseType            => ['code'],
	oidcTokenEndpointAuthMethod => 'none',
	# deliberately no oidcIdTokenSignedResponseAlg
	oidcJwks => $testapp_jwks_json,
);

# No alg registered and no key material at all.
my $client_default_nokey = FakeEntry->new(
	_dn                         => 'oidcClientId=defaultnokey,ou=oidc,dc=example,dc=com',
	oidcClientId                => 'defaultnokey',
	oidcRedirectURI             => ['https://defaultnokey.example.com/cb'],
	oidcScope                   => ['openid'],
	oidcGrantType               => ['authorization_code'],
	oidcResponseType            => ['code'],
	oidcTokenEndpointAuthMethod => 'none',
	# deliberately no oidcIdTokenSignedResponseAlg and no oidcJwks
);

$t->reset_session;
_install_stubs(
	$t->app,
	getOIDCClientEntry => sub {
		my ( $self, $args ) = @_;
		return $client_default_alg   if ( $args->{clientId} // '' ) eq 'defaultalg';
		return $client_default_nokey if ( $args->{clientId} // '' ) eq 'defaultnokey';
		return undef;
	},
);

$t->get_ok(
	'/authorize?client_id=defaultalg&redirect_uri=https://defaultalg.example.com/cb&response_type=code&scope=openid&state=da1&nonce=danonce1'
)->status_is(302);
$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $da_code = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');

$t->post_ok(
	'/token',
	form => {
		grant_type   => 'authorization_code',
		code         => $da_code,
		client_id    => 'defaultalg',
		redirect_uri => 'https://defaultalg.example.com/cb',
	}
)->status_is(200)->json_has( '/id_token', 'client without a registered signing alg completes the token exchange' );

my $da_id_token = $t->tx->res->json->{id_token};
my @da_parts    = split /\./, $da_id_token;
is( scalar @da_parts, 3, 'default-alg id_token is a signed JWT' );
my $da_header = decode_json( _b64url_decode( $da_parts[0] ) );
is( $da_header->{alg}, 'RS256',       'unregistered signing alg defaults to RS256' );
is( $da_header->{kid}, 'testapp-kid', 'default-alg id_token carries the key id' );
ok(
	$testapp_rsa->verify_message( _b64url_decode( $da_parts[2] ), "$da_parts[0].$da_parts[1]", 'SHA256', 'v1.5' ),
	'default-alg id_token signature verifies with the client key',
);
my $da_payload = decode_json( _b64url_decode( $da_parts[1] ) );
is( $da_payload->{sub},   'alice',      'default-alg id_token sub correct' );
is( $da_payload->{aud},   'defaultalg', 'default-alg id_token aud correct' );
is( $da_payload->{nonce}, 'danonce1',   'default-alg id_token nonce correct' );

# ── Failed signing leaves no orphan access token ─────────────────────────────
# The ID token is built before the access token is minted: when signing fails
# the exchange is a server_error, the code is consumed, and no access token
# may remain valid in the shared store.

sub _stored_token_count {
	my ($count)
		= $TEST_STORAGE->{backend}{dbh}->selectrow_array(q{SELECT COUNT(*) FROM oidc_store WHERE skey LIKE 'token:%'});
	return $count;
}

$t->reset_session;
$t->get_ok(
	'/authorize?client_id=defaultnokey&redirect_uri=https://defaultnokey.example.com/cb&response_type=code&scope=openid&state=nk1'
)->status_is(302);
$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $nk_code = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');

my $tokens_before = _stored_token_count();
$t->post_ok(
	'/token',
	form => {
		grant_type   => 'authorization_code',
		code         => $nk_code,
		client_id    => 'defaultnokey',
		redirect_uri => 'https://defaultnokey.example.com/cb',
	}
)->status_is(500)->json_is( '/error' => 'server_error', 'default RS256 with no key material fails closed' );
is( _stored_token_count(), $tokens_before, 'failed signing stores no orphan access token' );

# The code was still consumed — replaying it is invalid_grant, not another 500.
$t->post_ok(
	'/token',
	form => {
		grant_type   => 'authorization_code',
		code         => $nk_code,
		client_id    => 'defaultnokey',
		redirect_uri => 'https://defaultnokey.example.com/cb',
	}
)->status_is(400)->json_is( '/error' => 'invalid_grant', 'code from failed exchange is consumed' );

_install_stubs( $t->app );

# ── Authorization: registered scopes are an allow-list ──────────────────────
# A client may only request scopes its registration grants (openid itself is
# always permitted). secretapp registers only openid+profile, so email is
# denied even though the provider supports it.

$t->reset_session;
_install_stubs( $t->app );

$t->get_ok(
	'/authorize?client_id=secretapp&redirect_uri=https://secretapp.example.com/callback&response_type=code&scope=openid+profile+email&state=sc1'
	)
	->status_is(302)
	->header_like( Location => qr/error=invalid_scope/, 'unregistered scope redirects with invalid_scope' )
	->header_like( Location => qr/email/,               'error names the denied scope' )
	->header_like( Location => qr/state=sc1/,           'state preserved in invalid_scope redirect' );

# A client with no registered scopes at all may still authenticate (openid)
# but gets nothing more.
my $client_noscope = FakeEntry->new(
	_dn                          => 'oidcClientId=noscope,ou=oidc,dc=example,dc=com',
	oidcClientId                 => 'noscope',
	oidcRedirectURI              => ['https://noscope.example.com/cb'],
	oidcGrantType                => ['authorization_code'],
	oidcResponseType             => ['code'],
	oidcTokenEndpointAuthMethod  => 'none',
	oidcIdTokenSignedResponseAlg => 'RS256',
	oidcJwks                     => $testapp_jwks_json,
	# deliberately no oidcScope
);

$t->reset_session;
_install_stubs(
	$t->app,
	getOIDCClientEntry => sub {
		my ( $self, $args ) = @_;
		return $client_noscope if ( $args->{clientId} // '' ) eq 'noscope';
		return undef;
	},
);

$t->get_ok(
	'/authorize?client_id=noscope&redirect_uri=https://noscope.example.com/cb&response_type=code&scope=openid&state=sc2'
	)
	->status_is(302)
	->header_like( Location => qr{/sso/login}, 'client without registered scopes can still request openid' );

$t->get_ok(
	'/authorize?client_id=noscope&redirect_uri=https://noscope.example.com/cb&response_type=code&scope=openid+profile&state=sc3'
	)
	->status_is(302)
	->header_like( Location => qr/error=invalid_scope/, 'client without registered scopes is denied profile' );

_install_stubs( $t->app );

# ── Token endpoint: query-string parameters are ignored ─────────────────────
# RFC 6749 3.2: token request parameters belong in the POST body. Parameters
# smuggled in the query string (where they would land in access logs) must not
# be honoured.

$t->reset_session;
$t->get_ok(
	'/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid&state=qs1'
)->status_is(302);
$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $qs_code = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');

# A fully valid token request carried only in the query string is not seen at
# all — grant_type is missing from the body, so this fails before the code is
# even looked up.
$t->post_ok( '/token?grant_type=authorization_code&code='
		. $qs_code
		. '&client_id=testapp&redirect_uri=https%3A%2F%2Ftestapp.example.com%2Fcallback' )
	->status_is(400)
	->json_is( '/error' => 'unsupported_grant_type', 'token request in the query string is ignored' );

# The same request in the body succeeds — proving the query attempt had no
# side effects (the code was not consumed).
$t->post_ok(
	'/token',
	form => {
		grant_type   => 'authorization_code',
		code         => $qs_code,
		client_id    => 'testapp',
		redirect_uri => 'https://testapp.example.com/callback',
	}
)->status_is(200)->json_has( '/access_token', 'same parameters in the body still redeem the code' );

# A client secret supplied via the query string does not authenticate the
# client.
$t->reset_session;
$t->get_ok(
	'/authorize?client_id=secretapp&redirect_uri=https://secretapp.example.com/callback&response_type=code&scope=openid&state=qs2'
)->status_is(302);
$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $qs_code2 = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');

$t->post_ok(
	'/token?client_secret=s3cret',
	form => {
		grant_type   => 'authorization_code',
		code         => $qs_code2,
		client_id    => 'secretapp',
		redirect_uri => 'https://secretapp.example.com/callback',
	}
	)
	->status_is(401)
	->json_is( '/error' => 'invalid_client', 'client_secret in the query string does not authenticate' );

# ── Token endpoint: registered auth method is authoritative ─────────────────

# A client registered for an auth method this provider does not implement
# (private_key_jwt) fails closed instead of skipping authentication.
my $client_jwt_auth = FakeEntry->new(
	_dn                          => 'oidcClientId=jwtapp,ou=oidc,dc=example,dc=com',
	oidcClientId                 => 'jwtapp',
	oidcClientSecret             => 'jwt-s3cret',
	oidcIdTokenSignedResponseAlg => 'HS256',
	oidcRedirectURI              => ['https://jwtapp.example.com/cb'],
	oidcScope                    => ['openid'],
	oidcGrantType                => ['authorization_code'],
	oidcResponseType             => ['code'],
	oidcTokenEndpointAuthMethod  => 'private_key_jwt',
);

# A client registered none is public per its registration: a leftover stored
# secret must not be demanded at the token endpoint.
my $client_none_secret = FakeEntry->new(
	_dn                          => 'oidcClientId=nonesecret,ou=oidc,dc=example,dc=com',
	oidcClientId                 => 'nonesecret',
	oidcClientSecret             => 'leftover-s3cret',
	oidcIdTokenSignedResponseAlg => 'RS256',
	oidcJwks                     => $testapp_jwks_json,
	oidcRedirectURI              => ['https://nonesecret.example.com/cb'],
	oidcScope                    => ['openid'],
	oidcGrantType                => ['authorization_code'],
	oidcResponseType             => ['code'],
	oidcTokenEndpointAuthMethod  => 'none',
);

$t->reset_session;
_install_stubs(
	$t->app,
	getOIDCClientEntry => sub {
		my ( $self, $args ) = @_;
		return $client_jwt_auth    if ( $args->{clientId} // '' ) eq 'jwtapp';
		return $client_none_secret if ( $args->{clientId} // '' ) eq 'nonesecret';
		return undef;
	},
);

$t->get_ok(
	'/authorize?client_id=jwtapp&redirect_uri=https://jwtapp.example.com/cb&response_type=code&scope=openid&state=am1')
	->status_is(302);
$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $am_code = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');

$t->post_ok(
	'/token',
	form => {
		grant_type    => 'authorization_code',
		code          => $am_code,
		client_id     => 'jwtapp',
		client_secret => 'jwt-s3cret',
		redirect_uri  => 'https://jwtapp.example.com/cb',
	}
	)
	->status_is(401)
	->json_is( '/error' => 'invalid_client', 'unimplemented auth method (private_key_jwt) fails closed' );

$t->reset_session;
$t->get_ok(
	'/authorize?client_id=nonesecret&redirect_uri=https://nonesecret.example.com/cb&response_type=code&scope=openid&state=am2'
)->status_is(302);
$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $am_code2 = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');

$t->post_ok(
	'/token',
	form => {
		grant_type   => 'authorization_code',
		code         => $am_code2,
		client_id    => 'nonesecret',
		redirect_uri => 'https://nonesecret.example.com/cb',
	}
	)
	->status_is(200)
	->json_has( '/access_token', 'client registered none is not asked for its leftover stored secret' );

_install_stubs( $t->app );

# ── Authorization: code_challenge_method without code_challenge ─────────────
# Malformed PKCE: naming a method while omitting the challenge must not
# silently issue a code with no PKCE binding.

$t->reset_session;
$t->get_ok(
	'/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid&state=pk1&code_challenge_method=S256'
	)
	->status_is(302)
	->header_like( Location => qr/error=invalid_request/, 'method without challenge redirects with invalid_request' )
	->header_like( Location => qr/state=pk1/,             'state preserved in the error redirect' );

# ── prompt / max_age / response_mode (OIDC Core 3.1.2.1) ────────────────────

$t->reset_session;
_install_stubs( $t->app );

my $authz_base
	= '/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid';

# prompt=none with no authenticated session → login_required error redirect, no UI
$t->get_ok("$authz_base&state=pn1&prompt=none")
	->status_is(302)
	->header_like( Location => qr{^https://testapp\.example\.com/callback}, 'prompt=none errors to the client' )
	->header_like( Location => qr/error=login_required/, 'prompt=none without a session is login_required' )
	->header_like( Location => qr/state=pn1/,            'state preserved on login_required' );

# Unknown prompt value → invalid_request
$t->get_ok("$authz_base&state=pn2&prompt=bogus")
	->status_is(302)
	->header_like( Location => qr/error=invalid_request/, 'unknown prompt value is invalid_request' );

# prompt=none combined with another value → invalid_request
$t->get_ok("$authz_base&state=pn3&prompt=none+login")
	->status_is(302)
	->header_like( Location => qr/error=invalid_request/, 'prompt=none combined with login is invalid_request' );

# prompt=select_account cannot be satisfied → account_selection_required
$t->get_ok("$authz_base&state=pn4&prompt=select_account")
	->status_is(302)
	->header_like( Location => qr/error=account_selection_required/, 'select_account is refused explicitly' );

# response_mode: anything other than query is rejected; query itself proceeds
$t->get_ok("$authz_base&state=rm1&response_mode=fragment")
	->status_is(302)
	->header_like( Location => qr/error=invalid_request/, 'response_mode=fragment is rejected' );
$t->get_ok("$authz_base&state=rm2&response_mode=query")
	->status_is(302)
	->header_like( Location => qr{/sso/login}, 'response_mode=query proceeds normally' );

# Authenticate and consent (openid only) to set up session state for the
# silent-flow tests.
$t->get_ok("$authz_base&state=pn5")->status_is(302);
$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);

# prompt=none now succeeds silently for the already-consented client/scope
$t->get_ok("$authz_base&state=pn6&nonce=pnnonce1&prompt=none")
	->status_is(302)
	->header_like( Location => qr{^https://testapp\.example\.com/callback}, 'silent request returns to the client' )
	->header_unlike( Location => qr/error=/, 'silent request carries no error' );
my $pn_url  = Mojo::URL->new( $t->tx->res->headers->location );
my $pn_code = $pn_url->query->param('code');
ok( $pn_code, 'prompt=none issued a code with no UI' );
is( $pn_url->query->param('state'), 'pn6', 'prompt=none preserves state' );

$t->post_ok(
	'/token',
	form => {
		grant_type   => 'authorization_code',
		code         => $pn_code,
		client_id    => 'testapp',
		redirect_uri => 'https://testapp.example.com/callback',
	}
)->status_is(200)->json_has( '/id_token', 'silently issued code redeems normally' );
my @pn_parts   = split /\./, $t->tx->res->json->{id_token};
my $pn_payload = decode_json( _b64url_decode( $pn_parts[1] ) );
is( $pn_payload->{nonce}, 'pnnonce1', 'silent flow id_token carries the request nonce' );

# prompt=none for a scope this session has not consented to → consent_required
$t->get_ok(
	'/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid+profile&state=pn7&prompt=none'
	)
	->status_is(302)
	->header_like( Location => qr/error=consent_required/, 'silent request for unconsented scope is consent_required' );

# prompt=login forces re-authentication despite the existing session. (A
# login within the same second as the request is tolerated as "fresh", so put
# the session's auth_time strictly in the past first.)
sleep 1;
$t->get_ok("$authz_base&state=pl1&prompt=login")
	->status_is(302)
	->header_like( Location => qr{/sso/login}, 'prompt=login goes back to login despite the session' );
my $pl_rid = Mojo::URL->new( $t->tx->res->headers->location )->query->param('rid');
ok( $pl_rid, 'prompt=login flow carries a request id' );

# ...and the consent screen cannot be reached directly for that request
$t->get_ok("/sso/consent?rid=$pl_rid")
	->status_is(302)
	->header_like( Location => qr{/sso/login}, 'consent for a prompt=login request bounces back to login' );

# A fresh login satisfies it, and — since this session already consented to
# this client/scope — the flow completes without re-prompting for consent.
$t->post_ok( "/sso/login?rid=$pl_rid", form => { user => 'alice', pass => 'correct' } )
	->status_is(302)
	->header_like( Location => qr{^https://testapp\.example\.com/callback}, 'prompt=login flow completes' )
	->header_like( Location => qr/state=pl1/,                               'prompt=login flow returns its state' );

# max_age=0 (equivalent to prompt=login) also forces re-authentication
sleep 1;    # make the session's auth_time strictly older than the request
$t->get_ok("$authz_base&state=ma1&max_age=0")
	->status_is(302)
	->header_like( Location => qr{/sso/login}, 'max_age=0 forces re-authentication' );

# A client registered with oidcDefaultMaxAge=0 gets the same treatment with no
# max_age request parameter at all.
my $client_maxage = FakeEntry->new(
	_dn                          => 'oidcClientId=maxageapp,ou=oidc,dc=example,dc=com',
	oidcClientId                 => 'maxageapp',
	oidcRedirectURI              => ['https://maxageapp.example.com/cb'],
	oidcScope                    => ['openid'],
	oidcGrantType                => ['authorization_code'],
	oidcResponseType             => ['code'],
	oidcTokenEndpointAuthMethod  => 'none',
	oidcIdTokenSignedResponseAlg => 'RS256',
	oidcJwks                     => $testapp_jwks_json,
	oidcDefaultMaxAge            => 0,
);
_install_stubs(
	$t->app,
	getOIDCClientEntry => sub {
		my ( $self, $args ) = @_;
		return $client_maxage if ( $args->{clientId} // '' ) eq 'maxageapp';
		return $client_public if ( $args->{clientId} // '' ) eq 'testapp';
		return undef;
	},
);
$t->get_ok(
	'/authorize?client_id=maxageapp&redirect_uri=https://maxageapp.example.com/cb&response_type=code&scope=openid&state=ma2'
	)
	->status_is(302)
	->header_like( Location => qr{/sso/login}, 'registered oidcDefaultMaxAge=0 forces re-authentication' );

_install_stubs( $t->app );

# ── Concurrent authorization requests do not clobber each other ─────────────
# Two "tabs" start flows before either finishes; each completes against its
# own request id with its own state and nonce.

$t->reset_session;
_install_stubs( $t->app );

$t->get_ok("$authz_base&state=tabA&nonce=nonceA")->status_is(302);
my $rid_a = Mojo::URL->new( $t->tx->res->headers->location )->query->param('rid');
$t->get_ok("$authz_base&state=tabB&nonce=nonceB")->status_is(302);
my $rid_b = Mojo::URL->new( $t->tx->res->headers->location )->query->param('rid');
ok( $rid_a && $rid_b && $rid_a ne $rid_b, 'each authorize request gets its own request id' );

$t->post_ok( "/sso/login?rid=$rid_a", form => { user => 'alice', pass => 'correct' } )
	->status_is(302)
	->header_like( Location => qr/rid=\Q$rid_a\E/, 'login keeps working on tab A\'s request' );

# Consenting on tab A completes tab A's request...
$t->post_ok( "/sso/consent?rid=$rid_a", form => { decision => 'allow' } )->status_is(302);
my $url_a = Mojo::URL->new( $t->tx->res->headers->location );
is( $url_a->query->param('state'), 'tabA', 'tab A completion carries tab A\'s state' );
my $code_a = $url_a->query->param('code');

# ...while tab B's request is still pending and completes independently
$t->get_ok("/sso/consent?rid=$rid_b")->status_is(200)->content_like( qr/Test Application/, 'tab B still pending' );
$t->post_ok( "/sso/consent?rid=$rid_b", form => { decision => 'allow' } )->status_is(302);
my $url_b = Mojo::URL->new( $t->tx->res->headers->location );
is( $url_b->query->param('state'), 'tabB', 'tab B completion carries tab B\'s state' );
my $code_b = $url_b->query->param('code');

for my $pair ( [ $code_a, 'nonceA' ], [ $code_b, 'nonceB' ] ) {
	my ( $code, $nonce ) = @$pair;
	$t->post_ok(
		'/token',
		form => {
			grant_type   => 'authorization_code',
			code         => $code,
			client_id    => 'testapp',
			redirect_uri => 'https://testapp.example.com/callback',
		}
	)->status_is(200);
	my @parts = split /\./, $t->tx->res->json->{id_token};
	is( decode_json( _b64url_decode( $parts[1] ) )->{nonce}, $nonce, "code for $nonce maps to its own request" );
} ## end for my $pair ( [ $code_a, 'nonceA' ], [ $code_b...])

# A settled request cannot be revisited (back button)
$t->get_ok("/sso/consent?rid=$rid_a")
	->status_is(200)
	->content_like( qr/No Authorization Request/, 'a completed request id is gone' );

# ── Key rotation: sign with the newest private key, verify old hints by kid ──
# A rotated JWKS holds the previous key as a public-only entry alongside the
# new private key. Signing must pick the private key regardless of position;
# hint verification must select the right key by kid.

my $rot_old_rsa = Crypt::PK::RSA->new;
$rot_old_rsa->generate_key( 256, 65537 );
my $rot_old_pub = decode_json( $rot_old_rsa->export_key_jwk('public') );
$rot_old_pub->{kid} = 'rot-old';
$rot_old_pub->{use} = 'sig';
$rot_old_pub->{alg} = 'RS256';

my $rot_new_rsa = Crypt::PK::RSA->new;
$rot_new_rsa->generate_key( 256, 65537 );
my $rot_new_priv = decode_json( $rot_new_rsa->export_key_jwk('private') );
$rot_new_priv->{kid} = 'rot-new';
$rot_new_priv->{use} = 'sig';
$rot_new_priv->{alg} = 'RS256';

# Public-only key first, to prove signing skips keys without private material.
my $rot_jwks_json = Mojo::JSON::encode_json( { keys => [ $rot_old_pub, $rot_new_priv ] } );

my $client_rot = FakeEntry->new(
	_dn                          => 'oidcClientId=rotapp,ou=oidc,dc=example,dc=com',
	oidcClientId                 => 'rotapp',
	oidcRedirectURI              => ['https://rotapp.example.com/cb'],
	oidcPostLogoutRedirectURI    => ['https://rotapp.example.com/loggedout'],
	oidcScope                    => ['openid'],
	oidcGrantType                => ['authorization_code'],
	oidcResponseType             => ['code'],
	oidcTokenEndpointAuthMethod  => 'none',
	oidcIdTokenSignedResponseAlg => 'RS256',
	oidcJwks                     => $rot_jwks_json,
);

$t->reset_session;
_install_stubs(
	$t->app,
	getOIDCClientEntry => sub {
		my ( $self, $args ) = @_;
		return $client_rot if ( $args->{clientId} // '' ) eq 'rotapp';
		return undef;
	},
);

$t->get_ok(
	'/authorize?client_id=rotapp&redirect_uri=https://rotapp.example.com/cb&response_type=code&scope=openid&state=rot1')
	->status_is(302);
$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $rot_code = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');

$t->post_ok(
	'/token',
	form => {
		grant_type   => 'authorization_code',
		code         => $rot_code,
		client_id    => 'rotapp',
		redirect_uri => 'https://rotapp.example.com/cb',
	}
)->status_is(200)->json_has('/id_token');

my @rot_parts  = split /\./, $t->tx->res->json->{id_token};
my $rot_header = decode_json( _b64url_decode( $rot_parts[0] ) );
is( $rot_header->{kid}, 'rot-new', 'signing picks the private key, not the retained public-only key' );
ok(
	$rot_new_rsa->verify_message(
		_b64url_decode( $rot_parts[2] ), "$rot_parts[0].$rot_parts[1]", 'SHA256', 'v1.5'
	),
	'rotated-set id_token verifies with the new key',
);

# An id_token_hint signed with the retained OLD key (kid rot-old) still
# verifies at logout, so RP-initiated logout survives a rotation.
my $old_hint_header  = _b64url_encode('{"alg":"RS256","typ":"JWT","kid":"rot-old"}');
my $old_hint_payload = _b64url_encode(
	Mojo::JSON::encode_json(
		{ iss => 'http://localhost', aud => 'rotapp', sub => 'alice', iat => time() - 10, exp => time() + 3600 }
	)
);
my $old_hint_sig
	= _b64url_encode( $rot_old_rsa->sign_message( "$old_hint_header.$old_hint_payload", 'SHA256', 'v1.5' ) );
my $old_hint = "$old_hint_header.$old_hint_payload.$old_hint_sig";

$t->get_ok(
	"/sso/logout?id_token_hint=$old_hint&post_logout_redirect_uri=https://rotapp.example.com/loggedout&state=rot9")
	->status_is(302)
	->header_is(
		Location => 'https://rotapp.example.com/loggedout?state=rot9',
		'hint signed with the rotated-out key still verifies (selected by kid)'
	);

_install_stubs( $t->app );

# ── End-session endpoint accepts a cross-site POST with a verified hint ─────
# /sso/logout is exempt from the CSRF middleware so relying parties can POST
# to it (OIDC RP-Initiated Logout); the id_token_hint itself authenticates the
# request. A cross-site POST without a verified hint cannot force a logout —
# it is answered with the confirmation page instead.

{
	# No referer/CSRF-token UA hooks: these requests have the shape of a
	# cross-site (RP-initiated) POST.
	my $t_x = Test::Mojo->new('App::Nisaba::WebSSO');
	_install_stubs(
		$t_x->app,
		getOIDCClientEntry => sub {
			my ( $self, $args ) = @_;
			return $client_rs256 if ( $args->{clientId} // '' ) eq 'rs256app';
			return undef;
		},
	);

	$t_x->post_ok(
		'/sso/logout',
		form => {
			id_token_hint            => $lo_id_token,
			post_logout_redirect_uri => 'https://rs256app.example.com/loggedout',
			state                    => 'xpost1',
		}
	)->status_is(302)->header_is(
		Location => 'https://rs256app.example.com/loggedout?state=xpost1',
		'cross-site POST with a verified hint performs RP-initiated logout'
	);

	$t_x->post_ok(
		'/sso/logout',
		form => {
			client_id                => 'rs256app',
			post_logout_redirect_uri => 'https://rs256app.example.com/loggedout',
		}
		)
		->status_is(200)
		->content_like( qr/Sign Out/, 'cross-site POST without a hint gets the confirmation page, not a logout' );
}

# ── ssoIdTokenLifetime: ID token validity separate from the access token ────

$t->reset_session;
_install_stubs( $t->app );
$t->app->helper(
	pt => sub {
		my $fake_pt = bless {
			ini => {
				'' => {
					ssoIssuer               => 'http://localhost',
					ssoTokenLifetime        => 1800,
					ssoIdTokenLifetime      => 120,
					ssoCodeLifetime         => 600,
					passkeyRpId             => '',
					passkeyUserVerification => 'preferred',
				},
			},
			},
			'FakePT';
		return $fake_pt;
	}
);

$t->get_ok(
	'/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid&state=idtl1'
)->status_is(302);
$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $idtl_code = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');

$t->post_ok(
	'/token',
	form => {
		grant_type   => 'authorization_code',
		code         => $idtl_code,
		client_id    => 'testapp',
		redirect_uri => 'https://testapp.example.com/callback',
	}
)->status_is(200)->json_is( '/expires_in' => 1800, 'access token keeps ssoTokenLifetime' );

my @idtl_parts   = split /\./, $t->tx->res->json->{id_token};
my $idtl_payload = decode_json( _b64url_decode( $idtl_parts[1] ) );
is( $idtl_payload->{exp} - $idtl_payload->{iat}, 120, 'id_token validity uses ssoIdTokenLifetime' );

_install_stubs( $t->app );

# ── issuer_config_warnings ───────────────────────────────────────────────────

{
	my @unset = App::Nisaba::WebSSO::issuer_config_warnings( undef, 'production' );
	is( scalar @unset, 1, 'unset issuer warns in production mode' );
	like( $unset[0], qr/Host header/, 'unset-issuer warning explains the Host-header fallback' );

	is( scalar App::Nisaba::WebSSO::issuer_config_warnings( undef, 'development' ),
		0, 'unset issuer is quiet in development mode' );
	is( scalar App::Nisaba::WebSSO::issuer_config_warnings( 'https://sso.example.com', 'production' ),
		0, 'a clean issuer produces no warnings' );

	my @path = App::Nisaba::WebSSO::issuer_config_warnings( 'https://sso.example.com/sso', 'production' );
	is( scalar @path, 1, 'issuer with a path component warns' );
	like( $path[0], qr/path component/, 'path-component warning names the problem' );

	my @slash = App::Nisaba::WebSSO::issuer_config_warnings( 'https://sso.example.com/', 'production' );
	is( scalar @slash, 1, 'issuer with a trailing slash warns' );
	like( $slash[0], qr/trailing slash/, 'trailing-slash warning names the problem' );

	my @scheme = App::Nisaba::WebSSO::issuer_config_warnings( 'ldap://sso.example.com', 'production' );
	is( scalar @scheme, 1, 'non-http(s) issuer warns' );
}

# ── Refresh tokens (RFC 6749 Section 6, OIDC Core 12) ───────────────────────
# Issued only to clients whose registration includes the refresh_token grant,
# rotated on every use.

$t->reset_session;
_install_stubs( $t->app );

# Discovery advertises the new capabilities.
$t->get_ok('/.well-known/openid-configuration')
	->status_is(200)
	->json_is( '/revocation_endpoint'     => 'http://localhost/revoke',     'discovery advertises revocation' )
	->json_is( '/introspection_endpoint'  => 'http://localhost/introspect', 'discovery advertises introspection' )
	->json_is( '/grant_types_supported/1' => 'refresh_token', 'discovery advertises the refresh_token grant' );

my $sec_basic = 'Basic ' . MIME::Base64::encode_base64( 'secretapp:s3cret', '' );

my $get_secretapp_grant = sub {
	my ($state) = @_;
	$t->reset_session;
	$t->get_ok( '/authorize?client_id=secretapp&redirect_uri=https://secretapp.example.com/callback'
			. "&response_type=code&scope=openid+profile&state=$state&nonce=rtnonce-$state" )->status_is(302);
	$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
	$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
	my $code = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');
	$t->post_ok(
		'/token',
		{ Authorization => $sec_basic },
		form => {
			grant_type   => 'authorization_code',
			code         => $code,
			redirect_uri => 'https://secretapp.example.com/callback',
		}
	)->status_is(200);
	return $t->tx->res->json;
}; ## end $get_secretapp_grant = sub

my $grant1 = $get_secretapp_grant->('rt1');
ok( $grant1->{refresh_token}, 'refresh_token issued to a client registered for the grant' );
my $orig_id_payload = decode_json( _b64url_decode( ( split /\./, $grant1->{id_token} )[1] ) );

# Redeem the refresh token: fresh access token + rotated refresh token.
$t->post_ok(
	'/token',
	{ Authorization => $sec_basic },
	form => {
		grant_type    => 'refresh_token',
		refresh_token => $grant1->{refresh_token},
	}
	)
	->status_is(200)
	->json_has( '/access_token', 'refresh grant returns a new access token' )
	->json_is( '/scope' => 'openid profile', 'refresh grant keeps the original scope by default' )
	->json_has( '/refresh_token', 'refresh grant returns a rotated refresh token' );
my $refreshed = $t->tx->res->json;
isnt( $refreshed->{refresh_token}, $grant1->{refresh_token}, 'refresh token is rotated on use' );
isnt( $refreshed->{access_token},  $grant1->{access_token},  'a fresh access token is minted' );

my $ref_id_payload = decode_json( _b64url_decode( ( split /\./, $refreshed->{id_token} )[1] ) );
is( $ref_id_payload->{sub}, 'alice', 'refreshed id_token keeps the subject' );
ok( !exists $ref_id_payload->{nonce}, 'refreshed id_token carries no nonce (OIDC Core 12.2)' );
is( $ref_id_payload->{auth_time}, $orig_id_payload->{auth_time},
	'refreshed id_token preserves the original auth_time' );

# The new access token works at UserInfo.
$t->get_ok( '/userinfo', { Authorization => "Bearer $refreshed->{access_token}" } )
	->status_is(200)
	->json_is( '/sub' => 'alice', 'refreshed access token resolves at UserInfo' );

# The rotated-out refresh token is dead.
$t->post_ok(
	'/token',
	{ Authorization => $sec_basic },
	form => {
		grant_type    => 'refresh_token',
		refresh_token => $grant1->{refresh_token},
	}
)->status_is(400)->json_is( '/error' => 'invalid_grant', 'replaying a rotated-out refresh token fails' );

# Scope narrowing: a subset is allowed, an expansion is refused.
$t->post_ok(
	'/token',
	{ Authorization => $sec_basic },
	form => {
		grant_type    => 'refresh_token',
		refresh_token => $refreshed->{refresh_token},
		scope         => 'openid',
	}
)->status_is(200)->json_is( '/scope' => 'openid', 'refresh grant may narrow the scope' );
my $narrowed = $t->tx->res->json;

$t->post_ok(
	'/token',
	{ Authorization => $sec_basic },
	form => {
		grant_type    => 'refresh_token',
		refresh_token => $narrowed->{refresh_token},
		scope         => 'openid profile email',
	}
)->status_is(400)->json_is( '/error' => 'invalid_scope', 'refresh grant cannot expand beyond the original grant' );

# A client not registered for the grant gets neither a refresh token...
$t->reset_session;
$t->get_ok(
	'/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid&state=nort1'
)->status_is(302);
$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $nort_code = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');
$t->post_ok(
	'/token',
	form => {
		grant_type   => 'authorization_code',
		code         => $nort_code,
		client_id    => 'testapp',
		redirect_uri => 'https://testapp.example.com/callback',
	}
)->status_is(200)->json_hasnt( '/refresh_token', 'no refresh token for a client without the refresh_token grant' );
my $nort_access = $t->tx->res->json->{access_token};

# ...nor use of the grant type.
$t->post_ok(
	'/token',
	form => {
		grant_type    => 'refresh_token',
		refresh_token => 'whatever',
		client_id     => 'testapp',
	}
	)
	->status_is(400)
	->json_is( '/error' => 'unauthorized_client', 'refresh grant refused for a client not registered for it' );

# ── Token revocation (RFC 7009) ──────────────────────────────────────────────

my $grant2 = $get_secretapp_grant->('rev1');

# Revoking the access token kills it at UserInfo.
$t->post_ok( '/revoke', { Authorization => $sec_basic }, form => { token => $grant2->{access_token} } )
	->status_is( 200, 'revocation of an access token answers 200' );
$t->get_ok( '/userinfo', { Authorization => "Bearer $grant2->{access_token}" } )
	->status_is( 401, 'revoked access token no longer resolves at UserInfo' );

# Revoking the refresh token kills the refresh grant.
$t->post_ok( '/revoke', { Authorization => $sec_basic }, form => { token => $grant2->{refresh_token} } )
	->status_is( 200, 'revocation of a refresh token answers 200' );
$t->post_ok(
	'/token',
	{ Authorization => $sec_basic },
	form => {
		grant_type    => 'refresh_token',
		refresh_token => $grant2->{refresh_token},
	}
)->status_is(400)->json_is( '/error' => 'invalid_grant', 'revoked refresh token cannot be redeemed' );

# A foreign token is answered 200 (nothing revealed) but NOT revoked.
$t->post_ok( '/revoke', { Authorization => $sec_basic }, form => { token => $nort_access } )
	->status_is( 200, 'revoking a foreign token still answers 200' );
$t->get_ok( '/userinfo', { Authorization => "Bearer $nort_access" } )
	->status_is( 200, 'a foreign token is not actually revoked' );

# Revocation requires client authentication.
my $rev_bad_basic = 'Basic ' . MIME::Base64::encode_base64( 'secretapp:wrong', '' );
$t->post_ok( '/revoke', { Authorization => $rev_bad_basic }, form => { token => $nort_access } )
	->status_is(401)
	->json_is( '/error' => 'invalid_client', 'revocation requires valid client credentials' );

# ── Revocation cascade (RFC 7009 Section 2.1) ────────────────────────────────
# Revoking a refresh token also invalidates the access tokens minted from the
# same grant — every generation of them, at UserInfo and introspection alike.

my $grant_cas = $get_secretapp_grant->('cas1');
$t->post_ok(
	'/token',
	{ Authorization => $sec_basic },
	form => {
		grant_type    => 'refresh_token',
		refresh_token => $grant_cas->{refresh_token},
	}
)->status_is(200);
my $grant_cas2 = $t->tx->res->json;

$t->post_ok( '/revoke', { Authorization => $sec_basic }, form => { token => $grant_cas2->{refresh_token} } )
	->status_is( 200, 'cascade: refresh token revoked' );
$t->get_ok( '/userinfo', { Authorization => "Bearer $grant_cas2->{access_token}" } )
	->status_is( 401, 'cascade: access token from the revoked grant dies at UserInfo' );
$t->get_ok( '/userinfo', { Authorization => "Bearer $grant_cas->{access_token}" } )
	->status_is( 401, 'cascade: an earlier access token from the same grant dies too' );
$t->post_ok( '/introspect', { Authorization => $sec_basic }, form => { token => $grant_cas2->{access_token} } )
	->status_is(200)
	->json_is( '/active' => Mojo::JSON->false, 'cascade: access token from the revoked grant introspects inactive' );

# ── Refresh-token lifetime is absolute (no sliding via rotation) ─────────────
# A rotated successor carries the chain's original issue time; once the chain
# is older than ssoRefreshTokenLifetime, refreshing fails even though the
# presented token itself is younger.

my $grant_abs = $get_secretapp_grant->('abs1');
{
	my $aged = $TEST_STORAGE->get( 'refresh', $grant_abs->{refresh_token} );
	ok( defined $aged->{grant_issued_at}, 'refresh token records the chain start time' );
	$aged->{grant_issued_at} = time() - 2592001;    # past the 30-day default
	$TEST_STORAGE->put( 'refresh', $grant_abs->{refresh_token}, $aged, 3600 );
}
$t->post_ok(
	'/token',
	{ Authorization => $sec_basic },
	form => {
		grant_type    => 'refresh_token',
		refresh_token => $grant_abs->{refresh_token},
	}
	)
	->status_is(400)
	->json_is( '/error' => 'invalid_grant', 'a refresh chain older than the absolute lifetime is refused' );

# ── Client authentication: one method only (RFC 6749 Section 2.3) ────────────

$t->post_ok(
	'/token',
	{ Authorization => $sec_basic },
	form => {
		grant_type    => 'authorization_code',
		code          => 'whatever',
		client_secret => 's3cret',
	}
	)
	->status_is(400)
	->json_is( '/error' => 'invalid_request', 'Basic header plus body secret is rejected as conflicting' );

$t->post_ok(
	'/token',
	{ Authorization => $sec_basic },
	form => {
		grant_type => 'authorization_code',
		code       => 'whatever',
		client_id  => 'testapp',
	}
	)
	->status_is(400)
	->json_is( '/error' => 'invalid_request', 'body client_id conflicting with the Basic header is rejected' );

# ── Token introspection (RFC 7662) ───────────────────────────────────────────

my $grant3 = $get_secretapp_grant->('intro1');

$t->post_ok( '/introspect', { Authorization => $sec_basic }, form => { token => $grant3->{access_token} } )
	->status_is(200)
	->json_is( '/active'     => Mojo::JSON->true, 'own access token introspects as active' )
	->json_is( '/sub'        => 'alice' )
	->json_is( '/username'   => 'alice' )
	->json_is( '/client_id'  => 'secretapp' )
	->json_is( '/scope'      => 'openid profile' )
	->json_is( '/token_type' => 'Bearer' )
	->json_has('/exp')
	->json_has('/iat')
	->json_is( '/iss' => 'http://localhost', 'introspection response names the issuer' );

$t->post_ok( '/introspect', { Authorization => $sec_basic }, form => { token => $grant3->{refresh_token} } )
	->status_is(200)
	->json_is( '/active'     => Mojo::JSON->true, 'own refresh token introspects as active' )
	->json_is( '/token_type' => 'refresh_token' );

# Foreign and unknown tokens are simply inactive — no metadata leaks.
$t->post_ok( '/introspect', { Authorization => $sec_basic }, form => { token => $nort_access } )
	->status_is(200)
	->json_is( '/active' => Mojo::JSON->false, 'a foreign token introspects as inactive' )
	->json_hasnt( '/sub', 'no claims leak for a foreign token' );
$t->post_ok( '/introspect', { Authorization => $sec_basic }, form => { token => 'no-such-token' } )
	->status_is(200)
	->json_is( '/active' => Mojo::JSON->false, 'an unknown token introspects as inactive' );

# A public client cannot introspect at all (token-validity oracle).
$t->post_ok( '/introspect', form => { client_id => 'testapp', token => $nort_access } )
	->status_is(401)
	->json_is( '/error' => 'invalid_client', 'introspection is refused for public clients' );

# A revoked token introspects as inactive.
$t->post_ok( '/introspect', { Authorization => $sec_basic }, form => { token => $grant2->{access_token} } )
	->status_is(200)
	->json_is( '/active' => Mojo::JSON->false, 'a revoked token introspects as inactive' );

# ── Durable consent ("remember this decision") ───────────────────────────────
# A remembered grant survives the browser session: after a fresh login in a
# brand-new session, login completes the flow with no consent screen, and
# prompt=none succeeds without any interactive consent in that session.

my $client_remember = FakeEntry->new(
	_dn                          => 'oidcClientId=rememberapp,ou=oidc,dc=example,dc=com',
	oidcClientId                 => 'rememberapp',
	oidcClientName               => 'Remember App',
	oidcRedirectURI              => ['https://rememberapp.example.com/cb'],
	oidcScope                    => [ 'openid', 'profile' ],
	oidcGrantType                => ['authorization_code'],
	oidcResponseType             => ['code'],
	oidcTokenEndpointAuthMethod  => 'none',
	oidcIdTokenSignedResponseAlg => 'RS256',
	oidcJwks                     => $testapp_jwks_json,
);

$t->reset_session;
_install_stubs(
	$t->app,
	getOIDCClientEntry => sub {
		my ( $self, $args ) = @_;
		return $client_remember if ( $args->{clientId} // '' ) eq 'rememberapp';
		return $client_public   if ( $args->{clientId} // '' ) eq 'testapp';
		return undef;
	},
);

my $remember_authz = '/authorize?client_id=rememberapp&redirect_uri=https://rememberapp.example.com/cb'
	. '&response_type=code&scope=openid+profile';

# Session 1: consent interactively, ticking "remember this decision".
$t->get_ok("$remember_authz&state=rem1")->status_is(302);
$t->post_ok( '/sso/login', form => { user => 'alice', pass => 'correct' } )->status_is(302);
$t->get_ok( $t->tx->res->headers->location )
	->status_is(200)
	->content_like( qr/Remember this decision/, 'consent page offers to remember the decision' );
$t->post_ok( '/sso/consent', form => { decision => 'allow', remember => 1 } )
	->status_is(302)
	->header_like( Location => qr{^https://rememberapp\.example\.com/cb}, 'remembered consent flow completes' );

# Session 2 (fresh browser session): login completes the flow directly.
$t->reset_session;
$t->get_ok("$remember_authz&state=rem2")
	->status_is(302)
	->header_like( Location => qr{/sso/login}, 'new session still requires authentication' );
$t->post_ok( '/sso/login', form => { user => 'alice', pass => 'correct' } )->status_is(302)->header_like(
	Location => qr{^https://rememberapp\.example\.com/cb},
	'durable consent skips the consent screen after a fresh login'
)->header_like( Location => qr/state=rem2/, 'skipped flow returns its state' );

# prompt=none succeeds in this session even though no interactive consent
# happened here — the durable grant covers it.
$t->get_ok("$remember_authz&state=rem3&prompt=none")
	->status_is(302)
	->header_like( Location => qr{^https://rememberapp\.example\.com/cb}, 'silent request returns to the client' )
	->header_unlike( Location => qr/error=/, 'durable consent satisfies prompt=none across sessions' );

# prompt=consent forces the consent screen despite the durable grant.
$t->get_ok("$remember_authz&state=rem4&prompt=consent")
	->status_is(302)
	->header_like( Location => qr{/sso/consent}, 'prompt=consent forces the consent screen' );

# A consent that was NOT remembered does not survive the session: testapp was
# consented (without remember) many times above, yet a new session still gets
# the consent screen.
$t->reset_session;
$t->get_ok(
	'/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid&state=rem5'
)->status_is(302);
$t->post_ok( '/sso/login', form => { user => 'alice', pass => 'correct' } )
	->status_is(302)
	->header_like( Location => qr{/sso/consent}, 'unremembered consent does not persist across sessions' );

_install_stubs( $t->app );

# ── Token endpoint: cross-client code redemption is refused ─────────────────
# A correctly authenticated client cannot redeem an authorization code issued
# to a different client (code substitution).

$t->reset_session;
_install_stubs( $t->app );

$t->get_ok(
	'/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid&state=xc1'
)->status_is(302);
$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $xc_code = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');

$t->post_ok(
	'/token',
	{ Authorization => $sec_basic },
	form => {
		grant_type   => 'authorization_code',
		code         => $xc_code,
		redirect_uri => 'https://testapp.example.com/callback',
	}
	)
	->status_is(400)
	->json_is( '/error' => 'invalid_grant', q{authenticated client cannot redeem another client's code} )
	->json_like( '/error_description' => qr/client_id mismatch/, 'mismatch is reported as such' );

# ── Token endpoint: unset auth method (legacy default) ──────────────────────
# A client with no registered oidcTokenEndpointAuthMethod falls back to the
# legacy rule: with a stored secret it must present it (either transport);
# without one it is treated as public.

my $client_legacy_secret = FakeEntry->new(
	_dn                          => 'oidcClientId=legacysecret,ou=oidc,dc=example,dc=com',
	oidcClientId                 => 'legacysecret',
	oidcClientSecret             => 'legacy-s3cret',
	oidcIdTokenSignedResponseAlg => 'HS256',
	oidcRedirectURI              => ['https://legacysecret.example.com/cb'],
	oidcScope                    => ['openid'],
	oidcGrantType                => ['authorization_code'],
	oidcResponseType             => ['code'],
	# deliberately no oidcTokenEndpointAuthMethod
);
my $client_legacy_public = FakeEntry->new(
	_dn                          => 'oidcClientId=legacypublic,ou=oidc,dc=example,dc=com',
	oidcClientId                 => 'legacypublic',
	oidcIdTokenSignedResponseAlg => 'RS256',
	oidcJwks                     => $testapp_jwks_json,
	oidcRedirectURI              => ['https://legacypublic.example.com/cb'],
	oidcScope                    => ['openid'],
	oidcGrantType                => ['authorization_code'],
	oidcResponseType             => ['code'],
	# deliberately no oidcTokenEndpointAuthMethod and no secret
);

_install_stubs(
	$t->app,
	getOIDCClientEntry => sub {
		my ( $self, $args ) = @_;
		return $client_legacy_secret if ( $args->{clientId} // '' ) eq 'legacysecret';
		return $client_legacy_public if ( $args->{clientId} // '' ) eq 'legacypublic';
		return undef;
	},
);

my $get_legacy_code = sub {
	my ( $client_id, $state ) = @_;
	$t->reset_session;
	$t->get_ok( "/authorize?client_id=$client_id&redirect_uri=https://$client_id.example.com/cb"
			. "&response_type=code&scope=openid&state=$state" )->status_is(302);
	$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
	$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
	return Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');
};

# With a stored secret: either transport authenticates...
my $leg_code = $get_legacy_code->( 'legacysecret', 'leg1' );
$t->post_ok(
	'/token',
	form => {
		grant_type    => 'authorization_code',
		code          => $leg_code,
		client_id     => 'legacysecret',
		client_secret => 'legacy-s3cret',
		redirect_uri  => 'https://legacysecret.example.com/cb',
	}
)->status_is(200)->json_has( '/access_token', 'unset method: secret accepted via post transport' );

my $leg_code2 = $get_legacy_code->( 'legacysecret', 'leg2' );
my $leg_basic = 'Basic ' . MIME::Base64::encode_base64( 'legacysecret:legacy-s3cret', '' );
$t->post_ok(
	'/token',
	{ Authorization => $leg_basic },
	form => {
		grant_type   => 'authorization_code',
		code         => $leg_code2,
		redirect_uri => 'https://legacysecret.example.com/cb',
	}
)->status_is(200)->json_has( '/access_token', 'unset method: secret accepted via basic transport' );

# ...and the secret is still mandatory.
my $leg_code3 = $get_legacy_code->( 'legacysecret', 'leg3' );
$t->post_ok(
	'/token',
	form => {
		grant_type   => 'authorization_code',
		code         => $leg_code3,
		client_id    => 'legacysecret',
		redirect_uri => 'https://legacysecret.example.com/cb',
	}
)->status_is(401)->json_is( '/error' => 'invalid_client', 'unset method: missing secret is refused' );

# Without a stored secret the client is treated as public. Token responses
# also carry the RFC 6749 5.1 cache headers.
my $leg_code4 = $get_legacy_code->( 'legacypublic', 'leg4' );
$t->post_ok(
	'/token',
	form => {
		grant_type   => 'authorization_code',
		code         => $leg_code4,
		client_id    => 'legacypublic',
		redirect_uri => 'https://legacypublic.example.com/cb',
	}
	)
	->status_is(200)
	->json_has( '/access_token', 'unset method without a secret is treated as public' )
	->header_is( 'Cache-Control' => 'no-store', 'token response is marked no-store' )
	->header_is( 'Pragma'        => 'no-cache', 'token response is marked no-cache' );

_install_stubs( $t->app );

# ── Token endpoint: Basic credentials are form-urlencoded (RFC 6749 2.3.1) ──
# A secret with reserved characters must round-trip through the required
# URL-encoding in the Authorization header.

my $enc_secret = 'p@ss word%100:x';
my $client_enc = FakeEntry->new(
	_dn                          => 'oidcClientId=encapp,ou=oidc,dc=example,dc=com',
	oidcClientId                 => 'encapp',
	oidcClientSecret             => $enc_secret,
	oidcIdTokenSignedResponseAlg => 'HS256',
	oidcRedirectURI              => ['https://encapp.example.com/cb'],
	oidcScope                    => ['openid'],
	oidcGrantType                => ['authorization_code'],
	oidcResponseType             => ['code'],
	oidcTokenEndpointAuthMethod  => 'client_secret_basic',
);

$t->reset_session;
_install_stubs(
	$t->app,
	getOIDCClientEntry => sub {
		my ( $self, $args ) = @_;
		return $client_enc if ( $args->{clientId} // '' ) eq 'encapp';
		return undef;
	},
);

$t->get_ok(
	'/authorize?client_id=encapp&redirect_uri=https://encapp.example.com/cb&response_type=code&scope=openid&state=enc1')
	->status_is(302);
$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $enc_code = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');

my $enc_basic = 'Basic '
	. MIME::Base64::encode_base64( Mojo::Util::url_escape('encapp') . ':' . Mojo::Util::url_escape($enc_secret), '' );
$t->post_ok(
	'/token',
	{ Authorization => $enc_basic },
	form => {
		grant_type   => 'authorization_code',
		code         => $enc_code,
		redirect_uri => 'https://encapp.example.com/cb',
	}
	)
	->status_is(200)
	->json_has( '/access_token', 'URL-encoded Basic credentials with reserved characters authenticate' );

_install_stubs( $t->app );

# ── Refresh grant edge cases ─────────────────────────────────────────────────

# Missing refresh_token parameter.
$t->post_ok( '/token', { Authorization => $sec_basic }, form => { grant_type => 'refresh_token' } )
	->status_is(400)
	->json_is( '/error' => 'invalid_request', 'refresh grant without a token is invalid_request' );

# A different refresh-enabled client cannot redeem another client's token.
my $client_rt2 = FakeEntry->new(
	_dn                          => 'oidcClientId=rt2app,ou=oidc,dc=example,dc=com',
	oidcClientId                 => 'rt2app',
	oidcIdTokenSignedResponseAlg => 'RS256',
	oidcJwks                     => $testapp_jwks_json,
	oidcRedirectURI              => ['https://rt2app.example.com/cb'],
	oidcScope                    => ['openid'],
	oidcGrantType                => [ 'authorization_code', 'refresh_token' ],
	oidcResponseType             => ['code'],
	oidcTokenEndpointAuthMethod  => 'none',
);

_install_stubs(
	$t->app,
	getOIDCClientEntry => sub {
		my ( $self, $args ) = @_;
		return $client_confidential if ( $args->{clientId} // '' ) eq 'secretapp';
		return $client_rt2          if ( $args->{clientId} // '' ) eq 'rt2app';
		return undef;
	},
);

my $xrt_grant = $get_secretapp_grant->('xrt1');
$t->post_ok(
	'/token',
	form => {
		grant_type    => 'refresh_token',
		client_id     => 'rt2app',
		refresh_token => $xrt_grant->{refresh_token},
	}
	)
	->status_is(400)
	->json_is( '/error' => 'invalid_grant', q{a refresh token cannot be redeemed by a different client} );

# Expired refresh token: shrink the configured lifetime under an existing
# token, as the access-token expiry test does.
my $xrt_grant2 = $get_secretapp_grant->('xrt2');
$t->app->helper(
	pt => sub {
		my $fake_pt = bless {
			ini => {
				'' => {
					ssoIssuer               => 'http://localhost',
					ssoTokenLifetime        => 3600,
					ssoRefreshTokenLifetime => -1,
					ssoCodeLifetime         => 600,
					passkeyRpId             => '',
					passkeyUserVerification => 'preferred',
				},
			},
			},
			'FakePT';
		return $fake_pt;
	}
);
$t->post_ok(
	'/token',
	{ Authorization => $sec_basic },
	form => {
		grant_type    => 'refresh_token',
		refresh_token => $xrt_grant2->{refresh_token},
	}
	)
	->status_is(400)
	->json_is( '/error' => 'invalid_grant', 'expired refresh token is refused' )
	->json_like( '/error_description' => qr/expired/i, 'expiry is reported as such' );

_install_stubs( $t->app );

# ── Revocation by a public client ────────────────────────────────────────────
# A public client (auth method none) may revoke its own tokens; possession of
# the token is the credential.

$t->reset_session;
$t->get_ok(
	'/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid&state=prv1'
)->status_is(302);
$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $prv_code = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');
$t->post_ok(
	'/token',
	form => {
		grant_type   => 'authorization_code',
		code         => $prv_code,
		client_id    => 'testapp',
		redirect_uri => 'https://testapp.example.com/callback',
	}
)->status_is(200);
my $prv_access = $t->tx->res->json->{access_token};

$t->post_ok( '/revoke', form => { client_id => 'testapp', token => $prv_access } )
	->status_is( 200, 'public client may revoke its own token' );
$t->get_ok( '/userinfo', { Authorization => "Bearer $prv_access" } )
	->status_is( 401, 'token revoked by its public client is dead' );

# ── Pending authorization requests are capped at 5 ───────────────────────────

$t->reset_session;
_install_stubs( $t->app );

my @cap_rids;
for my $i ( 1 .. 7 ) {
	$t->get_ok("$authz_base&state=cap$i")->status_is(302);
	push @cap_rids, Mojo::URL->new( $t->tx->res->headers->location )->query->param('rid');
}

$t->post_ok( "/sso/login?rid=$cap_rids[6]", form => { user => 'alice', pass => 'correct' } )->status_is(302);

$t->get_ok("/sso/consent?rid=$cap_rids[0]")
	->status_is(200)
	->content_like( qr/No Authorization Request/, 'oldest pending request beyond the cap was dropped' );
$t->get_ok("/sso/consent?rid=$cap_rids[2]")
	->status_is(200)
	->content_like( qr/Test Application/, 'a request within the cap of five is still pending' );

# ── max_age with a nonzero value ─────────────────────────────────────────────
# The session from the cap test is authenticated; make its auth_time older
# than a tight max_age.

sleep 2;
$t->get_ok("$authz_base&state=man1&max_age=1")
	->status_is(302)
	->header_like( Location => qr{/sso/login}, 'session older than max_age is sent back through login' );
$t->get_ok("$authz_base&state=man2&max_age=9999")
	->status_is(302)
	->header_like( Location => qr{/sso/consent}, 'session within max_age proceeds' );

# ── RP-initiated logout with an HS256-signed hint ────────────────────────────

$t->reset_session;
_install_stubs(
	$t->app,
	getOIDCClientEntry => sub {
		my ( $self, $args ) = @_;
		return $client_hs256 if ( $args->{clientId} // '' ) eq 'hs256app';
		return undef;
	},
);

$t->get_ok(
	'/authorize?client_id=hs256app&redirect_uri=https://hs256app.example.com/callback&response_type=code&scope=openid&state=hlo1'
)->status_is(302);
$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $hlo_code = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');
$t->post_ok(
	'/token',
	{ Authorization => 'Basic ' . MIME::Base64::encode_base64( "hs256app:$hs256_secret", '' ) },
	form => {
		grant_type   => 'authorization_code',
		code         => $hlo_code,
		redirect_uri => 'https://hs256app.example.com/callback',
	}
)->status_is(200);
my $hlo_id_token = $t->tx->res->json->{id_token};

$t->get_ok(
	"/sso/logout?id_token_hint=$hlo_id_token&post_logout_redirect_uri=https://hs256app.example.com/loggedout&state=hlo9"
)->status_is(302)->header_is(
	Location => 'https://hs256app.example.com/loggedout?state=hlo9',
	'HS256-signed hint verifies and redirects to the registered post-logout URI'
);

# A hint from a foreign issuer is not verified, even with a valid signature.
my $evil_header  = _b64url_encode('{"alg":"HS256","typ":"JWT"}');
my $evil_payload = _b64url_encode(
	Mojo::JSON::encode_json( { iss => 'https://evil.example.com', aud => 'hs256app', sub => 'alice' } ) );
my $evil_sig  = _b64url_encode( Digest::SHA::hmac_sha256( "$evil_header.$evil_payload", $hs256_secret ) );
my $evil_hint = "$evil_header.$evil_payload.$evil_sig";
$t->get_ok("/sso/logout?id_token_hint=$evil_hint&post_logout_redirect_uri=https://hs256app.example.com/loggedout")
	->status_is(200)
	->content_like( qr/Sign Out/, 'hint with a foreign issuer requires confirmation' );

_install_stubs( $t->app );

# ── UserInfo: access_token as a body parameter ───────────────────────────────

$t->reset_session;
$t->get_ok(
	'/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid&state=uif1'
)->status_is(302);
$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $uif_code = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');
$t->post_ok(
	'/token',
	form => {
		grant_type   => 'authorization_code',
		code         => $uif_code,
		client_id    => 'testapp',
		redirect_uri => 'https://testapp.example.com/callback',
	}
)->status_is(200);
my $uif_token = $t->tx->res->json->{access_token};

$t->post_ok( '/userinfo', form => { access_token => $uif_token } )
	->status_is(200)
	->json_is( '/sub' => 'alice', 'access_token accepted as a form parameter (RFC 6750 2.2)' );

# ── JWKS aggregation across clients ──────────────────────────────────────────
# All clients' public keys are served, including every key of a rotated set;
# a client with unparseable key material is skipped, not fatal.

my $client_badjwks = FakeEntry->new(
	_dn          => 'oidcClientId=badjwks,ou=oidc,dc=example,dc=com',
	oidcClientId => 'badjwks',
	oidcJwks     => 'this is not json {',
);

_install_stubs( $t->app, getOIDCClients => sub { return [ $client_rs256, $client_rot, $client_badjwks ] }, );

$t->get_ok('/jwks')->status_is(200);
my $agg_keys = $t->tx->res->json->{keys};
is( scalar @$agg_keys, 3, 'JWKS aggregates all keys of all clients; malformed sets are skipped' );
my %agg_kids = map { ( $_->{kid} // '' ) => $_ } @$agg_keys;
ok( $agg_kids{'test-rs256-kid'},              'single-key client key served' );
ok( $agg_kids{'rot-new'},                     'rotated set: new key served' );
ok( $agg_kids{'rot-old'},                     'rotated set: retained old key served' );
ok( !( grep { defined $_->{d} } @$agg_keys ), 'no private material in the aggregated JWKS' );

# A client lookup failure is a 500, never a 200 with an empty key set — a
# relying party would cache 'no keys' and reject valid ID tokens.
_install_stubs( $t->app, getOIDCClients => sub { die "LDAP unavailable\n" } );
$t->get_ok('/jwks')
	->status_is(500)
	->json_is( '/error' => 'server_error', 'JWKS lookup failure answers 500, not an empty key set' );

_install_stubs( $t->app, getOIDCClients => sub { return [] } );

# ── Discovery: response modes ────────────────────────────────────────────────

$t->get_ok('/.well-known/openid-configuration')
	->status_is(200)
	->json_is( '/response_modes_supported/0' => 'query', 'discovery advertises the query response mode' );

# ── Authorization: client with no registered redirect URIs ───────────────────

my $client_nouri = FakeEntry->new(
	_dn          => 'oidcClientId=nouri,ou=oidc,dc=example,dc=com',
	oidcClientId => 'nouri',
	oidcScope    => ['openid'],
	# deliberately no oidcRedirectURI
);
_install_stubs(
	$t->app,
	getOIDCClientEntry => sub {
		my ( $self, $args ) = @_;
		return $client_nouri if ( $args->{clientId} // '' ) eq 'nouri';
		return undef;
	},
);
$t->get_ok('/authorize?client_id=nouri&redirect_uri=https://nouri.example.com/cb&response_type=code&scope=openid')
	->status_is(200)
	->content_like( qr/Client Configuration Error/, 'client without registered redirect URIs gets an error page' );

_install_stubs( $t->app );

# ── Conformance-grade JWT validation with Crypt::JWT ────────────────────────
# The checks above prove our signatures are byte-correct. This section instead
# validates the tokens the way a standards-based relying party would: it hands
# the *published* JWKS (fetched from /jwks) and the raw id_token to
# Crypt::JWT::decode_jwt, which selects the verification key by `kid`, checks
# the RS256 signature, and enforces the iss/aud/exp claims in a single call.
# Passing this is strong evidence of real-world OIDC interop, and it exercises
# the negative behaviours a compliant RP must have (reject wrong key, reject
# alg confusion, reject an unsigned token).
#
# Skips cleanly when Crypt::JWT is not installed so the rest of the suite still
# runs.
subtest 'Crypt::JWT relying-party verification' => sub {
	eval { require Crypt::JWT; 1 }
		or plan skip_all => "Crypt::JWT not installed: $@";

	my $tj = Test::Mojo->new('App::Nisaba::WebSSO');
	_install_stubs(
		$tj->app,
		getOIDCClientEntry => sub {
			my ( $self, $args ) = @_;
			return $client_rs256  if ( $args->{clientId} // '' ) eq 'rs256app';
			return $client_hs256  if ( $args->{clientId} // '' ) eq 'hs256app';
			return $client_public if ( $args->{clientId} // '' ) eq 'testapp';
			return $client_none   if ( $args->{clientId} // '' ) eq 'nonealg';
			return undef;
		},
		# /jwks aggregates public keys across all clients; expose the RS256 one.
		getOIDCClients => sub { return [$client_rs256] },
	);
	_add_referer_hook($tj);

	# An RP discovers the signing keys from the JWKS endpoint.
	$tj->get_ok('/jwks')->status_is(200);
	my $jwks = $tj->tx->res->json;

	# Helper: drive the browser flow and return the issued id_token.
	my $get_id_token = sub {
		my ( $client_id, $redirect, $query, %token_args ) = @_;
		$tj->reset_session;
		$tj->get_ok("/authorize?client_id=$client_id&redirect_uri=$redirect&response_type=code&$query")
			->status_is(302);
		$tj->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
		$tj->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
		my $code = Mojo::URL->new( $tj->tx->res->headers->location )->query->param('code');
		$tj->post_ok(
			'/token',
			( $token_args{headers} ? ( $token_args{headers} ) : () ),
			form => {
				grant_type   => 'authorization_code',
				code         => $code,
				redirect_uri => $redirect,
				( $token_args{form} ? %{ $token_args{form} } : () ),
			}
		)->status_is(200);
		return $tj->tx->res->json->{id_token};
	}; ## end $get_id_token = sub

	# ── RS256: verify signature + claims against the published JWKS ──
	my $rs_token = $get_id_token->(
		'rs256app',                                            'https://rs256app.example.com/callback',
		'scope=openid+profile+email&state=cj1&nonce=cjnonce1', form => { client_id => 'rs256app' },
	);
	ok( $rs_token, 'obtained RS256 id_token' );

	my $claims = eval {
		Crypt::JWT::decode_jwt(
			token        => $rs_token,
			kid_keys     => $jwks,                                 # select key by `kid`, verify signature
			accepted_alg => 'RS256',                               # pin alg — reject alg confusion
			verify_iss   => sub { $_[0] eq 'http://localhost' },
			verify_aud   => sub { $_[0] eq 'rs256app' },
			# verify_exp defaults to enforcing exp when present (it always is)
		);
	};
	ok( !$@, 'Crypt::JWT verifies RS256 id_token against published JWKS' )
		or diag "decode_jwt failed: $@";
	is( $claims->{sub},   'alice',             'RS256 verified claim: sub' );
	is( $claims->{aud},   'rs256app',          'RS256 verified claim: aud' );
	is( $claims->{nonce}, 'cjnonce1',          'RS256 verified claim: nonce' );
	is( $claims->{email}, 'alice@example.com', 'RS256 verified claim: email' );
	is( $claims->{name},  'Alice Wonderland',  'RS256 verified claim: name' );
	ok( defined $claims->{exp} && $claims->{exp} > time(), 'RS256 verified claim: exp in the future' );

	# Wrong key (same kid, different RSA key) → signature must fail.
	my $other_rsa = Crypt::PK::RSA->new;
	$other_rsa->generate_key( 256, 65537 );
	my $other_jwk = Mojo::JSON::decode_json( $other_rsa->export_key_jwk('public') );
	$other_jwk->{kid} = 'test-rs256-kid';
	eval {
		Crypt::JWT::decode_jwt(
			token        => $rs_token,
			kid_keys     => { keys => [$other_jwk] },
			accepted_alg => 'RS256'
		);
	};
	ok( $@, 'RS256 id_token rejected when verified against the wrong key' );

	# alg confusion: an RS256 token must not be accepted where only HS256 is allowed.
	eval { Crypt::JWT::decode_jwt( token => $rs_token, kid_keys => $jwks, accepted_alg => 'HS256' ); };
	ok( $@, 'RS256 id_token rejected when only HS256 is accepted (alg confusion defense)' );

	# Tampered payload → signature must fail.
	my @p = split /\./, $rs_token;
	my $tampered_payload = Mojo::JSON::decode_json( _b64url_decode( $p[1] ) );
	$tampered_payload->{sub} = 'attacker';
	my $tampered = join '.', $p[0], _b64url_encode( Mojo::JSON::encode_json($tampered_payload) ), $p[2];
	eval { Crypt::JWT::decode_jwt( token => $tampered, kid_keys => $jwks, accepted_alg => 'RS256' ); };
	ok( $@, 'RS256 id_token with a tampered payload is rejected' );

	# ── alg=none: the provider refuses to issue an unsigned token ──
	# A client configured for alg=none never receives a token — the endpoint
	# fails closed with server_error rather than emitting an unsigned JWT.
	$tj->reset_session;
	$tj->get_ok(
		'/authorize?client_id=nonealg&redirect_uri=https://nonealg.example.com/cb&response_type=code&scope=openid&state=cj2&nonce=cjnonce2'
	)->status_is(302);
	$tj->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
	$tj->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
	my $none_code = Mojo::URL->new( $tj->tx->res->headers->location )->query->param('code');
	$tj->post_ok(
		'/token',
		form => {
			grant_type   => 'authorization_code',
			code         => $none_code,
			redirect_uri => 'https://nonealg.example.com/cb',
			client_id    => 'nonealg',
		}
		)
		->status_is(500)
		->json_is( '/error' => 'server_error', 'provider refuses to issue an unsigned (alg=none) token' );

	# ── HS256: verify with the shared client secret ──
	my $hs_basic = 'Basic ' . MIME::Base64::encode_base64( "hs256app:$hs256_secret", '' );
	my $hs_token = $get_id_token->(
		'hs256app',                                      'https://hs256app.example.com/callback',
		'scope=openid+profile&state=cj3&nonce=cjnonce3', headers => { Authorization => $hs_basic },
	);

	my $hs_claims = eval {
		Crypt::JWT::decode_jwt(
			token        => $hs_token,
			key          => $hs256_secret,
			accepted_alg => 'HS256',
			verify_iss   => sub { $_[0] eq 'http://localhost' },
			verify_aud   => sub { $_[0] eq 'hs256app' },
		);
	};
	ok( !$@, 'Crypt::JWT verifies HS256 id_token with the client secret' )
		or diag "decode_jwt HS256 failed: $@";
	is( $hs_claims->{aud},   'hs256app', 'HS256 verified claim: aud' );
	is( $hs_claims->{nonce}, 'cjnonce3', 'HS256 verified claim: nonce' );

	# Wrong secret → must fail.
	eval { Crypt::JWT::decode_jwt( token => $hs_token, key => 'wrong-secret', accepted_alg => 'HS256' ); };
	ok( $@, 'HS256 id_token rejected with the wrong secret' );
}; ## end 'Crypt::JWT relying-party verification' => sub

done_testing;
