#!perl
use strict;
use warnings;

# Stub File::ShareDir::dist_dir so the web app can start without the dist
# being installed. Must happen before App::Nisaba::WebSSO is loaded.
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

	# This suite exercises broad OIDC behaviour with a public client and no PKCE;
	# the mandatory-PKCE policy is covered on its own in t/web-sso-pkce.t.
	$ENV{NISABA_REQUIRE_PKCE} = '0' unless defined $ENV{NISABA_REQUIRE_PKCE};

	# Rate limiting has its own suite (t/web-ratelimit.t); disable here so the
	# many repeated logins aren't throttled.
	$ENV{NISABA_RATELIMIT} = '0' unless defined $ENV{NISABA_RATELIMIT};
} ## end BEGIN

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
	oidcScope                    => [ 'openid', 'profile', 'email' ],
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
	oidcScope                    => [ 'openid', 'profile' ],
	oidcGrantType                => ['authorization_code'],
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
)->status_is(400)->json_is( '/error' => 'invalid_grant', 'wrong client_id returns invalid_grant' );

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

# ── Token endpoint: confidential client with correct secret ──────────────────

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
)->status_is(200)->json_has( '/access_token', 'correct secret gets access_token' );

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

my $plain_verifier = 'my-plain-verifier-string';

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

# Second authorize with existing sso_user session → straight to consent
$t->get_ok(
	'/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid&state=pre2'
)->status_is(302)->header_like( Location => qr{/sso/consent}, 'already-authenticated user skips login' );

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
# Test form-based client_secret (not Authorization header) for confidential client

$t->reset_session;
_install_stubs( $t->app );

$t->get_ok(
	'/authorize?client_id=secretapp&redirect_uri=https://secretapp.example.com/callback&response_type=code&scope=openid&state=csp1'
)->status_is(302);
$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $csp_code = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');

# Wrong secret via form parameter
$t->post_ok(
	'/token',
	form => {
		grant_type    => 'authorization_code',
		code          => $csp_code,
		client_id     => 'secretapp',
		client_secret => 'wrongsecret',
		redirect_uri  => 'https://secretapp.example.com/callback',
	}
)->status_is(401)->json_is( '/error' => 'invalid_client', 'client_secret_post: wrong secret rejected' );

# Correct secret via form parameter (need a new code since previous was consumed)
$t->reset_session;
_install_stubs( $t->app );

$t->get_ok(
	'/authorize?client_id=secretapp&redirect_uri=https://secretapp.example.com/callback&response_type=code&scope=openid&state=csp2'
)->status_is(302);
$t->post_ok( '/sso/login',   form => { user     => 'alice', pass => 'correct' } )->status_is(302);
$t->post_ok( '/sso/consent', form => { decision => 'allow' } )->status_is(302);
my $csp_code2 = Mojo::URL->new( $t->tx->res->headers->location )->query->param('code');

$t->post_ok(
	'/token',
	form => {
		grant_type    => 'authorization_code',
		code          => $csp_code2,
		client_id     => 'secretapp',
		client_secret => 's3cret',
		redirect_uri  => 'https://secretapp.example.com/callback',
	}
	)
	->status_is(200)
	->json_has( '/access_token', 'client_secret_post: correct secret accepted via form param' )
	->json_is( '/token_type' => 'Bearer' );

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

# Session is active: a second authorize skips login.
$t->get_ok(
	'/authorize?client_id=testapp&redirect_uri=https://testapp.example.com/callback&response_type=code&scope=openid&state=lo2'
)->status_is(302)->header_like( Location => qr{/sso/consent}, 'logout: session active before logout' );

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
