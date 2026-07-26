#!perl
use strict;
use warnings;

# Parser-abuse / robustness tests for App::Nisaba::WebSSO: malformed input at the
# web layer must be handled gracefully (a clean 4xx), never an uncaught exception
# rendered as HTTP 500. In-process Test::Mojo (mocked LDAP, same shape as
# t/web-sso.t) is sufficient here — these paths are pure request parsing (Basic
# auth, Bearer tokens, JWT id_token_hint, query/form params, JSON bodies) and do
# not depend on a real directory. (Worker-crash / hang / wire-level fuzzing lives
# in the out-of-process harness under xt/sso-fuzz.)

use FindBin ();
use lib "$FindBin::Bin/lib";
use NisabaWebTest qw(no_pkce no_rate_limit);

use Test::More;
use Mojo::Util   ();
use MIME::Base64 ();

eval { require App::Nisaba::WebSSO };
plan skip_all => "App::Nisaba::WebSSO failed to load: $@" if $@;

my $TEST_STORAGE;
eval {
	require App::Nisaba::WebSSO::Storage;
	$TEST_STORAGE = App::Nisaba::WebSSO::Storage->new( { backend => 'SQLite', path => ':memory:' } );
	1;
} or plan skip_all => "App::Nisaba::WebSSO::Storage unavailable (DBD::SQLite?): $@";

eval { require Test::Mojo; 1 } or plan skip_all => "Test::Mojo unavailable: $@";

# ── Minimal fake LDAP entry + confidential client + user ─────────────────────
my $client = FakeEntry->new(
	_dn                          => 'oidcClientId=secretapp,ou=oidc,dc=example,dc=com',
	oidcClientId                 => 'secretapp',
	oidcClientSecret             => 's3cret',
	oidcIdTokenSignedResponseAlg => 'HS256',
	oidcRedirectURI              => ['https://secretapp.example.com/callback'],
	oidcScope                    => [ 'openid', 'profile' ],
	oidcGrantType                => ['authorization_code'],
	oidcResponseType             => ['code'],
	oidcTokenEndpointAuthMethod  => 'client_secret_basic',
);

my $alice = FakeEntry->new(
	_dn         => 'uid=alice,ou=users,dc=example,dc=com',
	uid         => 'alice',
	displayName => 'Alice Wonderland',
	mail        => 'alice@example.com',
	objectClass => [ 'posixAccount', 'inetOrgPerson', 'person' ],
);

sub install_stubs {
	my ($app) = @_;
	my %methods = (
		error                  => sub { 0 },
		errorString            => sub { '' },
		errorblank             => sub { },
		oidcbaseConfigured     => sub { 1 },
		passkeySchemaAvailable => sub { 0 },
		getOIDCClientEntry     => sub {
			my ( $self, $args ) = @_;
			return $client if ( $args->{clientId} // '' ) eq 'secretapp';
			return undef;
		},
		getOIDCClients     => sub { return [$client] },
		userVerifyPassword => sub {
			my ( $self, $args ) = @_;
			die "bad password\n"
				unless ( $args->{user} // '' ) eq 'alice' && ( $args->{password} // '' ) eq 'correct';
			return 1;
		},
		userSelfInfo => sub { return { totpStatus => 'inactive' } },
		getUserEntry => sub {
			my ( $self, $args ) = @_;
			return $alice if ( $args->{user} // '' ) eq 'alice';
			return undef;
		},
		userTotpVerify => sub { return 0 },
	);
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
	no warnings 'redefine';
	$app->helper( sso_storage => sub { $TEST_STORAGE } );
	$app->hook( before_dispatch => sub { $_[0]->session( csrf_token => 'testcsrf' ) } );
	return;
} ## end sub install_stubs

my $t = Test::Mojo->new('App::Nisaba::WebSSO');
install_stubs( $t->app );

# Give every POST a same-origin Referer + CSRF token so requests reach the action
# (and its parser) rather than being turned away by the CSRF guard.
$t->ua->on(
	start => sub {
		my ( $ua, $tx ) = @_;
		return unless $tx->req->method eq 'POST';
		my $host = $tx->req->url->to_abs->host_port // 'localhost';
		$tx->req->headers->referrer("http://$host/");
		$tx->req->headers->header( 'X-CSRF-Token' => 'testcsrf' );
	}
);

my $basic_bad  = 'Basic ' . '!!!not-valid-base64!!!';
my $basic_good = 'Basic ' . MIME::Base64::encode_base64( 'secretapp:s3cret', '' );
my $huge       = 'A' x 100_000;
my $nested     = ( '[' x 2000 ) . '1' . ( ']' x 2000 );

# Each case: (description, coderef returning a completed transaction). Driven
# through $t->ua (not get_ok/post_ok) so the huge/binary payloads don't get
# echoed into the TAP stream. The assertion is uniform — a response arrived and
# it is not a 500 (an uncaught exception would render as one). The `start` hook
# below still adds a same-origin Referer + CSRF token to every POST.
my $cb    = 'https://secretapp.example.com/callback';
my @cases = (
	[
		'authorize: oversized scope',
		sub {
			$t->ua->get(
				"/authorize?client_id=secretapp&redirect_uri=$cb&response_type=code&scope=openid+$huge&state=s1");
		}
	],
	[
		'authorize: duplicated client_id',
		sub {
			$t->ua->get(
				"/authorize?client_id=secretapp&client_id=*&redirect_uri=$cb&response_type=code&scope=openid&state=s2");
		}
	],
	[
		'authorize: junk response_type',
		sub {
			$t->ua->get(
				"/authorize?client_id=secretapp&redirect_uri=$cb&response_type=%00%01%02&scope=openid&state=s3");
		}
	],
	[
		'token: malformed Basic auth',
		sub {
			$t->ua->post(
				'/token',
				{ Authorization => $basic_bad },
				form => { grant_type => 'authorization_code', code => 'garbage', redirect_uri => 'x' }
			);
		} ## end sub
	],
	[
		'token: unknown grant_type',
		sub {
			$t->ua->post( '/token', { Authorization => $basic_good }, form => { grant_type => "weird\x00type" } );
		}
	],
	[
		'token: garbage code',
		sub {
			$t->ua->post(
				'/token',
				{ Authorization => $basic_good },
				form => { grant_type => 'authorization_code', code => $huge, redirect_uri => 'x' }
			);
		} ## end sub
	],
	[
		'token: bad Base64 code_verifier',
		sub {
			$t->ua->post(
				'/token',
				{ Authorization => $basic_good },
				form => { grant_type => 'authorization_code', code => 'x', code_verifier => '####not b64####' }
			);
		} ## end sub
	],
	[
		'userinfo: malformed Bearer',
		sub {
			$t->ua->get( '/userinfo', { Authorization => 'Bearer ..not-a-token..' } );
		}
	],
	[
		'revoke: garbage token',
		sub {
			$t->ua->post( '/revoke', { Authorization => $basic_good }, form => { token => "\x00\xff garbage" } );
		}
	],
	[
		'introspect: garbage token',
		sub {
			$t->ua->post( '/introspect', { Authorization => $basic_good }, form => { token => $huge } );
		}
	],
	[
		'logout: malformed id_token_hint (three junk segments)',
		sub {
			$t->ua->get('/sso/logout?id_token_hint=aaa.bbb.ccc');
		}
	],
	[
		'logout: oversized id_token_hint',
		sub {
			$t->ua->get("/sso/logout?id_token_hint=$huge");
		}
	],
	[
		'passkey finish: truncated JSON',
		sub {
			$t->ua->post( '/sso/passkeys/login/finish', { 'Content-Type' => 'application/json' }, '{"id":"x",' );
		}
	],
	[
		'passkey finish: response is not an object',
		sub {
			$t->ua->post( '/sso/passkeys/login/finish', { 'Content-Type' => 'application/json' },
				'{"response":"nope"}' );
		}
	],
	[
		'passkey finish: deeply nested JSON',
		sub {
			$t->ua->post( '/sso/passkeys/login/finish', { 'Content-Type' => 'application/json' }, $nested );
		}
	],
	[
		'passkey finish: not JSON at all',
		sub {
			$t->ua->post( '/sso/passkeys/login/finish', { 'Content-Type' => 'application/json' },
				'%%%not-json%%%' );
		}
	],
);

for my $case (@cases) {
	my ( $desc, $fn ) = @{$case};
	my $tx   = $fn->();
	my $code = $tx->res->code;
	ok( defined $code && $code != 500, "$desc -> HTTP " . ( defined $code ? $code : 'undef' ) . ' (handled, not 500)' );
}

done_testing;
