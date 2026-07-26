#!perl
use strict;
use warnings;

# Open-redirect and HTTP response-splitting regression tests for
# App::Nisaba::WebSSO, in-process via Test::Mojo (mocked LDAP, same shape as
# t/web-sso.t). Both are pure application logic and need no real directory or
# network:
#
#   A. redirect_uri / post_logout_redirect_uri must be matched exactly — the
#      bypass-class payloads (protocol-relative, userinfo, suffix, traversal,
#      backslash) must never produce a redirect to an attacker host (CWE-601).
#   B. a CR/LF-bearing reflected parameter (state, echoed into the error-redirect
#      Location) must not split into a new response header (CWE-113).
#
# t/web-sso.t already covers one crude redirect_uri mismatch; this widens that to
# the tricky variants and adds the logout + splitting cases.

use FindBin ();
use lib "$FindBin::Bin/lib";
use NisabaWebTest qw(no_pkce no_rate_limit);

use Test::More;
use Mojo::Util ();
use Mojo::URL  ();

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
my $reg_redirect = 'https://secretapp.example.com/callback';

my $client = FakeEntry->new(
	_dn                          => 'oidcClientId=secretapp,ou=oidc,dc=example,dc=com',
	oidcClientId                 => 'secretapp',
	oidcClientSecret             => 's3cret',
	oidcIdTokenSignedResponseAlg => 'HS256',
	oidcRedirectURI              => [$reg_redirect],
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

my $EVIL = 'evil.example.com';

# GET /authorize with an overridable query. Returns the transaction.
sub authorize {
	my (%o) = @_;
	my $url = Mojo::URL->new('/authorize')->query(
		{
			response_type => 'code',
			client_id     => 'secretapp',
			redirect_uri  => $reg_redirect,
			scope         => 'openid',
			state         => 'st123',
			%o,
		}
	);
	return $t->ua->get($url);
} ## end sub authorize

# True if the response is a 3xx whose Location points at the attacker host.
sub redirected_to_evil {
	my ($tx) = @_;
	my $code = $tx->res->code // 0;
	return 0 unless $code >= 300 && $code < 400;
	return index( $tx->res->headers->location // '', $EVIL ) >= 0 ? 1 : 0;
}

# ── Baseline: a valid redirect_uri is accepted (reaches login) ───────────────
{
	my $tx = authorize();
	is( $tx->res->code, 302, 'valid authorize request redirects' );
	like( $tx->res->headers->location // '', qr{/sso/login}, 'valid redirect_uri sends the browser to login' );
}

# ── A. Open redirect on /authorize: bypass-class redirect_uri payloads ───────
my @redirect_payloads = (
	"https://$EVIL/",                                  # different host
	"https://$EVIL/callback",                          # different host, same path
	"//$EVIL/",                                        # protocol-relative
	"https://secretapp.example.com\@$EVIL/",           # userinfo trick (real host as userinfo)
	"https://secretapp.example.com.$EVIL/callback",    # host suffix
	"$reg_redirect.$EVIL",                             # full-URI suffix
	"$reg_redirect/../../$EVIL",                       # path traversal
	"https://$EVIL\\\@secretapp.example.com/",         # backslash confusion
	"$reg_redirect#\@$EVIL/",                          # fragment trick
);

for my $payload (@redirect_payloads) {
	my $tx = authorize( redirect_uri => $payload );
	ok( !redirected_to_evil($tx),
		"redirect_uri=$payload is not honoured as an open redirect (HTTP " . ( $tx->res->code // '?' ) . ')' );
}

# ── A. Open redirect on /sso/logout: post_logout_redirect_uri ────────────────
# The client registers no post-logout redirect URI, so none may be honoured.
for my $payload ( "https://$EVIL/", "//$EVIL/", "https://secretapp.example.com\@$EVIL/" ) {
	my $url
		= Mojo::URL->new('/sso/logout')->query( { post_logout_redirect_uri => $payload, client_id => 'secretapp' } );
	my $tx = $t->ua->get($url);
	ok( !redirected_to_evil($tx),
		"post_logout_redirect_uri=$payload is not honoured (HTTP " . ( $tx->res->code // '?' ) . ')' );
}

# ── B. HTTP response splitting: CR/LF in a reflected parameter ───────────────
# An unregistered scope forces an error redirect back to the (valid) redirect_uri
# with `state` echoed into the Location; a CR/LF in state must not split a header.
{
	my $marker = 'X-Nisaba-Split-Test';
	my $tx     = authorize( scope => 'openid this_scope_is_not_registered', state => "s\r\n$marker: pwned" );

	# A genuine split would surface $marker as its own response header name.
	my $split = grep { lc eq lc $marker } @{ $tx->res->headers->names };
	ok( !$split, 'CR/LF in state does not split into a new response header' );

	# And no header value should carry a raw CR/LF.
	my $raw_crlf = grep { defined && /[\r\n]/ } map { $tx->res->headers->header($_) } @{ $tx->res->headers->names };
	ok( !$raw_crlf, 'no response header carries a raw CR/LF' );
}

done_testing;
