#!/usr/bin/env perl

# sso-fuzz-target.pl — stand up mojo_nisaba_sso (App::Nisaba::WebSSO) as a real,
# long-lived prefork HTTP listener so an external fuzzer (ffuf, wfuzz, Burp, a
# raw fuzzer, curl loops) can throw traffic at it while sso-fuzz-supervisor.pl
# watches for breakage.
#
# This is the network-layer target the in-process Test::Mojo suites cannot be:
# it binds a real socket and runs multiple worker processes, so a payload that
# crashes a worker, wedges the event loop (ReDoS), or corrupts shared state is
# observable from outside.
#
# Two backends:
#
#   --backend mock   Monkey-patched fake LDAP (the shape used by t/web-sso*.t).
#                    No external services, deterministic, fast. Good for the
#                    HTTP-layer / Perl-code-path bug classes: malformed params,
#                    oversized/duplicate params, JSON bombs on the passkey
#                    endpoint, malformed JWT id_token_hint, bad Base64 in PKCE
#                    and Basic auth, crashes / 500s / ReDoS.
#
#   --backend slapd  A REAL OpenLDAP via Test::OpenLDAP (t/lib/NisabaSlapdTest).
#                    Required for anything that actually reaches an LDAP search
#                    filter — LDAP injection on the login user / client_id — a
#                    class the mock backend renders structurally invisible.
#
# The script prints a banner (URL, endpoints, seeded credentials) to STDERR and
# then blocks in the prefork event loop. Send it SIGINT/SIGTERM to shut down;
# the slapd backend is torn down cleanly on the way out.
#
# NOT for production. Seeds throwaway cleartext credentials and disables the
# session-cookie Secure flag so it works over plain HTTP.

use strict;
use warnings;

use File::Basename ();
use File::Spec     ();
use Cwd            ();

# ── Locate the repo and wire @INC before App::Nisaba::WebSSO is loaded ─────────
my ( $REPO, $SHARE );

BEGIN {
	my $script_dir = File::Basename::dirname( Cwd::abs_path(__FILE__) );    # devel/sso-fuzz
	$REPO  = Cwd::abs_path( File::Spec->catdir( $script_dir, File::Spec->updir, File::Spec->updir ) );
	$SHARE = File::Spec->catdir( $REPO, 'share' );
	unshift @INC, File::Spec->catdir( $REPO, 'lib' );
	unshift @INC, File::Spec->catdir( $REPO, 't', 'lib' );                  # NisabaSlapdTest / NisabaLDAPTest

	# The web app looks up its templates/assets through File::ShareDir; stub it
	# so we can run straight from the checkout without installing the dist.
	require File::ShareDir;
	no warnings 'redefine';
	*File::ShareDir::dist_dir = sub { $SHARE };

	# The app refuses to start without an explicit session secret, and marks the
	# session cookie Secure by default (which would not round-trip over plain
	# HTTP). Set sane fuzzing defaults unless the caller overrode them.
	$ENV{NISABA_SECRET}        = 'sso-fuzz-secret' unless defined $ENV{NISABA_SECRET};
	$ENV{NISABA_COOKIE_SECURE} = '0'               unless defined $ENV{NISABA_COOKIE_SECURE};
} ## end BEGIN

use Getopt::Long          qw(:config no_ignore_case bundling);
use File::Temp            ();
use Mojo::Util            ();
use Mojo::Server::Prefork ();

# ── Options ───────────────────────────────────────────────────────────────────
my %opt = (
	backend      => 'mock',
	host         => '127.0.0.1',
	port         => 3000,
	workers      => 4,
	'log-level'  => 'info',
	'rate-limit' => 0,             # off by default so payloads reach parsing code
);
GetOptions( \%opt, 'backend=s', 'host=s', 'port=i', 'workers=i', 'log-level=s', 'rate-limit=i', 'help|h', )
	or die "bad options; try --help\n";

if ( $opt{help} ) {
	print <<'USAGE';
usage: sso-fuzz-target.pl [options]

  --backend mock|slapd   LDAP backend (default: mock)
  --host HOST            bind address (default: 127.0.0.1)
  --port PORT            bind port    (default: 3000)
  --workers N            prefork worker count (default: 4)
  --log-level LEVEL      Mojo log level: debug|info|warn|error (default: info)
  --rate-limit 0|1       enable the app's brute-force rate limiter (default: 0)
  --help                 this text

Logs are written to STDERR. Normally launched by sso-fuzz-supervisor.pl.
USAGE
	exit 0;
} ## end if ( $opt{help} )

die "--backend must be 'mock' or 'slapd'\n"
	unless $opt{backend} eq 'mock' || $opt{backend} eq 'slapd';

$ENV{NISABA_RATELIMIT} = $opt{'rate-limit'} ? '1' : '0';

my $listen = "http://$opt{host}:$opt{port}";

# Seeded credentials, identical across backends where possible so the same
# fuzzing corpus drives either target.
my %CREDS = (
	user          => 'alice',
	pass          => 'correct',
	conf_client   => 'conf',
	conf_secret   => 's3cret',
	conf_redirect => 'https://fuzz.example.com/callback',
	pub_client    => 'pub',
	pub_redirect  => 'https://fuzz.example.com/pub-callback',
);

# Kept alive at file scope for the whole process lifetime.
my $SLAPD_ENV;
my $OWNER_PID = $$;

# ── Backend: slapd ────────────────────────────────────────────────────────────
# Spawn a real OpenLDAP, seed a user + confidential client, and point the app at
# it via NISABA_CONFIG. Only this (owner) process may tear slapd down — see the
# DESTROY guard below.
sub start_slapd_backend {
	require NisabaSlapdTest;

	my $store_dir  = File::Temp::tempdir( 'sso-fuzz-store-XXXXXX', TMPDIR => 1, CLEANUP => 1 );
	my $store_path = File::Spec->catfile( $store_dir, 'websso.sqlite' );

	my ( $env, $skip ) = NisabaSlapdTest::setup(
		ini => {
			ssoIssuer         => $listen,
			ssoStorageBackend => 'SQLite',
			ssoStoragePath    => $store_path,
			cookieSecure      => 0,
			rateLimit         => $opt{'rate-limit'},
		},
	);
	die "cannot start slapd backend: $skip\n" unless $env;
	$SLAPD_ENV = $env;

	# Test::OpenLDAP::DESTROY / stop() have no pid guard: in a forked prefork
	# worker, waitpid() on slapd's pid returns -1 (truthy), so an exiting worker
	# would unlink the shared ldapi socket and tear the directory down for every
	# other worker. Neutralise teardown everywhere except the owner process.
	{
		no warnings 'redefine';
		my $orig_destroy = \&Test::OpenLDAP::DESTROY;
		my $orig_stop    = \&Test::OpenLDAP::stop;
		*Test::OpenLDAP::DESTROY = sub { return if $$ != $OWNER_PID; return $orig_destroy->(@_); };
		*Test::OpenLDAP::stop    = sub { return if $$ != $OWNER_PID; return $orig_stop->(@_); };
	}

	_seed_slapd($env);

	# Hand the app its config; App::Nisaba::connect() opens a fresh Net::LDAP per
	# call, so there is no handle shared across the fork.
	$ENV{NISABA_CONFIG} = $env->{config}->filename;

	warn "[target] slapd backend up at $env->{uri}\n";
	return;
} ## end sub start_slapd_backend

sub _seed_slapd {
	my ($env) = @_;
	my $pt = $env->{pt};

	my $ok = $pt->addOIDCClient(
		{
			clientId                 => $CREDS{conf_client},
			clientSecret             => $CREDS{conf_secret},
			clientName               => 'SSO Fuzz Confidential Client',
			applicationType          => 'web',
			authMethod               => 'client_secret_basic',
			idTokenSignedResponseAlg => 'HS256',
			redirectURIs             => [ $CREDS{conf_redirect} ],
			scopes                   => [ 'openid', 'profile', 'email' ],
			grantTypes               => [ 'authorization_code', 'refresh_token' ],
			responseTypes            => ['code'],
		}
	);
	die 'seeding OIDC client failed: ' . $pt->errorString . "\n" unless $ok;

	# Seed the user directly so we control exactly which attributes exist and can
	# bind with a known password.
	my $dn   = "uid=$CREDS{user},ou=users,dc=example,dc=com";
	my $mesg = $env->{admin}->add(
		$dn,
		attrs => [
			objectClass   => [ 'top', 'person', 'organizationalPerson', 'inetOrgPerson', 'posixAccount' ],
			uid           => $CREDS{user},
			cn            => 'Alice',
			sn            => 'Wonderland',
			givenName     => 'Alice',
			displayName   => 'Alice Wonderland',
			mail          => 'alice@example.com',
			uidNumber     => 10_000,
			gidNumber     => 10_000,
			homeDirectory => "/home/$CREDS{user}",
			loginShell    => '/bin/sh',
			userPassword  => $CREDS{pass},
		],
	);
	die 'seeding user failed: ' . $mesg->error . "\n" if $mesg->code;
	return;
} ## end sub _seed_slapd

# ── Backend: mock ─────────────────────────────────────────────────────────────
# Replicate the fake-LDAP stubs from t/web-sso.t on a freshly built app: a fake
# `pt` helper plus a shared, file-backed grant store so codes/tokens issued by
# one worker are redeemable by another.
sub install_mock_stubs {
	my ($app) = @_;

	require App::Nisaba::WebSSO::Storage;
	require Crypt::PK::RSA;
	require Mojo::JSON;

	# A public client signs id tokens with its own RSA key (alg none is refused),
	# mirroring a real registration.
	my $rsa = Crypt::PK::RSA->new;
	$rsa->generate_key( 256, 65_537 );    # 2048-bit
	my $jwk = Mojo::JSON::decode_json( $rsa->export_key_jwk('private') );
	$jwk->{kid} = 'sso-fuzz-pub-kid';
	$jwk->{use} = 'sig';
	$jwk->{alg} = 'RS256';
	my $jwks_json = Mojo::JSON::encode_json( { keys => [$jwk] } );

	my $client_pub = FuzzEntry->new(
		_dn                          => "oidcClientId=$CREDS{pub_client},ou=oidc,dc=example,dc=com",
		oidcClientId                 => $CREDS{pub_client},
		oidcClientName               => 'SSO Fuzz Public Client',
		oidcRedirectURI              => [ $CREDS{pub_redirect} ],
		oidcScope                    => [ 'openid', 'profile', 'email', 'phone', 'address' ],
		oidcGrantType                => ['authorization_code'],
		oidcResponseType             => ['code'],
		oidcApplicationType          => 'web',
		oidcTokenEndpointAuthMethod  => 'none',
		oidcIdTokenSignedResponseAlg => 'RS256',
		oidcJwks                     => $jwks_json,
	);

	my $client_conf = FuzzEntry->new(
		_dn                          => "oidcClientId=$CREDS{conf_client},ou=oidc,dc=example,dc=com",
		oidcClientId                 => $CREDS{conf_client},
		oidcClientName               => 'SSO Fuzz Confidential Client',
		oidcClientSecret             => $CREDS{conf_secret},
		oidcIdTokenSignedResponseAlg => 'HS256',
		oidcRedirectURI              => [ $CREDS{conf_redirect} ],
		oidcScope                    => [ 'openid', 'profile', 'email' ],
		oidcGrantType                => [ 'authorization_code', 'refresh_token' ],
		oidcResponseType             => ['code'],
		oidcApplicationType          => 'web',
		oidcTokenEndpointAuthMethod  => 'client_secret_basic',
	);

	my $alice = FuzzEntry->new(
		_dn               => "uid=$CREDS{user},ou=users,dc=example,dc=com",
		uid               => $CREDS{user},
		displayName       => 'Alice Wonderland',
		givenName         => 'Alice',
		sn                => 'Wonderland',
		mail              => 'alice@example.com',
		telephoneNumber   => '+1-555-0100',
		preferredLanguage => 'en',
		objectClass       => [ 'posixAccount', 'inetOrgPerson', 'person', 'oidcSubject' ],
		oidcEmailVerified => 'TRUE',
	);

	my %methods = (
		error                  => sub { 0 },
		errorString            => sub { '' },
		errorblank             => sub { },
		oidcbaseConfigured     => sub { 1 },
		passkeySchemaAvailable => sub { 0 },
		getOIDCClientEntry     => sub {
			my ( $self, $args ) = @_;
			my $id = $args->{clientId} // '';
			return $client_pub  if $id eq $CREDS{pub_client};
			return $client_conf if $id eq $CREDS{conf_client};
			return undef;
		},
		getOIDCClients     => sub { return [ $client_pub, $client_conf ] },
		userVerifyPassword => sub {
			my ( $self, $args ) = @_;
			die "bad password\n"
				unless ( $args->{user} // '' ) eq $CREDS{user}
				&& ( $args->{password} // '' ) eq $CREDS{pass};
			return 1;
		},
		userSelfInfo => sub { return { totpStatus => 'inactive' } },
		getUserEntry => sub {
			my ( $self, $args ) = @_;
			return $alice if ( $args->{user} // '' ) eq $CREDS{user};
			return undef;
		},
		userTotpVerify => sub { return 0 },
	);

	my $fake_pt = bless {
		ini => {
			'' => {
				ssoIssuer               => $listen,
				ssoTokenLifetime        => 3600,
				ssoCodeLifetime         => 600,
				passkeyRpId             => '',
				passkeyUserVerification => 'preferred',
			},
		},
		},
		'FuzzPT';
	Mojo::Util::monkey_patch( 'FuzzPT', %methods );

	$app->helper( pt => sub { $fake_pt } );

	# One grant store, on disk, shared by all workers. Open lazily per process so
	# each worker gets its own DBI handle to the same file (no dbh across fork).
	my $store_dir  = File::Temp::tempdir( 'sso-fuzz-store-XXXXXX', TMPDIR => 1, CLEANUP => 1 );
	my $store_path = File::Spec->catfile( $store_dir, 'store.sqlite' );
	my %store_by_pid;
	no warnings 'redefine';
	$app->helper(
		sso_storage => sub {
			return $store_by_pid{$$} //=
				App::Nisaba::WebSSO::Storage->new( { backend => 'SQLite', path => $store_path } );
		}
	);

	# Seed a CSRF token into every session so browser-form POSTs (login/consent)
	# are drivable with the fixed 'sso-fuzz-csrf' token/header.
	$app->hook( before_dispatch => sub { $_[0]->session( csrf_token => 'sso-fuzz-csrf' ) } );
	return;
} ## end sub install_mock_stubs

# Minimal Net::LDAP::Entry look-alike for the mock backend.
{

	package FuzzEntry;

	sub new {
		my ( $class, %attrs ) = @_;
		my $dn = delete $attrs{_dn} // '';
		return bless { attrs => \%attrs, _dn => $dn }, $class;
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

# ── Boot ──────────────────────────────────────────────────────────────────────
start_slapd_backend() if $opt{backend} eq 'slapd';

my $prefork = Mojo::Server::Prefork->new(
	listen => [$listen],
	silent => 1,
);
$prefork->workers( $opt{workers} );

my $app = $prefork->build_app('App::Nisaba::WebSSO');
$app->log->level( $opt{'log-level'} );
install_mock_stubs($app) if $opt{backend} eq 'mock';

print {*STDERR} _banner();

# Clean slapd teardown on the way out (owner only; File::Temp objects are
# pid-guarded on their own).
END {
	if ( defined $SLAPD_ENV && $$ == $OWNER_PID ) {
		require NisabaSlapdTest;
		NisabaSlapdTest::teardown($SLAPD_ENV);
	}
}

$prefork->run;

sub _banner {
	my $b = <<"BANNER";
──────────────────────────────────────────────────────────────────────────────
 mojo_nisaba_sso fuzz target  ($opt{backend} backend, $opt{workers} workers)
 listening:  $listen
 discovery:  $listen/.well-known/openid-configuration
 endpoints:  /authorize /token /userinfo /revoke /introspect /jwks
             /sso/login /sso/totp /sso/consent /sso/logout /sso/passkeys/...
 rate limit: @{[ $opt{'rate-limit'} ? 'ON' : 'off' ]}
 user:       $CREDS{user} / $CREDS{pass}
 client(c):  $CREDS{conf_client} / $CREDS{conf_secret}  (client_secret_basic, HS256)
             redirect_uri $CREDS{conf_redirect}
BANNER
	if ( $opt{backend} eq 'mock' ) {
		$b .= " client(p):  $CREDS{pub_client}  (public, PKCE S256, RS256)\n";
		$b .= "             redirect_uri $CREDS{pub_redirect}\n";
		$b .= " csrf token: sso-fuzz-csrf  (header X-CSRF-Token)\n";
	}
	$b .= "──────────────────────────────────────────────────────────────────────────────\n";
	return $b;
} ## end sub _banner
