#!perl
use strict;
use warnings;

# End-to-end OIDC interop test driven by oauth2c
# (https://github.com/cloudentity/oauth2c) — a real OAuth2/OIDC relying-party
# CLI. Unlike t/web-sso.t (in-process Test::Mojo), this test:
#
#   1. Boots App::Nisaba::WebSSO as a real HTTP daemon on an ephemeral port
#      (same stubbed LDAP backend as t/web-sso.t — no directory needed).
#   2. Runs `oauth2c <issuer> ... --pkce --no-browser`, which performs OIDC
#      discovery, generates its own state/PKCE pair, prints the authorization
#      URL, and waits on its own callback server.
#   3. Plays the browser: follows the authorization URL, logs in, consents,
#      and delivers the resulting redirect to oauth2c's callback server.
#   4. Asserts oauth2c completed the authorization-code + PKCE exchange
#      (token endpoint, client_secret_basic) and received an id_token.
#
# Prerequisites are soft: the test skips cleanly when oauth2c is missing. If
# NISABA_TEST_OAUTH2C_INSTALL is set to a true value and a Go toolchain is
# available (plain `go` or version-suffixed like go126 / go1.26; override with
# GO=/path/to/go), it will first try
# `go install github.com/cloudentity/oauth2c@latest` (network + compile).

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
use Config;
use File::Temp   ();
use IO::Socket::INET;
use MIME::Base64 ();
use POSIX        qw(WNOHANG);

# ── Generic helpers ──────────────────────────────────────────────────────────

# Run a command with no shell, capturing merged STDOUT+STDERR, with a timeout
# (seconds). Returns ($exit_status, $output, $timed_out).
sub capture {
	my ( $timeout, @cmd ) = @_;

	my $pid = open( my $fh, '-|' );
	return ( undef, "fork/exec failed: $!", 0 ) unless defined $pid;
	if ( $pid == 0 ) {
		open STDERR, '>&', \*STDOUT;
		exec @cmd or POSIX::_exit(127);
	}

	my $out       = '';
	my $timed_out = 0;
	eval {
		local $SIG{ALRM} = sub { die "timeout\n" };
		alarm($timeout) if $timeout;
		local $/;
		$out = <$fh> // '';
		alarm 0;
		1;
	} or do {
		if ( ( $@ // '' ) eq "timeout\n" ) {
			$timed_out = 1;
			kill 'TERM', $pid;
			kill 'KILL', $pid;
		}
	};
	close $fh;
	return ( $?, $out, $timed_out );
}

sub path_dirs {
	my $sep = $Config{path_sep} || ':';
	return grep { length $_ && -d $_ } split /\Q$sep\E/, ( $ENV{PATH} // '' );
}

sub find_on_path {
	my ($name) = @_;
	for my $dir ( path_dirs() ) {
		my $p = File::Spec->catfile( $dir, $name );
		return $p if -x $p && !-d $p;
	}
	return undef;
}

# Locate a Go toolchain: an explicit GO override, then plain `go`, then any
# version-suffixed variant (go126 / go1.26 / go1.21.5) found on PATH.
sub find_go {
	if ( my $g = $ENV{GO} ) {
		return $g if -x $g && !-d $g;
	}

	my @cands;
	for my $dir ( path_dirs() ) {
		opendir( my $dh, $dir ) or next;
		for my $f ( readdir $dh ) {
			next unless $f =~ /^go(?:[0-9][0-9.]*)?\z/;
			my $p = File::Spec->catfile( $dir, $f );
			push @cands, $p if -x $p && !-d $p;
		}
		closedir $dh;
	}

	my ($plain) = grep { ( File::Spec->splitpath($_) )[2] eq 'go' } @cands;
	return $plain if $plain;

	(@cands) = sort { $b cmp $a } @cands;
	return $cands[0];
}

# Where `go install` places binaries (GOBIN, else first GOPATH entry + /bin).
sub go_bin_dir {
	my ($go) = @_;
	return undef unless $go;
	my ( undef, $gobin )  = capture( 30, $go, 'env', 'GOBIN' );
	my ( undef, $gopath ) = capture( 30, $go, 'env', 'GOPATH' );
	for ( $gobin, $gopath ) { $_ //= ''; s/\s+\z//; }
	return $gobin if $gobin ne '';
	if ( $gopath ne '' ) {
		my $sep = $Config{path_sep} || ':';
		my ($first) = split /\Q$sep\E/, $gopath;
		return File::Spec->catdir( $first, 'bin' ) if defined $first && $first ne '';
	}
	return undef;
}

# Locate oauth2c: PATH, $GOBIN, ~/go/bin, then the Go toolchain's bin dir.
sub find_oauth2c {
	my ($go) = @_;
	my $p = find_on_path('oauth2c');
	return $p if $p;
	my @dirs;
	push @dirs, $ENV{GOBIN} if defined $ENV{GOBIN} && $ENV{GOBIN} ne '';
	push @dirs, File::Spec->catdir( $ENV{HOME}, 'go', 'bin' ) if defined $ENV{HOME};
	if ( my $gb = go_bin_dir($go) ) { push @dirs, $gb }
	for my $dir (@dirs) {
		my $cand = File::Spec->catfile( $dir, 'oauth2c' );
		return $cand if -x $cand && !-d $cand;
	}
	return undef;
}

# Grab a free TCP port on 127.0.0.1.
sub free_port {
	my $sock = IO::Socket::INET->new(
		LocalAddr => '127.0.0.1',
		LocalPort => 0,
		Listen    => 1,
		Proto     => 'tcp',
	) or die "cannot allocate a local port: $!";
	my $port = $sock->sockport;
	close $sock;
	return $port;
}

sub strip_ansi {
	my ($s) = @_;
	$s //= '';
	$s =~ s/\e\[[0-9;?]*[ -\/]*[@-~]//g;
	return $s;
}

# ── Locate oauth2c (installing it only when explicitly asked) ────────────────

my $go      = find_go();
my $oauth2c = find_oauth2c($go);

if ( !$oauth2c && $ENV{NISABA_TEST_OAUTH2C_INSTALL} ) {
	plan skip_all =>
		"No Go toolchain found to install oauth2c (looked for 'go' and version-suffixed names like go126; set GO=/path/to/go)"
		unless $go;
	diag("Installing oauth2c via: $go install github.com/cloudentity/oauth2c\@latest");
	my ( $inst_exit, $inst_out, $inst_timeout )
		= capture( 300, $go, 'install', 'github.com/cloudentity/oauth2c@latest' );
	diag( strip_ansi($inst_out) )
		unless defined $inst_exit && $inst_exit == 0 && !$inst_timeout;
	$oauth2c = find_oauth2c($go);
}

plan skip_all =>
	'oauth2c not installed; set NISABA_TEST_OAUTH2C_INSTALL=1 to build it with '
	. '`go install github.com/cloudentity/oauth2c@latest` (needs Go and network)'
	unless $oauth2c;

# ── Load the SSO app + storage ───────────────────────────────────────────────

eval { require App::Nisaba::WebSSO };
plan skip_all => "App::Nisaba::WebSSO failed to load: $@" if $@;

eval {
	require App::Nisaba::WebSSO::Storage;
	App::Nisaba::WebSSO::Storage->new( { backend => 'SQLite', path => ':memory:' } );
	1;
} or plan skip_all => "App::Nisaba::WebSSO::Storage unavailable (DBD::SQLite?): $@";

require Mojo::Server::Daemon;
require Mojo::UserAgent;
require Mojo::URL;
require Mojo::JSON;
require Crypt::PK::RSA;

# ── Test fixtures (same shape as t/web-sso.t) ───────────────────────────────

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

my $sso_port     = free_port();
my $cb_port      = free_port();
my $issuer       = "http://127.0.0.1:$sso_port";
my $redirect_url = "http://127.0.0.1:$cb_port/callback";
my $client_id    = 'oauth2capp';
my $client_secret = 'oauth2c-test-secret';

# RS256 signing key for the client so oauth2c gets a properly signed id_token.
my $rsa = Crypt::PK::RSA->new;
$rsa->generate_key( 256, 65537 );    # 2048-bit
my $priv_jwk = Mojo::JSON::decode_json( $rsa->export_key_jwk('private') );
$priv_jwk->{kid} = 'oauth2c-test-kid';
$priv_jwk->{use} = 'sig';
$priv_jwk->{alg} = 'RS256';
my $jwks_json = Mojo::JSON::encode_json( { keys => [$priv_jwk] } );

my $client_entry = FakeEntry->new(
	_dn                          => "oidcClientId=$client_id,ou=oidc,dc=example,dc=com",
	oidcClientId                 => $client_id,
	oidcClientName               => 'oauth2c Test App',
	oidcClientSecret             => $client_secret,
	oidcRedirectURI              => [$redirect_url],
	oidcScope                    => [ 'openid', 'profile', 'email' ],
	oidcGrantType                => ['authorization_code'],
	oidcResponseType             => ['code'],
	oidcApplicationType          => 'web',
	oidcTokenEndpointAuthMethod  => 'client_secret_basic',
	oidcIdTokenSignedResponseAlg => 'RS256',
	oidcJwks                     => $jwks_json,
);

my $usr_alice = FakeEntry->new(
	_dn         => 'uid=alice,ou=users,dc=example,dc=com',
	uid         => 'alice',
	displayName => 'Alice Wonderland',
	givenName   => 'Alice',
	sn          => 'Wonderland',
	mail        => 'alice@example.com',
	objectClass => [ 'posixAccount', 'inetOrgPerson', 'person' ],
);

sub _install_stubs {
	my ($app) = @_;

	my %methods = (
		error                  => sub { 0 },
		errorString            => sub { '' },
		errorblank             => sub { },
		oidcbaseConfigured     => sub { 1 },
		passkeySchemaAvailable => sub { 0 },
		getOIDCClientEntry     => sub {
			my ( $self, $args ) = @_;
			return $client_entry if ( $args->{clientId} // '' ) eq $client_id;
			return undef;
		},
		getOIDCClients     => sub { return [$client_entry] },
		userVerifyPassword => sub {
			my ( $self, $args ) = @_;
			die "bad password\n"
				unless ( $args->{user} // '' ) eq 'alice'
				&& ( $args->{password} // '' ) eq 'correct';
		},
		userSelfInfo => sub { return { totpStatus => 'inactive' } },
		getUserEntry => sub {
			my ( $self, $args ) = @_;
			return $usr_alice if ( $args->{user} // '' ) eq 'alice';
			return undef;
		},
	);

	my $fake_pt = bless {
		ini => {
			'' => {
				ssoIssuer               => $issuer,
				ssoTokenLifetime        => 3600,
				ssoCodeLifetime         => 600,
				passkeyRpId             => '',
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

	my $storage = App::Nisaba::WebSSO::Storage->new( { backend => 'SQLite', path => ':memory:' } );
	no warnings 'redefine';
	$app->helper( sso_storage => sub { $storage } );
}

# ── Child process management ─────────────────────────────────────────────────

my $server_pid;
my $oauth2c_pid;

sub _cleanup_children {
	for my $pid ( $oauth2c_pid, $server_pid ) {
		next unless $pid;
		kill 'TERM', $pid;
	}
	# Give them a moment, then force.
	my $deadline = time() + 5;
	for my $pid ( $oauth2c_pid, $server_pid ) {
		next unless $pid;
		while ( time() < $deadline ) {
			last if waitpid( $pid, WNOHANG ) != 0;
			select( undef, undef, undef, 0.1 );
		}
		kill 'KILL', $pid;
		waitpid( $pid, WNOHANG );
	}
	( $oauth2c_pid, $server_pid ) = ( undef, undef );
}
END { _cleanup_children() }

# ── 1. Boot the SSO provider as a real daemon ───────────────────────────────

$server_pid = fork();
die "fork failed: $!" unless defined $server_pid;
if ( $server_pid == 0 ) {
	# Server child: never run Test::More END blocks — use POSIX::_exit.
	eval {
		my $daemon = Mojo::Server::Daemon->new(
			listen => ["http://127.0.0.1:$sso_port"],
			silent => 1,
		);
		my $app = $daemon->build_app('App::Nisaba::WebSSO');
		$app->log->level('fatal');    # keep request traces out of the TAP stream
		_install_stubs($app);
		$daemon->run;    # blocks
		1;
	} or warn "SSO daemon failed: $@";
	POSIX::_exit(1);
}

# Wait for the daemon to come up: discovery must answer with our issuer.
my $ua = Mojo::UserAgent->new( max_redirects => 0 );
$ua->connect_timeout(5)->request_timeout(10);

my $ready = 0;
my $ready_deadline = time() + 20;
while ( time() < $ready_deadline ) {
	my $tx = $ua->get("$issuer/.well-known/openid-configuration");
	if ( !$tx->error && ( $tx->res->json('/issuer') // '' ) eq $issuer ) {
		$ready = 1;
		last;
	}
	select( undef, undef, undef, 0.2 );
}
ok( $ready, "SSO daemon is up and serving discovery at $issuer" )
	or do { _cleanup_children(); done_testing(); exit 0 };

# ── 2. Launch oauth2c as a real relying party ───────────────────────────────

my $out_fh   = File::Temp->new( TEMPLATE => 'oauth2c-XXXXXX', TMPDIR => 1, SUFFIX => '.out' );
my $out_file = $out_fh->filename;

my @oauth2c_cmd = (
	$oauth2c, $issuer,
	'--client-id',     $client_id,
	'--client-secret', $client_secret,
	'--response-types', 'code',
	'--response-mode',  'query',
	'--grant-type',     'authorization_code',
	'--auth-method',    'client_secret_basic',
	'--scopes',         'openid,profile,email',
	'--redirect-url',   $redirect_url,
	'--callback-addr',  "127.0.0.1:$cb_port",
	'--pkce',
	'--no-browser',
	'--no-prompt',
);
diag( 'Running: ' . join( ' ', @oauth2c_cmd ) );

$oauth2c_pid = fork();
die "fork failed: $!" unless defined $oauth2c_pid;
if ( $oauth2c_pid == 0 ) {
	open STDOUT, '>', $out_file or POSIX::_exit(127);
	open STDERR, '>&', \*STDOUT;
	open STDIN, '<', File::Spec->devnull;
	$ENV{NO_COLOR} = '1';    # keep the output parseable
	exec @oauth2c_cmd or POSIX::_exit(127);
}

# Slurp oauth2c's output so far, ANSI-stripped and de-wrapped (pterm may hard-
# wrap long lines, which would split the authorization URL).
my $read_out = sub {
	open my $fh, '<', $out_file or return '';
	local $/;
	my $raw = <$fh> // '';
	close $fh;
	return strip_ansi($raw);
};

# oauth2c performs discovery, then prints the authorization URL and waits on
# its callback server. Fish the URL out of its output.
my $auth_url;
my $url_deadline = time() + 30;
while ( time() < $url_deadline ) {
	# Bail out early if oauth2c already died (bad flags, discovery failure...).
	if ( waitpid( $oauth2c_pid, WNOHANG ) != 0 ) {
		my $err_out = $read_out->();
		$oauth2c_pid = undef;
		fail('oauth2c exited before printing the authorization URL');
		diag($err_out);
		_cleanup_children();
		done_testing();
		exit 0;
	}
	my $out = $read_out->();
	# De-wrap: a URL split across lines has no blank line in between.
	( my $joined = $out ) =~ s/\n(?=\S)//g;
	for my $candidate ( $out, $joined ) {
		if ( $candidate =~ m{(\Q$issuer\E/authorize\?[^\s'"<>]+)} ) {
			$auth_url = $1;
			last;
		}
	}
	last if $auth_url;
	select( undef, undef, undef, 0.2 );
}
ok( $auth_url, 'oauth2c printed the authorization URL' )
	or do { diag( $read_out->() ); _cleanup_children(); done_testing(); exit 0 };

my $auth_query = Mojo::URL->new($auth_url)->query;
is( $auth_query->param('client_id'), $client_id, 'authorization URL carries our client_id' );
is( $auth_query->param('code_challenge_method'), 'S256', 'oauth2c uses PKCE S256' );
ok( ( $auth_query->param('code_challenge') // '' ) ne '', 'authorization URL carries a code_challenge' );

# ── 3. Play the browser: authorize → login → consent → callback ─────────────

# GET the authorization URL; an unauthenticated session is sent to login.
my $tx = $ua->get($auth_url);
is( $tx->res->code, 302, 'authorize redirects the browser' );
like( $tx->res->headers->location // '', qr{/sso/login}, 'authorize sends the browser to login' );

# Log in (the app's CSRF check requires a same-host Referer on POSTs).
$tx = $ua->post(
	"$issuer/sso/login",
	{ Referer => "$issuer/sso/login" },
	form => { user => 'alice', pass => 'correct' },
);
is( $tx->res->code, 302, 'login POST accepted' );
like( $tx->res->headers->location // '', qr{/sso/consent}, 'login redirects to consent' );

# Consent.
$tx = $ua->post(
	"$issuer/sso/consent",
	{ Referer => "$issuer/sso/consent" },
	form => { decision => 'allow' },
);
is( $tx->res->code, 302, 'consent POST accepted' );
my $cb_url = $tx->res->headers->location // '';
like( $cb_url, qr{^\Q$redirect_url\E\?}, 'consent redirects to the oauth2c callback' );
ok( ( Mojo::URL->new($cb_url)->query->param('code') // '' ) ne '',
	'callback redirect carries an authorization code' );

# Deliver the redirect to oauth2c's callback server; oauth2c then redeems the
# code at our token endpoint (client_secret_basic + PKCE verifier).
$tx = $ua->get($cb_url);
ok( !$tx->error, 'delivered the code to the oauth2c callback server' )
	or diag( 'callback error: ' . ( $tx->error ? $tx->error->{message} : '?' ) );

# ── 4. oauth2c must complete the exchange ───────────────────────────────────

my $oauth2c_status;
my $exit_deadline = time() + 30;
while ( time() < $exit_deadline ) {
	if ( waitpid( $oauth2c_pid, WNOHANG ) != 0 ) {
		$oauth2c_status = $?;
		$oauth2c_pid    = undef;
		last;
	}
	select( undef, undef, undef, 0.2 );
}

my $output = $read_out->();
ok( defined $oauth2c_status, 'oauth2c exited after the callback' )
	or diag($output);
is( ( defined $oauth2c_status ? $oauth2c_status : -1 ), 0, 'oauth2c exited successfully' )
	or diag($output);

like( $output, qr/"access_token"/, 'oauth2c received an access_token' );
like( $output, qr/"id_token"/,     'oauth2c received an id_token' );

# ── 5. Verify the issued id_token like an RP would (bonus, needs Crypt::JWT) ──

SKIP: {
	skip 'Crypt::JWT not installed', 4 unless eval { require Crypt::JWT; 1 };

	# De-wrap before extracting: the id_token JWT is long enough to hard-wrap.
	( my $joined = $output ) =~ s/\n(?=\S)//g;
	my ($id_token) = $joined =~ /"id_token"\s*:\s*"([A-Za-z0-9_.-]+)"/;
	skip 'could not extract id_token from oauth2c output', 4 unless $id_token;

	my $jwks_tx = $ua->get("$issuer/jwks");
	skip 'could not fetch JWKS', 4 if $jwks_tx->error;

	my $claims = eval {
		Crypt::JWT::decode_jwt(
			token        => $id_token,
			kid_keys     => $jwks_tx->res->json,
			accepted_alg => 'RS256',
			verify_iss   => sub { $_[0] eq $issuer },
			verify_aud   => sub { $_[0] eq $client_id },
		);
	};
	ok( !$@, 'id_token issued to oauth2c verifies against the published JWKS' )
		or diag("decode_jwt failed: $@");
	is( $claims->{sub},   'alice',             'id_token sub is the logged-in user' );
	is( $claims->{email}, 'alice@example.com', 'id_token carries the email claim' );
	is( $claims->{name},  'Alice Wonderland',  'id_token carries the profile name claim' );
}

_cleanup_children();
done_testing;
