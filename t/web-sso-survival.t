#!perl
use strict;
use warnings;

# Out-of-process worker-survival test for App::Nisaba::WebSSO. Boots the app as a
# real multi-worker prefork daemon (pure Perl, mock LDAP) on an ephemeral port,
# fires a fixed corpus of malformed/abuse requests, and asserts:
#
#   * every request got a response  — a worker did not die mid-request (a crash
#     would drop the connection and yield no response),
#   * none was HTTP 500,
#   * none hung (bounded by the client request-timeout),
#   * discovery still answers afterward — the daemon as a whole survived.
#
# This is the deterministic, dependency-free (no slapd, no /proc, no supervisor)
# distillation of the xt/sso-fuzz harness: the one thing in-process Test::Mojo
# cannot see is an actual worker *process* death, which this catches.

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
	$ENV{NISABA_REQUIRE_PKCE}  = '0'                  unless defined $ENV{NISABA_REQUIRE_PKCE};
	$ENV{NISABA_RATELIMIT}     = '0'                  unless defined $ENV{NISABA_RATELIMIT};
} ## end BEGIN

use Test::More;
use Mojo::URL ();
use FindBin   ();
use lib "$FindBin::Bin/lib";

eval { require App::Nisaba::WebSSO; 1 } or plan skip_all => "App::Nisaba::WebSSO failed to load: $@";
eval {
	require App::Nisaba::WebSSO::Storage;
	App::Nisaba::WebSSO::Storage->new( { backend => 'SQLite', path => ':memory:' } );
	1;
} or plan skip_all => "App::Nisaba::WebSSO::Storage unavailable (DBD::SQLite?): $@";
eval { require Mojo::Server::Prefork; require Mojo::UserAgent; 1 }
	or plan skip_all => "Mojo prefork/UA unavailable: $@";

# Needs fork + a POSIX process group; skip where unavailable (e.g. Windows).
plan skip_all => 'fork() not available on this platform'
	unless eval { require POSIX; my $p = fork(); defined $p or die; POSIX::_exit(0) if $p == 0; waitpid( $p, 0 ); 1 };

use NisabaWebSSOMock;

my ( $ctx, $err ) = NisabaWebSSOMock::boot_daemon( workers => 2 );
plan skip_all => "could not boot mock daemon: $err" unless $ctx;
diag("mock survival daemon up at $ctx->{base} (pid $ctx->{pid})");
END { NisabaWebSSOMock::stop_daemon($ctx) if $ctx }

# Overall watchdog so a fully wedged daemon can't hang the whole run.
alarm(120);
local $SIG{ALRM} = sub { die "survival test watchdog expired\n" };

my $ua   = $ctx->{ua};
my $base = $ctx->{base};
$ua->request_timeout(10);    # a hung worker surfaces as a timeout (no code)

my $cid   = $NisabaWebSSOMock::CLIENT_ID;
my $reg   = $NisabaWebSSOMock::REDIRECT_URI;
my $basic = 'Basic ' . Mojo::Util::b64_encode( "$cid:$NisabaWebSSOMock::CLIENT_SECRET", '' );
my $huge  = 'A' x 200_000;

sub authz_url {
	my (%o) = @_;
	return Mojo::URL->new("$base/authorize")
		->query( { response_type => 'code', client_id => $cid, redirect_uri => $reg, scope => 'openid', %o } );
}

# Fixed corpus: (description, coderef returning a transaction).
my @corpus = (
	[ 'authorize: oversized scope',    sub { $ua->get( authz_url( scope         => "openid $huge" ) ) } ],
	[ 'authorize: junk response_type', sub { $ua->get( authz_url( response_type => "\x00\x01" ) ) } ],
	[ 'authorize: bad redirect_uri',   sub { $ua->get( authz_url( redirect_uri  => "https://evil.example.com/" ) ) } ],
	[ 'authorize: CRLF in state',      sub { $ua->get( authz_url( scope => 'openid nope', state => "s\r\nX: y" ) ) } ],
	[
		'token: malformed Basic auth',
		sub {
			$ua->post(
				"$base/token",
				{ Authorization => 'Basic !!!' },
				form => { grant_type => 'authorization_code', code => 'x' }
			);
		} ## end sub
	],
	[
		'token: oversized code',
		sub {
			$ua->post(
				"$base/token",
				{ Authorization => $basic },
				form => { grant_type => 'authorization_code', code => $huge }
			);
		} ## end sub
	],
	[
		'token: junk grant_type',
		sub { $ua->post( "$base/token", { Authorization => $basic }, form => { grant_type => "weird\x00" } ) }
	],
	[ 'userinfo: malformed Bearer', sub { $ua->get( "$base/userinfo", { Authorization => 'Bearer ..nope..' } ) } ],
	[
		'revoke: garbage token',
		sub { $ua->post( "$base/revoke", { Authorization => $basic }, form => { token => "\x00\xff x" } ) }
	],
	[
		'introspect: oversized token',
		sub { $ua->post( "$base/introspect", { Authorization => $basic }, form => { token => $huge } ) }
	],
	[
		'logout: malformed id_token_hint',
		sub { $ua->get( Mojo::URL->new("$base/sso/logout")->query( { id_token_hint => 'a.b.c' } ) ) }
	],
	[
		'passkey finish: truncated JSON',
		sub {
			$ua->post( "$base/sso/passkeys/login/finish", { 'Content-Type' => 'application/json' }, '{"id":"x",' );
		} ## end sub
	],
	[
		'passkey finish: nested JSON',
		sub {
			$ua->post(
				"$base/sso/passkeys/login/finish",
				{ 'Content-Type' => 'application/json' },
				( '[' x 3000 ) . '1' . ( ']' x 3000 )
			);
		} ## end sub
	],
);

for my $case (@corpus) {
	my ( $desc, $fn ) = @{$case};
	my $tx   = $fn->();
	my $code = $tx->res->code;
	# No code => connection dropped or timed out => a worker crashed or hung.
	ok( defined $code && $code != 500,
		"$desc: worker survived and answered (HTTP " . ( defined $code ? $code : 'NO RESPONSE' ) . ')' );
}

# After the whole battery the daemon must still be serving.
my $tx = $ua->get("$base/.well-known/openid-configuration");
is( $tx->res->code, 200, 'daemon still answers discovery after the malformed-request battery' );

done_testing;
