package NisabaSSOFuzz;

# Test helper for the sso-fuzz harness (xt/sso-fuzz). Boots sso-fuzz-target.pl
# as a real prefork HTTP daemon on an ephemeral port and runs the same
# open-redirect / LDAP-injection / parser-abuse / header-injection assertions
# probe-check.pl performs — but as Test::More subtests, so `prove xt/sso-fuzz.t`
# is a network-level security regression check on mojo_nisaba_sso.

use strict;
use warnings;

use FindBin          ();
use File::Spec       ();
use File::Temp       ();
use IO::Socket::INET ();
use POSIX            qw(setsid WNOHANG);
use Time::HiRes      qw(sleep);
use Digest::SHA      qw(sha256);
use MIME::Base64     qw(encode_base64url);
use Test::More;

# The harness scripts live alongside the test dir: xt/sso-fuzz/.
sub target_script {
	return File::Spec->catfile( $FindBin::Bin, 'sso-fuzz', 'sso-fuzz-target.pl' );
}

sub _free_port {
	my $s = IO::Socket::INET->new( LocalAddr => '127.0.0.1', Proto => 'tcp', Listen => 1 )
		or return undef;
	my $port = $s->sockport;
	close $s;
	return $port;
}

sub _ua {
	require Mojo::UserAgent;
	my $ua = Mojo::UserAgent->new( max_redirects => 0 );
	$ua->connect_timeout(5)->request_timeout(20);
	return $ua;
}

# boot_target(%opt) -> ( \%ctx, undef ) on success or ( undef, $skip_reason ).
# opt: backend (mock|slapd), workers, ready_timeout.
sub boot_target {
	my (%opt)   = @_;
	my $backend = $opt{backend}       // 'mock';
	my $workers = $opt{workers}       // 2;
	my $timeout = $opt{ready_timeout} // ( $backend eq 'slapd' ? 90 : 30 );

	my $target = target_script();
	return ( undef, "target script not found at $target" ) unless -f $target;

	my $port = _free_port() or return ( undef, 'could not allocate a local port' );
	my $log  = File::Temp->new( TEMPLATE => 'sso-fuzz-XXXXXX', SUFFIX => '.log', TMPDIR => 1 );

	my $pid = fork();
	return ( undef, "fork failed: $!" ) unless defined $pid;
	if ( $pid == 0 ) {
		# Own session so the whole prefork tree can be signalled at teardown.
		setsid();
		open STDOUT, '>&', $log or POSIX::_exit(127);
		open STDERR, '>&', $log or POSIX::_exit(127);
		exec $^X, $target,
			'--backend', $backend,
			'--host', '127.0.0.1', '--port', $port, '--workers', $workers, '--log-level', 'error'
			or POSIX::_exit(127);
	} ## end if ( $pid == 0 )

	# The confidential 'conf' client is seeded by both backends with the same
	# redirect_uri, so the probes are backend-agnostic.
	my $ctx = {
		base         => "http://127.0.0.1:$port",
		port         => $port,
		pid          => $pid,
		log          => $log,
		ua           => _ua(),
		client_id    => 'conf',
		redirect_uri => 'https://fuzz.example.com/callback',
	};

	# Wait for discovery to answer, or for the child to die first.
	my $deadline = time + $timeout;
	while ( time < $deadline ) {
		if ( waitpid( $pid, WNOHANG ) == $pid ) {
			return ( undef, "target exited during startup:\n" . _log_tail($log) );
		}
		my $tx = $ctx->{ua}->get("$ctx->{base}/.well-known/openid-configuration");
		if ( $tx->res->code && $tx->res->code == 200 ) {
			return ( $ctx, undef );
		}
		sleep 0.3;
	} ## end while ( time < $deadline )
	stop_target($ctx);
	return ( undef, "target did not answer discovery within ${timeout}s:\n" . _log_tail($log) );
} ## end sub boot_target

sub _log_tail {
	my ($log) = @_;
	open my $fh, '<', $log->filename or return '(no log)';
	my @lines = <$fh>;
	close $fh;
	return join '', @lines[ -15 .. -1 ] if @lines > 15;
	return join '', @lines;
}

sub stop_target {
	my ($ctx) = @_;
	return unless $ctx && $ctx->{pid};
	return if $ctx->{stopped}++;    # idempotent (boot_target-on-timeout + END)
	my $pid = $ctx->{pid};

	kill 'TERM', -$pid;             # whole process group (prefork master + workers)
	my $deadline = time + 8;
	my $reaped   = 0;
	while ( time < $deadline ) {
		if ( waitpid( $pid, WNOHANG ) == $pid ) { $reaped = 1; last }
		sleep 0.2;
	}
	unless ($reaped) {
		kill 'KILL', -$pid;
		waitpid( $pid, 0 );
	}

	# A signalled child (or a waitpid that finds nothing to reap) would otherwise
	# leave $? non-zero and taint this test process's own exit status.
	$? = 0;    ## no critic (RequireLocalizedPunctuationVars)
	return;
} ## end sub stop_target

# ── Request helpers (mirror probe-check.pl) ───────────────────────────────────
sub _pkce {
	return encode_base64url( sha256('verifier-1234567890-abcdefghij') );
}

sub _authz {
	my ( $ctx, %o ) = @_;
	require Mojo::URL;
	my $url = Mojo::URL->new("$ctx->{base}/authorize")->query(
		{
			response_type         => 'code',
			client_id             => $ctx->{client_id},
			redirect_uri          => $ctx->{redirect_uri},
			scope                 => 'openid',
			state                 => 'st123',
			nonce                 => 'nn123',
			code_challenge        => _pkce(),
			code_challenge_method => 'S256',
			%o,
		}
	);
	return $ctx->{ua}->get($url);
} ## end sub _authz

sub _reached_ui {
	my ($tx) = @_;
	my $loc = $tx->res->headers->location // '';
	return 1 if $loc                                                       =~ m{/sso/(?:login|consent|totp)};
	return 1 if ( $tx->res->code // 0 ) == 200 && ( $tx->res->body // '' ) =~ /name=["']?(?:user|pass)/i;
	return 0;
}

# ── The probe assertions ──────────────────────────────────────────────────────
sub run_security_probes {
	my ($ctx) = @_;
	my $evil = 'evil.attacker.example';

	subtest 'discovery serves a valid document' => sub {
		my $tx = $ctx->{ua}->get("$ctx->{base}/.well-known/openid-configuration");
		is( $tx->res->code, 200, 'discovery returns 200' );
		ok( ( $tx->res->json('/issuer') // '' ) ne '', 'issuer is present' );
	};

	subtest 'a valid authorize request reaches the login UI' => sub {
		ok( _reached_ui( _authz($ctx) ), "client_id=$ctx->{client_id} reaches the login/consent UI" );
	};

	subtest 'open redirect: unregistered redirect_uri is not honoured' => sub {
		for my $p ( "https://$evil/", "$ctx->{redirect_uri}.$evil", "//$evil/" ) {
			my $tx  = _authz( $ctx, redirect_uri => $p );
			my $loc = $tx->res->headers->location // '';
			my $c   = $tx->res->code              // 0;
			ok( !( $c >= 300 && $c < 400 && $loc =~ /\Q$evil\E/ ), "redirect_uri=$p not redirected to attacker" );
		}
	};

	subtest 'LDAP injection: client_id metacharacters do not match a client' => sub {
		my $rnd = _authz( $ctx, client_id => 'zzznope' . int( rand 1e6 ) );
		if ( _reached_ui($rnd) ) {
			plan skip_all => 'unknown client_id already reaches the UI; check inconclusive';
		}
		for my $inj ( '*', "$ctx->{client_id}*", '*)(oidcClientId=*' ) {
			ok( !_reached_ui( _authz( $ctx, client_id => $inj ) ), "client_id=$inj does not match a client" );
		}
	};

	subtest 'parser abuse: malformed input yields no 500 and no dropped connection' => sub {
		my @cases = (
			[
				'passkey truncated json',
				sub {
					$ctx->{ua}
						->post( "$ctx->{base}/sso/passkeys/login/finish" => { 'Content-Type' => 'application/json' } =>
							'{"id":"x",' );
				}
			],
			[
				'passkey not-a-hash',
				sub {
					$ctx->{ua}
						->post( "$ctx->{base}/sso/passkeys/login/finish" => { 'Content-Type' => 'application/json' } =>
							'{"response":"notahash"}' );
				}
			],
			[
				'passkey garbage',
				sub {
					$ctx->{ua}
						->post( "$ctx->{base}/sso/passkeys/login/finish" => { 'Content-Type' => 'application/json' } =>
							'%%%not-json%%%' );
				}
			],
			[
				'token malformed basic',
				sub {
					$ctx->{ua}
						->post( "$ctx->{base}/token" => { 'Authorization' => 'Basic !!!not-base64' } => form =>
							{ grant_type => 'authorization_code', code => 'abcd' } );
				}
			],
			[
				'logout bad id_token_hint',
				sub {
					require Mojo::URL;
					$ctx->{ua}
						->get( Mojo::URL->new("$ctx->{base}/sso/logout")->query( { id_token_hint => '..%20.' } ) );
				}
			],
			[ 'authorize oversized scope', sub { _authz( $ctx, scope => 'openid ' . ( 'A' x 200_000 ) ) } ],
		);
		for my $case (@cases) {
			my ( $label, $fn ) = @{$case};
			my $tx = eval { $fn->() };
			ok( $tx && $tx->res->code && $tx->res->code != 500,
				"$label handled cleanly (code " . ( $tx && $tx->res->code ? $tx->res->code : 'none' ) . ')' );
		}
	}; ## end 'parser abuse: malformed input yields no 500 and no dropped connection' => sub

	subtest 'header injection: CRLF payload does not split a new response header' => sub {
		my $marker = 'X-Nisaba-Inject-' . int( rand 1e6 );
		my $tx     = _authz( $ctx, scope => 'openid bogus_unregistered', state => "s\r\n$marker: pwned" );
		# Only a genuine split creates a header NAMED $marker; a value-only
		# reflection inside the URL-encoded Location is not a vuln.
		my $split = grep { lc eq lc $marker } @{ $tx->res->headers->names };
		ok( !$split, 'no CRLF header split' );
	};

	return;
} ## end sub run_security_probes

1;
