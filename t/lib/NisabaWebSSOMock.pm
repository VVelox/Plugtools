package NisabaWebSSOMock;

# Pure-Perl mock harness for App::Nisaba::WebSSO — no slapd, no external tools.
# Provides the fake-LDAP stubs shared by the in-process robustness tests, plus a
# helper to boot the app as a real prefork daemon on an ephemeral port (for the
# out-of-process worker-survival test). Everything here is Perl + Mojolicious +
# DBD::SQLite, so it can live under t/ and run in the default suite.
#
#   install_stubs($app, storage => $obj)   install fake pt/storage/csrf on an app
#   boot_daemon(workers => 2)              fork a real mock daemon, returns \%ctx
#   stop_daemon($ctx)                      signal + reap the daemon's process group
#
# Seeds one confidential client (secretapp / s3cret, client_secret_basic, HS256)
# and one user (alice / correct). Throwaway values — test-only.

use strict;
use warnings;

use File::Spec       ();
use File::Temp       ();
use IO::Socket::INET ();
use Mojo::Util       ();

our $CLIENT_ID     = 'secretapp';
our $CLIENT_SECRET = 's3cret';
our $REDIRECT_URI  = 'https://secretapp.example.com/callback';
our $USER          = 'alice';
our $PASSWORD      = 'correct';

# ── Fake Net::LDAP::Entry ─────────────────────────────────────────────────────
{

	package NisabaWebSSOMock::Entry;

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

sub _client {
	return NisabaWebSSOMock::Entry->new(
		_dn                          => "oidcClientId=$CLIENT_ID,ou=oidc,dc=example,dc=com",
		oidcClientId                 => $CLIENT_ID,
		oidcClientSecret             => $CLIENT_SECRET,
		oidcIdTokenSignedResponseAlg => 'HS256',
		oidcRedirectURI              => [$REDIRECT_URI],
		oidcScope                    => [ 'openid', 'profile' ],
		oidcGrantType                => ['authorization_code'],
		oidcResponseType             => ['code'],
		oidcTokenEndpointAuthMethod  => 'client_secret_basic',
	);
} ## end sub _client

sub _user {
	return NisabaWebSSOMock::Entry->new(
		_dn         => "uid=$USER,ou=users,dc=example,dc=com",
		uid         => $USER,
		displayName => 'Alice Wonderland',
		mail        => 'alice@example.com',
		objectClass => [ 'posixAccount', 'inetOrgPerson', 'person' ],
	);
}

# install_stubs($app, %opt) — patch the pt/storage helpers with the mock backend.
# opt: storage => $obj (shared store; otherwise a per-process :memory: store).
sub install_stubs {
	my ( $app, %opt ) = @_;
	require App::Nisaba::WebSSO::Storage;

	my $client = _client();
	my $user   = _user();

	my %methods = (
		error                  => sub { 0 },
		errorString            => sub { '' },
		errorblank             => sub { },
		oidcbaseConfigured     => sub { 1 },
		passkeySchemaAvailable => sub { 0 },
		getOIDCClientEntry     => sub {
			my ( $self, $args ) = @_;
			return $client if ( $args->{clientId} // '' ) eq $CLIENT_ID;
			return undef;
		},
		getOIDCClients     => sub { return [$client] },
		userVerifyPassword => sub {
			my ( $self, $args ) = @_;
			die "bad password\n"
				unless ( $args->{user} // '' ) eq $USER && ( $args->{password} // '' ) eq $PASSWORD;
			return 1;
		},
		userSelfInfo => sub { return { totpStatus => 'inactive' } },
		getUserEntry => sub {
			my ( $self, $args ) = @_;
			return $user if ( $args->{user} // '' ) eq $USER;
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
		'NisabaWebSSOMock::PT';
	Mojo::Util::monkey_patch( 'NisabaWebSSOMock::PT', %methods );
	$app->helper( pt => sub { $fake_pt } );

	no warnings 'redefine';
	if ( my $storage = $opt{storage} ) {
		$app->helper( sso_storage => sub { $storage } );
	} else {
		# Lazily opened per process so forked prefork workers each get their own
		# handle (never share a DBI/SQLite connection across a fork).
		my %by_pid;
		$app->helper(
			sso_storage => sub {
				return $by_pid{$$} //=
					App::Nisaba::WebSSO::Storage->new( { backend => 'SQLite', path => ':memory:' } );
			}
		);
	} ## end else [ if ( my $storage = $opt{storage} ) ]

	$app->hook( before_dispatch => sub { $_[0]->session( csrf_token => 'testcsrf' ) } );
	return;
} ## end sub install_stubs

# ── Real prefork daemon (for the out-of-process survival test) ────────────────
sub _free_port {
	my $s = IO::Socket::INET->new( LocalAddr => '127.0.0.1', Proto => 'tcp', Listen => 1 )
		or return undef;
	my $port = $s->sockport;
	close $s;
	return $port;
}

# boot_daemon(%opt) -> ( \%ctx, undef ) | ( undef, $reason ). opt: workers.
sub boot_daemon {
	my (%opt) = @_;
	my $workers = $opt{workers} // 2;

	require POSIX;
	require Time::HiRes;
	require Mojo::Server::Prefork;
	require Mojo::UserAgent;

	my $port = _free_port() or return ( undef, 'could not allocate a local port' );
	my $log  = File::Temp->new( TEMPLATE => 'websso-mock-XXXXXX', SUFFIX => '.log', TMPDIR => 1 );

	my $pid = fork();
	return ( undef, "fork failed: $!" ) unless defined $pid;
	if ( $pid == 0 ) {
		# Own session so the whole prefork tree can be signalled at teardown.
		POSIX::setsid();
		open STDOUT, '>&', $log or POSIX::_exit(127);
		open STDERR, '>&', $log or POSIX::_exit(127);
		eval {
			my $prefork = Mojo::Server::Prefork->new( listen => ["http://127.0.0.1:$port"], silent => 1 );
			$prefork->workers($workers);
			my $app = $prefork->build_app('App::Nisaba::WebSSO');
			$app->log->level('fatal');
			install_stubs($app);
			$prefork->run;
			1;
		} or warn "mock daemon failed: $@";
		POSIX::_exit(0);
	} ## end if ( $pid == 0 )

	my $ua = Mojo::UserAgent->new( max_redirects => 0 );
	$ua->connect_timeout(5)->request_timeout(10);
	my $base = "http://127.0.0.1:$port";

	my $deadline = time + 30;
	while ( time < $deadline ) {
		if ( waitpid( $pid, POSIX::WNOHANG() ) == $pid ) {
			return ( undef, 'daemon exited during startup: ' . _log_tail($log) );
		}
		my $tx = $ua->get("$base/.well-known/openid-configuration");
		if ( $tx->res->code && $tx->res->code == 200 ) {
			return ( { base => $base, port => $port, pid => $pid, ua => $ua, log => $log }, undef );
		}
		Time::HiRes::sleep(0.2);
	} ## end while ( time < $deadline )
	stop_daemon( { pid => $pid } );
	return ( undef, 'daemon did not answer discovery within 30s: ' . _log_tail($log) );
} ## end sub boot_daemon

sub _log_tail {
	my ($log) = @_;
	open my $fh, '<', $log->filename or return '(no log)';
	my @lines = <$fh>;
	close $fh;
	return join ' | ', map { chomp; $_ } ( @lines > 8 ? @lines[ -8 .. -1 ] : @lines );
}

sub stop_daemon {
	my ($ctx) = @_;
	return unless $ctx && $ctx->{pid};
	require POSIX;
	require Time::HiRes;
	my $pid = $ctx->{pid};

	kill 'TERM', -$pid;
	my $deadline = time + 8;
	my $reaped   = 0;
	while ( time < $deadline ) {
		if ( waitpid( $pid, POSIX::WNOHANG() ) == $pid ) { $reaped = 1; last }
		Time::HiRes::sleep(0.2);
	}
	unless ($reaped) {
		kill 'KILL', -$pid;
		waitpid( $pid, 0 );
	}
	# A signalled child would otherwise taint this test process's exit status.
	$? = 0;    ## no critic (RequireLocalizedPunctuationVars)
	return;
} ## end sub stop_daemon

1;
