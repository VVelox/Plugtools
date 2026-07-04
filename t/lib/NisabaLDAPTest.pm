package NisabaLDAPTest;

# Shared harness for testing App::Nisaba against an in-memory LDAP server
# (Net::LDAP::Server::Test). Used by the t/ldap-*.t tests.
#
# Hard-won gotchas this module encapsulates:
#
#   * Net::LDAP::Server must be required explicitly: Net::LDAP::Server::Test's
#     inline server package loads it via `use base`, which silently tolerates
#     the module being absent — the forked server then dies on the first
#     connection and every later LDAP call blocks forever.
#
#   * The server is handed an already-listening IPv4 socket rather than a port
#     number: given a bare port, Net::LDAP::Server::Test may bind via
#     IO::Socket::INET6 on '::' (unreachable from 127.0.0.1 on systems where
#     IPv6 sockets are v6-only by default, e.g. FreeBSD). Pre-binding also
#     avoids a free-port race.
#
#   * App::Nisaba::connect() opens a NEW connection for every method call and
#     never unbinds. The test server's forked child exits as soon as its last
#     open connection closes, so setup() holds one "anchor" connection open
#     for the lifetime of the environment to keep the server alive between
#     App::Nisaba's short-lived per-call connections.
#
#   * App::Nisaba is constructed with all_errors_fatal, so errors die() as
#     well as setting the error code. pt_try() wraps calls the same way the
#     web controllers do.
#
#   * The stock test server accepts ANY bind (its bind() is literally
#     `return RESULT_OK`), which would make wrong-password tests pass
#     falsely. setup() replaces the inline server package's bind() BEFORE the
#     server forks (the child inherits the compiled override) with one that
#     verifies simple binds against the stored userPassword — see
#     _install_bind_verification() for the exact policy.

use strict;
use warnings;
use File::Spec;
use File::Temp ();
use IO::Socket::INET;

# Build a test environment. Returns ( $env, undef ) on success or
# ( undef, $skip_reason ) when a prerequisite is missing — callers turn the
# reason into plan skip_all.
#
# $env is a hashref: { pt, server, anchor, port, config }.
#
# Options:
#   ini => { key => value, ... }   extra/overriding config keys
sub setup {
	my (%opts) = @_;

	eval { require Net::LDAP::Server; require Net::LDAP::Server::Test; 1 }
		or return ( undef, "Net::LDAP::Server::Test not usable: $@" );
	eval { require Net::LDAP; require App::Nisaba; 1 }
		or return ( undef, "App::Nisaba failed to load: $@" );

	_install_bind_verification();

	my $listen = IO::Socket::INET->new(
		LocalAddr => '127.0.0.1',
		LocalPort => 0,
		Listen    => 5,
		Proto     => 'tcp',
		Reuse     => 1,
	) or return ( undef, "cannot allocate a local listening socket: $!" );
	my $port = $listen->sockport;

	my $server = eval { Net::LDAP::Server::Test->new( $listen, auto_schema => 1 ) };
	return ( undef, "could not spawn test LDAP server: $@" ) unless $server;

	my $anchor = Net::LDAP->new( '127.0.0.1', port => $port );
	unless ($anchor) {
		$server->stop;
		return ( undef, 'could not connect to the test LDAP server' );
	}
	$anchor->bind;

	# Config safety: NSScheck off (LDAP-only), createHome/removeHome off so no
	# cp/chown/rm ever touches the filesystem during tests.
	my %ini = (
		server       => '127.0.0.1',
		port         => $port,
		bind         => 'cn=admin,dc=example,dc=com',
		pass         => 'testpass',
		userbase     => 'ou=users,dc=example,dc=com',
		groupbase    => 'ou=groups,dc=example,dc=com',
		oidcbase     => 'ou=oidc,dc=example,dc=com',
		netgroupbase => 'ou=netgroup,dc=example,dc=com',
		NSScheck     => 0,
		createHome   => 0,
		removeHome   => 0,
		%{ $opts{ini} // {} },
	);

	my $config = File::Temp->new( TEMPLATE => 'nisabarc-XXXXXX', TMPDIR => 1 );
	for my $key ( sort keys %ini ) {
		print $config "$key=$ini{$key}\n";
	}
	close $config;

	my $pt = eval { App::Nisaba->new( { config => $config->filename } ) };
	unless ($pt) {
		$server->stop;
		return ( undef, "App::Nisaba->new failed: $@" );
	}

	return (
		{
			pt     => $pt,
			server => $server,
			anchor => $anchor,
			port   => $port,
			config => $config,    # keep the File::Temp object alive
		},
		undef
	);
} ## end sub setup

# Eval-wrapped pt call, mirroring how the web controllers wrap the pt layer.
# Returns ( $return_value, $error_string ); $error_string is '' on success.
# Error::Helper's warn() chatter is swallowed for the duration of the call by
# pointing STDERR at the null device ($SIG{__WARN__} is not enough — the
# messages are printed to STDERR directly, not raised via warn()). Expected-
# error tests assert on the returned error string, so the stderr copy is just
# noise.
sub pt_try {
	my ( $pt, $code ) = @_;
	open my $saved_stderr, '>&', \*STDERR or die "cannot dup STDERR: $!";
	open STDERR, '>', File::Spec->devnull;
	my $ret = eval { $code->() };
	open STDERR, '>&', $saved_stderr;
	close $saved_stderr;
	if ($@) {
		my $err = $@;
		$err =~ s/\s+\z//;
		return ( undef, $err );
	}
	if ( $pt->error ) {
		return ( $ret, $pt->errorString || ( 'Error code ' . $pt->error ) );
	}
	return ( $ret, '' );
}

# Replace the test server's accept-everything bind() with one that verifies
# simple binds against the in-memory entry data, so userVerifyPassword-style
# code is actually testable. Policy:
#
#   * anonymous binds (no DN) and binds as DNs NOT stored in the server
#     (e.g. the configured admin bind DN, which exists only in the config)
#     are accepted — App::Nisaba's connect() and the anchor keep working;
#   * binds as a stored DN succeed only when the supplied simple password
#     equals the entry's userPassword (plaintext compare — hashed schemes are
#     out of scope for the test server);
#   * a stored DN with no userPassword, a wrong password, or a non-simple
#     authentication choice fails with invalidCredentials (49).
#
# The override targets the inline 'MyLDAPServer' package inside
# Net::LDAP::Server::Test and must be installed before new() forks the server
# child; the child inherits the redefined sub. %MyLDAPServer::Data is the
# child's entry store keyed by DN.
sub _install_bind_verification {
	require Net::LDAP::Constant;
	my $invalid = {
		matchedDN    => '',
		errorMessage => 'invalid credentials',
		resultCode   => Net::LDAP::Constant::LDAP_INVALID_CREDENTIALS(),
	};
	my $ok = {
		matchedDN    => '',
		errorMessage => '',
		resultCode   => Net::LDAP::Constant::LDAP_SUCCESS(),
	};

	no warnings 'redefine';
	*MyLDAPServer::bind = sub {
		my ( $self, $reqData ) = @_;

		my $dn = $reqData->{name} // '';
		return $ok if $dn eq '';    # anonymous

		# Look the DN up in the server's entry store (exact, then
		# case-insensitive — DNs are case-insensitive in LDAP).
		my $entry = $MyLDAPServer::Data{$dn};
		if ( !$entry ) {
			my ($key) = grep { lc($_) eq lc($dn) } keys %MyLDAPServer::Data;
			$entry = $MyLDAPServer::Data{$key} if defined $key;
		}

		# DNs that are not stored entries (the configured admin bind DN)
		# are accepted, mirroring how the tests treat the service account.
		return $ok unless $entry;

		my $auth = $reqData->{authentication};
		return $invalid unless ref $auth eq 'HASH' && defined $auth->{simple};

		my $stored = $entry->get_value('userPassword');
		return $invalid unless defined $stored && $stored ne '';
		return $auth->{simple} eq $stored ? $ok : $invalid;
	};
} ## end sub _install_bind_verification

sub teardown {
	my ($env) = @_;
	return unless $env;
	eval { $env->{anchor}->unbind } if $env->{anchor};
	eval { $env->{server}->stop }   if $env->{server};
}

1;
