package App::Nisaba::WebUtil;

use strict;
use warnings;
use Exporter 'import';
use Mojo::Util                        ();
use App::Nisaba::WebUtil::RateLimiter ();

our @EXPORT_OK = qw(secure_compare);

=head1 NAME

App::Nisaba::WebUtil - small shared security helpers for the Nisaba web apps

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 FUNCTIONS

=head2 secure_compare

    secure_compare( $a, $b )  or  die "mismatch";

Constant-time string comparison. Returns true when C<$a> and C<$b> are equal.
Unlike C<eq>, the time taken does not depend on how many leading characters
match, so it cannot be used as an oracle to recover a secret one character at a
time. Use it whenever one operand is a secret or a MAC/signature (client
secrets, HMACs, tokens).

The length of C<$a> is compared to C<$b> up front, which is standard practice
(e.g. Rails' C<secure_compare>); only the per-character comparison needs to be
constant time. The comparison itself is delegated to
L<Mojo::Util/secure_compare>; this wrapper adds tolerance of C<undef> operands.

=cut

sub secure_compare {
	my ( $x, $y ) = @_;
	return 0 unless defined $x && defined $y;
	return Mojo::Util::secure_compare( $x, $y ) ? 1 : 0;
}

# --------------------------------------------------------------------------- #
# Rate limiting
# --------------------------------------------------------------------------- #

=head2 install_rate_limiter

    App::Nisaba::WebUtil::install_rate_limiter($app);

Installs brute-force rate limiting on a Mojolicious app. Adds a lazily-built,
shared L<App::Nisaba::WebUtil::RateLimiter> (config is read from the app's
C<pt> helper on first use) plus controller helpers:

=over 4

=item * C<< $c->rate_guard($scope, %opts) >> - checks the limit and, if blocked,
renders a 429 (or 503 when the limiter DB is unavailable) and returns false;
returns true when the request may proceed. Pass C<< render => {...} >> with the
form template to re-render on a block, or C<< render => { json => 1 } >>, and
C<< hit => 1 >> for request-rate scopes.

=item * C<< $c->rate_fail($scope, %opts) >> - record a failed attempt.

=item * C<< $c->rate_reset($scope, %opts) >> - clear on success (the IP backstop
is intentionally not cleared).

=item * C<< $c->rate_check / $c->rate_hit >> - the underlying evaluators.

=back

C<%opts> carries the key parts, e.g. C<< user => $user >>; the client IP is
taken from C<< $c->tx->remote_address >>. When rate limiting is disabled
(C<rateLimit=0>) all helpers allow. When it is enabled but the store cannot be
opened, guarded endpoints fail B<closed>.

=cut

# scope => ordered list of sub-limits. 'backstop' sub-limits (the per-IP one)
# are not cleared on success so a single valid credential can't reset them.
my %SCOPE_KEYS = (
	login =>
		[ { scope => 'login', parts => [ 'user', 'ip' ] }, { scope => 'login_ip', parts => ['ip'], backstop => 1 } ],
	totp =>
		[ { scope => 'totp', parts => [ 'user', 'ip' ] }, { scope => 'totp_ip', parts => ['ip'], backstop => 1 } ],
	forgot =>
		[ { scope => 'forgot', parts => [ 'user', 'ip' ] }, { scope => 'forgot_ip', parts => ['ip'], backstop => 1 } ],
	passkey => [ { scope => 'passkey', parts => ['ip'] } ],
	reset   => [ { scope => 'reset',   parts => ['ip'] } ],
	token   =>
		[ { scope => 'token', parts => [ 'user', 'ip' ] }, { scope => 'token_ip', parts => ['ip'], backstop => 1 } ],
);

# Built-in defaults; every value is overridable in the config (see below).
my %DEFAULT_POLICIES = (
	login     => { max => 8,   window => 900,  lockout => 900 },
	login_ip  => { max => 50,  window => 900,  lockout => 1800 },
	totp      => { max => 5,   window => 300,  lockout => 900 },
	totp_ip   => { max => 50,  window => 900,  lockout => 1800 },
	passkey   => { max => 30,  window => 900,  lockout => 900 },
	reset     => { max => 20,  window => 3600, lockout => 3600 },
	forgot    => { max => 3,   window => 3600, lockout => 3600 },
	forgot_ip => { max => 10,  window => 3600, lockout => 3600 },
	token     => { max => 10,  window => 900,  lockout => 900 },
	token_ip  => { max => 100, window => 900,  lockout => 1800 },
);

sub install_rate_limiter {
	my ($app) = @_;

	# Lazily built and memoized, so tests (which override the pt helper after
	# startup) and the real app both read config from pt at first use.
	my %S      = ( built => 0, enabled => 0, rl => undef );
	my $ensure = sub {
		my ($c) = @_;
		return \%S if $S{built};
		$S{built} = 1;
		my $ini = ( eval { $c->pt->{ini}->{''} } ) || {};
		my $en  = $ini->{rateLimit} // $ENV{NISABA_RATELIMIT} // 1;
		$S{enabled} = ( $en && $en ne '0' ) ? 1 : 0;
		if ( $S{enabled} ) {
			my $path = $ini->{rateLimitPath} // $ENV{NISABA_RATELIMIT_PATH}
				// $App::Nisaba::WebUtil::RateLimiter::DEFAULT_PATH;
			$S{rl} = eval {
				App::Nisaba::WebUtil::RateLimiter->new(
					{ path => $path, policies => { _policies_from_config($ini) } } );
			};
			$c->app->log->error( 'Rate limiter DB unavailable, failing closed: ' . ( $@ || '' ) ) if !$S{rl};
		}
		return \%S;
	}; ## end $ensure = sub

	$app->helper( rate_limiter => sub { my $c = shift; $ensure->($c)->{rl} } );

	$app->helper( rate_check => sub { my ( $c, $scope, %p ) = @_; _rl_evaluate( $c, $ensure->($c), $scope, \%p, 0 ) } );
	$app->helper( rate_hit   => sub { my ( $c, $scope, %p ) = @_; _rl_evaluate( $c, $ensure->($c), $scope, \%p, 1 ) } );
	$app->helper( rate_fail =>
			sub { my ( $c, $scope, %p ) = @_; _rl_mutate( $c, $ensure->($c), $scope, \%p, 'fail' ); return } );
	$app->helper( rate_reset =>
			sub { my ( $c, $scope, %p ) = @_; _rl_mutate( $c, $ensure->($c), $scope, \%p, 'reset' ); return } );

	$app->helper(
		rate_guard => sub {
			my ( $c, $scope, %opts ) = @_;
			my $render = delete $opts{render} || {};
			my $hit    = delete $opts{hit} ? 1                             : 0;
			my $res    = $hit              ? $c->rate_hit( $scope, %opts ) : $c->rate_check( $scope, %opts );
			return 1 if $res->{allowed};
			_rl_render_block( $c, $res, $render );
			return 0;
		}
	);

	return 1;
} ## end sub install_rate_limiter

# Populate the Mojolicious "hypnotoad" config section from nisabarc keys and/or
# NISABA_HYPNOTOAD_* environment variables, so the production Hypnotoad server
# (see rc/) can be tuned without a separate Mojolicious config file. Called from
# each web app's startup; a no-op (hypnotoad uses its own defaults) when nothing
# is set. Must run during startup, before hypnotoad reads config('hypnotoad').
#
# Config key / env var / hypnotoad setting (all optional):
#   hypnotoadListen           NISABA_LISTEN                        listen (space-separated URLs)
#   hypnotoadWorkers          NISABA_HYPNOTOAD_WORKERS             workers
#   hypnotoadClients          NISABA_HYPNOTOAD_CLIENTS             clients
#   hypnotoadAccepts          NISABA_HYPNOTOAD_ACCEPTS             accepts
#   hypnotoadSpare            NISABA_HYPNOTOAD_SPARE               spare
#   hypnotoadBacklog          NISABA_HYPNOTOAD_BACKLOG             backlog
#   hypnotoadRequests         NISABA_HYPNOTOAD_REQUESTS            requests
#   hypnotoadGracefulTimeout  NISABA_HYPNOTOAD_GRACEFUL_TIMEOUT    graceful_timeout
#   hypnotoadHeartbeatInterval NISABA_HYPNOTOAD_HEARTBEAT_INTERVAL heartbeat_interval
#   hypnotoadHeartbeatTimeout NISABA_HYPNOTOAD_HEARTBEAT_TIMEOUT   heartbeat_timeout
#   hypnotoadInactivityTimeout NISABA_HYPNOTOAD_INACTIVITY_TIMEOUT inactivity_timeout
#   hypnotoadKeepAliveTimeout NISABA_HYPNOTOAD_KEEP_ALIVE_TIMEOUT  keep_alive_timeout
#   hypnotoadUpgradeTimeout   NISABA_HYPNOTOAD_UPGRADE_TIMEOUT     upgrade_timeout
#   hypnotoadPidFile          NISABA_HYPNOTOAD_PID_FILE            pid_file
#   hypnotoadProxy            NISABA_HYPNOTOAD_PROXY               proxy (reverse-proxy header handling)
sub install_hypnotoad_config {
	my ($app) = @_;
	my $ini = ( eval { $app->pt->{ini}->{''} } ) || {};

	my %h = %{ $app->config('hypnotoad') || {} };

	# nisabarc key, env var, hypnotoad setting — coerced to a number.
	my @numeric = (
		[ 'hypnotoadWorkers',           'NISABA_HYPNOTOAD_WORKERS',            'workers' ],
		[ 'hypnotoadClients',           'NISABA_HYPNOTOAD_CLIENTS',            'clients' ],
		[ 'hypnotoadAccepts',           'NISABA_HYPNOTOAD_ACCEPTS',            'accepts' ],
		[ 'hypnotoadSpare',             'NISABA_HYPNOTOAD_SPARE',              'spare' ],
		[ 'hypnotoadBacklog',           'NISABA_HYPNOTOAD_BACKLOG',            'backlog' ],
		[ 'hypnotoadRequests',          'NISABA_HYPNOTOAD_REQUESTS',           'requests' ],
		[ 'hypnotoadGracefulTimeout',   'NISABA_HYPNOTOAD_GRACEFUL_TIMEOUT',   'graceful_timeout' ],
		[ 'hypnotoadHeartbeatInterval', 'NISABA_HYPNOTOAD_HEARTBEAT_INTERVAL', 'heartbeat_interval' ],
		[ 'hypnotoadHeartbeatTimeout',  'NISABA_HYPNOTOAD_HEARTBEAT_TIMEOUT',  'heartbeat_timeout' ],
		[ 'hypnotoadInactivityTimeout', 'NISABA_HYPNOTOAD_INACTIVITY_TIMEOUT', 'inactivity_timeout' ],
		[ 'hypnotoadKeepAliveTimeout',  'NISABA_HYPNOTOAD_KEEP_ALIVE_TIMEOUT', 'keep_alive_timeout' ],
		[ 'hypnotoadUpgradeTimeout',    'NISABA_HYPNOTOAD_UPGRADE_TIMEOUT',    'upgrade_timeout' ],
	);
	for my $m (@numeric) {
		my ( $ckey, $env, $hkey ) = @{$m};
		my $v = $ini->{$ckey} // $ENV{$env};
		next unless defined $v && $v ne '';
		$h{$hkey} = $v + 0;
	}

	# One or more whitespace-separated listen URLs. A single TLS URL such as
	# https://*:8443?cert=...&key=... contains no whitespace, so it survives.
	my $listen = $ini->{hypnotoadListen} // $ENV{NISABA_LISTEN};
	if ( defined $listen && $listen ne '' ) {
		$h{listen} = [ grep { length } split ' ', $listen ];
	}

	# Hypnotoad's default pid_file sits next to the application script, which is
	# not writable under a hardened service; honour an explicit path.
	my $pid = $ini->{hypnotoadPidFile} // $ENV{NISABA_HYPNOTOAD_PID_FILE};
	$h{pid_file} = $pid if defined $pid && $pid ne '';

	# Trust reverse-proxy headers (X-Forwarded-*). MOJO_REVERSE_PROXY is honoured
	# as a fallback for parity with the rest of the stack.
	my $proxy = $ini->{hypnotoadProxy} // $ENV{NISABA_HYPNOTOAD_PROXY} // $ENV{MOJO_REVERSE_PROXY};
	$h{proxy} = 1 if defined $proxy && $proxy ne '' && $proxy ne '0';

	$app->config( hypnotoad => \%h ) if %h;
	return 1;
} ## end sub install_hypnotoad_config

sub _policies_from_config {
	my ($ini) = @_;
	my %pol;
	for my $scope ( keys %DEFAULT_POLICIES ) {
		my $camel = join '', map { ucfirst } split /_/, $scope;
		my %p;
		for my $param (qw(max window lockout)) {
			my $key = 'rateLimit' . $camel . ucfirst($param);
			my $v   = $ini->{$key};
			$p{$param} = ( defined $v && $v ne '' ) ? ( $v + 0 ) : $DEFAULT_POLICIES{$scope}{$param};
		}
		$pol{$scope} = \%p;
	} ## end for my $scope ( keys %DEFAULT_POLICIES )
	return %pol;
} ## end sub _policies_from_config

sub _rl_subscopes { return @{ $SCOPE_KEYS{ $_[0] } || [] } }

sub _rl_build_id {
	my ( $sub, $parts, $ip ) = @_;
	my @vals;
	for my $p ( @{ $sub->{parts} } ) {
		push @vals, $ip                        if $p eq 'ip';
		push @vals, lc( $parts->{user} // '' ) if $p eq 'user';
	}
	return join( "\0", @vals );
}

# Returns { allowed => 1|0, retry_after => secs, unavailable => 1? }.
sub _rl_evaluate {
	my ( $c, $st, $scope, $parts, $record ) = @_;
	return { allowed => 1 }                                      unless $st->{enabled};
	return { allowed => 0, unavailable => 1, retry_after => 30 } unless $st->{rl};

	my $ip    = $c->tx->remote_address // '';
	my $worst = { allowed => 1, retry_after => 0 };
	for my $sub ( _rl_subscopes($scope) ) {
		my $id = _rl_build_id( $sub, $parts, $ip );
		my $r  = eval { $record ? $st->{rl}->hit( $sub->{scope}, $id ) : $st->{rl}->check( $sub->{scope}, $id ) };
		return { allowed => 0, unavailable => 1, retry_after => 30 } if $@;
		if ( !$r->{allowed} && ( $r->{retry_after} // 0 ) > $worst->{retry_after} ) {
			$worst = { allowed => 0, retry_after => $r->{retry_after} };
		}
	}
	return $worst;
} ## end sub _rl_evaluate

sub _rl_mutate {
	my ( $c, $st, $scope, $parts, $op ) = @_;
	return unless $st->{enabled} && $st->{rl};
	my $ip = $c->tx->remote_address // '';
	for my $sub ( _rl_subscopes($scope) ) {
		next if $op eq 'reset' && $sub->{backstop};
		my $id = _rl_build_id( $sub, $parts, $ip );
		eval { $st->{rl}->$op( $sub->{scope}, $id ) };
	}
	return;
} ## end sub _rl_mutate

sub _rl_render_block {
	my ( $c, $res, $render ) = @_;
	my $secs   = $res->{retry_after} || 30;
	my $status = $res->{unavailable} ? 503 : 429;
	$c->res->headers->header( 'Retry-After' => $secs );

	if ( $render->{json} ) {
		return $c->render(
			json => {
				error       => ( $res->{unavailable} ? 'service_unavailable' : 'too_many_requests' ),
				retry_after => ( $secs + 0 ),
			},
			status => $status,
		);
	}

	my $msg
		= $res->{unavailable}
		? 'The service is temporarily unavailable. Please try again shortly.'
		: 'Too many attempts. Please try again in ' . _rl_fmt_secs($secs) . '.';
	$c->stash( rate_error => $msg );
	return $c->render( %$render, status => $status );
} ## end sub _rl_render_block

sub _rl_fmt_secs {
	my ($s) = @_;
	return "$s seconds" if $s < 90;
	my $m = int( ( $s + 59 ) / 60 );
	return "$m minute" . ( $m == 1 ? '' : 's' );
}

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 LICENSE

Same terms as Perl itself.

=cut

1;
