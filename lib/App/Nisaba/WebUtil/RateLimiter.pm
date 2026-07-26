package App::Nisaba::WebUtil::RateLimiter;

use strict;
use warnings;
use Carp                         ();
use Digest::SHA                  qw(sha256_hex);
use App::Nisaba::WebUtil::SQLite ();

=head1 NAME

App::Nisaba::WebUtil::RateLimiter - SQLite-backed fixed-window rate limiter

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 DESCRIPTION

A small brute-force throttle shared across all prefork worker processes via a
single SQLite database (default F</var/db/nisaba/web_rate_limiter.sqlite>). It
counts events (failed logins, reset requests, ...) per hashed key inside a
fixed time window and locks the key out for a configurable period once a
threshold is reached.

Keys are namespaced by a B<scope> and stored as the SHA-256 hex digest of
C<"$scope\0$id">, so raw usernames and IP addresses are never written to disk.

The clock is injectable (C<now>) so lockout and window expiry are testable
without sleeping.

=head1 METHODS

=head2 new

    my $rl = App::Nisaba::WebUtil::RateLimiter->new({
        path            => '/var/db/nisaba/web_rate_limiter.sqlite',
        policies        => { login => { max => 8, window => 900, lockout => 900 }, ... },
        now             => \&time,   # optional, for tests
        cleanup_interval => 300,     # optional
    });

Opens (creating if needed) the database. The parent directory is created mode
0700 and the file tightened to 0600. The special path C<:memory:> keeps an
in-process database for tests.

=cut

our $DEFAULT_PATH = '/var/db/nisaba/web_rate_limiter.sqlite';

# Conservative fallback applied to any scope not present in `policies`.
our %FALLBACK_POLICY = ( max => 20, window => 900, lockout => 900 );

sub new {
	my ( $class, $args ) = @_;
	$args //= {};

	my $path = $args->{path};
	$path = $DEFAULT_PATH if !defined $path || $path eq '';

	my $self = bless {
		path             => $path,
		policies         => $args->{policies} || {},
		now              => $args->{now}      || sub { time() },
		cleanup_interval => ( defined $args->{cleanup_interval} ? $args->{cleanup_interval} : 300 ),
		_last_cleanup    => 0,
	}, $class;

	$self->{dbh} = App::Nisaba::WebUtil::SQLite::open_database(
		path        => $path,
		description => 'rate-limiter database',
	);
	$self->_init_schema;

	return $self;
} ## end sub new

sub _init_schema {
	my $self = shift;
	$self->{dbh}->do(
		q{
		CREATE TABLE IF NOT EXISTS rate_limit (
			rlkey        TEXT PRIMARY KEY,
			count        INTEGER NOT NULL,
			window_start INTEGER NOT NULL,
			locked_until INTEGER,
			expires_at   INTEGER NOT NULL
		)
	}
	);
	$self->{dbh}->do('CREATE INDEX IF NOT EXISTS rate_limit_exp ON rate_limit (expires_at)');
	return 1;
} ## end sub _init_schema

sub _now { return $_[0]->{now}->() }

sub _policy {
	my ( $self, $scope ) = @_;
	return $self->{policies}{$scope} || \%FALLBACK_POLICY;
}

sub _key {
	my ( $self, $scope, $id ) = @_;
	return sha256_hex( $scope . "\0" . ( defined $id ? $id : '' ) );
}

=head2 check

    my $r = $rl->check( $scope, $id );   # { allowed => 1|0, retry_after => secs }

Read-only: reports whether the key is currently locked out. Does not count
anything.

=cut

sub check {
	my ( $self, $scope, $id ) = @_;
	my $now = $self->_now;
	my $row = $self->{dbh}->selectrow_arrayref( 'SELECT locked_until FROM rate_limit WHERE rlkey = ?', undef,
		$self->_key( $scope, $id ) );
	if ( $row && defined $row->[0] && $row->[0] > $now ) {
		return { allowed => 0, retry_after => $row->[0] - $now };
	}
	return { allowed => 1, retry_after => 0 };
} ## end sub check

=head2 fail

    $rl->fail( $scope, $id );

Records one event against the key, opening or continuing the window and setting
a lockout once the scope's threshold is reached. Returns the same shape as
L</check> reflecting the post-record state.

=cut

sub fail {
	my ( $self, $scope, $id ) = @_;
	my $state = $self->_record( $scope, $id );
	my $now   = $self->_now;
	if ( defined $state->{locked_until} && $state->{locked_until} > $now ) {
		return { allowed => 0, retry_after => $state->{locked_until} - $now };
	}
	return { allowed => 1, retry_after => 0 };
}

=head2 hit

Alias for L</fail>, named for request-rate scopes where every request counts
(there is no separate success/failure signal).

=cut

sub hit { return shift->fail(@_) }

=head2 reset

    $rl->reset( $scope, $id );

Clears the key (e.g. after a successful authentication).

=cut

sub reset {
	my ( $self, $scope, $id ) = @_;
	$self->{dbh}->do( 'DELETE FROM rate_limit WHERE rlkey = ?', undef, $self->_key( $scope, $id ) );
	return 1;
}

# Atomic read-modify-write of a key's window/count/lock.
sub _record {
	my ( $self, $scope, $id ) = @_;
	my $pol = $self->_policy($scope);
	my $now = $self->_now;
	my $key = $self->_key( $scope, $id );
	my $dbh = $self->{dbh};

	my ( $count, $window_start, $locked_until );
	eval {
		$dbh->begin_work;    # IMMEDIATE: take the write lock up front
		my $row
			= $dbh->selectrow_arrayref( 'SELECT count, window_start, locked_until FROM rate_limit WHERE rlkey = ?',
				undef, $key );

		if ($row) {
			( $count, $window_start, $locked_until ) = @$row;
		} else {
			( $count, $window_start, $locked_until ) = ( 0, $now, undef );
		}

		my $locked = ( defined $locked_until && $locked_until > $now );

		# Start a fresh window once the current one has aged out — but never while
		# an active lock is in force (that would clear the lock early).
		if ( !$locked && ( $now - $window_start ) >= $pol->{window} ) {
			$count        = 0;
			$window_start = $now;
			$locked_until = undef if defined $locked_until && $locked_until <= $now;
		}

		$count += 1;

		# Trip the lock the moment the threshold is reached (and not already locked).
		if ( $count >= $pol->{max} && !$locked ) {
			$locked_until = $now + $pol->{lockout};
		}

		my $lock_exp   = defined $locked_until ? $locked_until : 0;
		my $win_exp    = $window_start + $pol->{window};
		my $expires_at = $win_exp > $lock_exp ? $win_exp : $lock_exp;

		$dbh->do(
			'INSERT OR REPLACE INTO rate_limit (rlkey, count, window_start, locked_until, expires_at) '
				. 'VALUES (?, ?, ?, ?, ?)',
			undef, $key, $count, $window_start, $locked_until, $expires_at,
		);
		$dbh->commit;
		1;
	} or do {
		my $err = $@ || 'unknown error';
		eval { $dbh->rollback };
		Carp::croak("rate-limiter record failed: $err");
	};

	$self->_maybe_cleanup;
	return { count => $count, locked_until => $locked_until };
} ## end sub _record

=head2 cleanup

Deletes expired rows and returns the number removed.

=cut

sub cleanup {
	my $self = shift;
	my $n    = $self->{dbh}->do( 'DELETE FROM rate_limit WHERE expires_at <= ?', undef, $self->_now );
	return ( $n && $n ne '0E0' ) ? ( $n + 0 ) : 0;
}

sub _maybe_cleanup {
	my $self     = shift;
	my $interval = $self->{cleanup_interval};
	return if !$interval || $interval <= 0;
	my $now = $self->_now;
	return if ( $now - $self->{_last_cleanup} ) < $interval;
	$self->{_last_cleanup} = $now;
	eval { $self->cleanup };
	return;
} ## end sub _maybe_cleanup

sub DESTROY {
	my $self = shift;
	if ( $self->{dbh} ) {
		eval { $self->{dbh}->disconnect };
	}
	return;
}

1;

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 LICENSE

Same terms as Perl itself.

=cut
