package App::Nisaba::WebSSO::Storage::backends::SQLite;

use strict;
use warnings;
use Carp                         ();
use App::Nisaba::WebUtil::SQLite ();

=head1 NAME

App::Nisaba::WebSSO::Storage::backends::SQLite - SQLite grant store backend

=head1 DESCRIPTION

The default L<App::Nisaba::WebSSO::Storage> backend. Persists OIDC
authorization codes and access tokens in a single SQLite database so they
are shared across all prefork worker processes and survive restarts.

This is a dumb key/blob/expiry store: it knows nothing about OIDC. Keys are
already namespaced and hashed by the facade; values are opaque serialized
blobs. The backend is responsible only for persistence, atomic one-time
consumption, expiry filtering, and bulk cleanup.

The default database path is F</var/db/nisaba/websso.sqlite>. The parent
directory is created (mode 0700) if missing and the database file is
restricted to mode 0600 because it holds bearer tokens at rest.

The special path C<:memory:> opens an in-process database (used by the test
suite); directory creation and permission tightening are skipped for it.

=head1 METHODS

All methods operate on opaque string keys and values.

=head2 new

    my $backend = App::Nisaba::WebSSO::Storage::backends::SQLite->new(\%args);

=head3 args

=over 4

=item * path - database file path. Defaults to F</var/db/nisaba/websso.sqlite>.

=back

=cut

our $DEFAULT_PATH = '/var/db/nisaba/websso.sqlite';

sub new {
	my ( $class, $args ) = @_;
	$args //= {};

	my $path = $args->{path};
	$path = $DEFAULT_PATH if !defined $path || $path eq '';

	my $self = bless { path => $path }, $class;

	$self->{dbh} = App::Nisaba::WebUtil::SQLite::open_database(
		path        => $path,
		description => 'SQLite storage',
	);
	$self->_init_schema;

	return $self;
} ## end sub new

sub _init_schema {
	my $self = shift;
	$self->{dbh}->do(
		q{
		CREATE TABLE IF NOT EXISTS oidc_store (
			skey       TEXT PRIMARY KEY,
			sval       TEXT NOT NULL,
			expires_at INTEGER
		)
	}
	);
	$self->{dbh}->do('CREATE INDEX IF NOT EXISTS oidc_store_exp ON oidc_store (expires_at)');
	return 1;
} ## end sub _init_schema

=head2 put

    $backend->put($key, $value, $expires_at);

Stores (or replaces) a value. C<$expires_at> is an absolute epoch time, or
undef for no expiry.

=cut

sub put {
	my ( $self, $key, $value, $expires_at ) = @_;
	$self->{dbh}->do( 'INSERT OR REPLACE INTO oidc_store (skey, sval, expires_at) VALUES (?, ?, ?)',
		undef, $key, $value, $expires_at, );
	return 1;
}

=head2 get

    my $value = $backend->get($key);

Returns the stored value, or undef if absent or expired. Expired rows are
deleted lazily on access.

=cut

sub get {
	my ( $self, $key ) = @_;
	my $row = $self->{dbh}->selectrow_arrayref( 'SELECT sval, expires_at FROM oidc_store WHERE skey = ?', undef, $key );
	return undef unless $row;
	my ( $val, $exp ) = @$row;
	if ( defined $exp && $exp <= time() ) {
		$self->delete($key);
		return undef;
	}
	return $val;
} ## end sub get

=head2 consume

    my $value = $backend->consume($key);

Atomically fetches and deletes a value, enforcing single use across
concurrent worker processes. Returns the value, or undef if absent or
expired (the row is removed either way).

=cut

sub consume {
	my ( $self, $key ) = @_;
	my $dbh = $self->{dbh};

	my ( $val, $exp );
	eval {
		$dbh->begin_work;    # IMMEDIATE: takes the write lock up front
		my $row = $dbh->selectrow_arrayref( 'SELECT sval, expires_at FROM oidc_store WHERE skey = ?', undef, $key );
		if ($row) {
			( $val, $exp ) = @$row;
			$dbh->do( 'DELETE FROM oidc_store WHERE skey = ?', undef, $key );
		}
		$dbh->commit;
		1;
	} or do {
		my $err = $@ || 'unknown error';
		eval { $dbh->rollback };
		Carp::croak("SQLite consume failed: $err");
	};

	return undef unless defined $val;
	return undef if defined $exp && $exp <= time();
	return $val;
} ## end sub consume

=head2 delete

    $backend->delete($key);

Removes a key if present.

=cut

sub delete {
	my ( $self, $key ) = @_;
	$self->{dbh}->do( 'DELETE FROM oidc_store WHERE skey = ?', undef, $key );
	return 1;
}

=head2 cleanup

    my $removed = $backend->cleanup;

Deletes all expired rows and returns the number removed.

=cut

sub cleanup {
	my $self = shift;
	my $n
		= $self->{dbh}->do( 'DELETE FROM oidc_store WHERE expires_at IS NOT NULL AND expires_at <= ?', undef, time() );
	return ( $n && $n ne '0E0' ) ? ( $n + 0 ) : 0;
}

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
