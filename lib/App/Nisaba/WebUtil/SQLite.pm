package App::Nisaba::WebUtil::SQLite;

use strict;
use warnings;
use Carp           ();
use DBI            ();
use File::Basename ();
use File::Path     ();

=head1 NAME

App::Nisaba::WebUtil::SQLite - shared SQLite opener for the Nisaba web stores

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    my $dbh = App::Nisaba::WebUtil::SQLite::open_database(
        path        => '/var/db/nisaba/websso.sqlite',
        description => 'SSO storage',
    );

=head1 DESCRIPTION

One place for the SQLite settings shared by the on-disk stores (the rate
limiter and the SSO grant store), so the concurrency-critical parts — WAL
journaling, the busy timeout, immediate transactions — cannot drift between
them.

=head1 FUNCTIONS

=head2 open_database

Creates the containing directory (mode 0700) when needed, opens the database
with RaiseError, unicode, and immediate transactions, enables WAL journaling
with NORMAL synchronous and a five-second busy timeout, restricts an on-disk
database file to mode 0600, and returns the database handle. C<path> may be
C<:memory:> for tests; C<description> names the store in error messages.

=cut

sub open_database {
	my (%args) = @_;

	my $path        = $args{path};
	my $description = $args{description} // 'database';

	if ( $path ne ':memory:' ) {
		my $directory = File::Basename::dirname($path);
		if ( !-d $directory ) {
			File::Path::make_path( $directory, { mode => oct('0700') } )
				or Carp::croak("Failed to create $description directory '$directory': $!");
		}
	}

	my $dbh = DBI->connect(
		'dbi:SQLite:dbname=' . $path,
		'', '',
		{
			RaiseError                       => 1,
			PrintError                       => 0,
			AutoCommit                       => 1,
			sqlite_unicode                   => 1,
			sqlite_use_immediate_transaction => 1,
		}
	) or Carp::croak( "Failed to open $description at '$path': " . $DBI::errstr );

	$dbh->sqlite_busy_timeout(5000);
	$dbh->do('PRAGMA journal_mode=WAL');
	$dbh->do('PRAGMA synchronous=NORMAL');

	chmod 0600, $path if $path ne ':memory:' && -e $path;

	return $dbh;
} ## end sub open_database

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 LICENSE

Same terms as Perl itself.

=cut

1;
