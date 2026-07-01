package App::Nisaba::WebSSO::Storage;

use strict;
use warnings;
use Carp        ();
use Digest::SHA qw(sha256_hex);
use Mojo::JSON  qw(encode_json decode_json);

=head1 NAME

App::Nisaba::WebSSO::Storage - shared server-side store for OIDC grants

=head1 SYNOPSIS

    my $store = App::Nisaba::WebSSO::Storage->new({
        backend => 'SQLite',
        path    => '/var/db/nisaba/websso.sqlite',
    });

    # Authorization code (single use)
    $store->put( 'code', $code, \%code_data, $code_lifetime );
    my $code_data = $store->consume( 'code', $code );   # atomic fetch + delete

    # Access token
    $store->put( 'token', $access_token, \%token_data, $token_lifetime );
    my $token_data = $store->get( 'token', $access_token );
    $store->delete( 'token', $access_token );

=head1 DESCRIPTION

OIDC authorization codes and access tokens are presented to the token and
UserInfo endpoints by the relying party's back end - server-to-server
requests that carry no browser session cookie. They must therefore live in
a store that is shared across all (prefork) worker processes and that
survives restarts, rather than in the user's session.

This module is the facade in front of pluggable storage backends (under
C<App::Nisaba::WebSSO::Storage::backends>). It handles the OIDC-aware
concerns so backends can stay simple:

=over 4

=item * B<Namespacing> - each grant kind (C<code>, C<token>, ...) is a
separate key space.

=item * B<Key hashing> - the lookup key (the actual code/token) is stored
as its SHA-256 hex digest, never in the clear. A leak of the store does not
yield usable bearer tokens.

=item * B<Serialization> - grant data (a hashref) is JSON encoded.

=item * B<Expiry> - a TTL is converted to an absolute expiry handed to the
backend. Note this is a garbage-collection backstop: the protocol-level
expiry decision still belongs to the controller, which compares the
stored C<issued_at> against the current configured lifetime.

=back

The login session itself (the authenticated user, pending TOTP/passkey
state, the in-flight authorization request) intentionally stays in the
browser cookie and is B<not> handled here.

=head1 METHODS

=head2 new

    my $store = App::Nisaba::WebSSO::Storage->new(\%args);

=head3 args

=over 4

=item * backend - backend name under C<App::Nisaba::WebSSO::Storage::backends>.
Defaults to C<SQLite>.

=item * cleanup_interval - minimum seconds between opportunistic expiry
sweeps triggered by C<put>. Defaults to 300. Set to 0 to disable.

=back

Any remaining args are passed through to the backend constructor (e.g.
C<path> for the SQLite backend).

=cut

sub new {
	my ( $class, $args ) = @_;
	$args //= {};

	my $backend_name = $args->{backend} // 'SQLite';
	unless ( $backend_name =~ /\A[A-Za-z][A-Za-z0-9_]*\z/ ) {
		Carp::croak("Invalid storage backend name '$backend_name'");
	}

	my $backend_class = __PACKAGE__ . '::backends::' . $backend_name;
	## no critic (BuiltinFunctions::ProhibitStringyEval)
	eval "require $backend_class; 1"
		or Carp::croak("Failed to load storage backend $backend_class: $@");
	## use critic

	my $backend = $backend_class->new($args);

	return bless {
		backend          => $backend,
		cleanup_interval => ( defined $args->{cleanup_interval} ? $args->{cleanup_interval} : 300 ),
		_last_cleanup    => 0,
	}, $class;
} ## end sub new

# Namespaced, hashed storage key. The raw code/token is never stored.
sub _key {
	my ( $self, $kind, $key ) = @_;
	return $kind . ':' . sha256_hex($key);
}

=head2 put

    $store->put( $kind, $key, \%data, $ttl );

Stores C<\%data> under C<$kind>/C<$key>. C<$ttl> is a lifetime in seconds
(undef or 0 means no expiry). Triggers an opportunistic, throttled expiry
sweep.

=cut

sub put {
	my ( $self, $kind, $key, $data, $ttl ) = @_;
	my $expires_at = ( defined $ttl && $ttl ne '' && $ttl > 0 ) ? ( time() + $ttl ) : undef;
	$self->{backend}->put( $self->_key( $kind, $key ), encode_json($data), $expires_at );
	$self->_maybe_cleanup;
	return 1;
}

=head2 get

    my $data = $store->get( $kind, $key );

Returns the stored hashref, or undef if absent or expired.

=cut

sub get {
	my ( $self, $kind, $key ) = @_;
	my $blob = $self->{backend}->get( $self->_key( $kind, $key ) );
	return undef unless defined $blob;
	my $data = eval { decode_json($blob) };
	return $data;
}

=head2 consume

    my $data = $store->consume( $kind, $key );

Atomically fetches and deletes a grant, enforcing single use across worker
processes. Returns the hashref, or undef if absent or expired.

=cut

sub consume {
	my ( $self, $kind, $key ) = @_;
	my $blob = $self->{backend}->consume( $self->_key( $kind, $key ) );
	return undef unless defined $blob;
	return eval { decode_json($blob) };
}

=head2 delete

    $store->delete( $kind, $key );

Removes a grant.

=cut

sub delete {
	my ( $self, $kind, $key ) = @_;
	$self->{backend}->delete( $self->_key( $kind, $key ) );
	return 1;
}

=head2 cleanup

    my $removed = $store->cleanup;

Deletes all expired grants and returns the number removed.

=cut

sub cleanup {
	my $self = shift;
	return $self->{backend}->cleanup;
}

# Run cleanup at most once per cleanup_interval, on the back of a put().
sub _maybe_cleanup {
	my $self     = shift;
	my $interval = $self->{cleanup_interval};
	return if !$interval || $interval <= 0;
	my $now = time();
	return if ( $now - $self->{_last_cleanup} ) < $interval;
	$self->{_last_cleanup} = $now;
	eval { $self->{backend}->cleanup };
	return;
} ## end sub _maybe_cleanup

1;

=head1 SEE ALSO

L<App::Nisaba::WebSSO::Storage::backends::SQLite>, L<App::Nisaba::WebSSO>

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 LICENSE

Same terms as Perl itself.

=cut
