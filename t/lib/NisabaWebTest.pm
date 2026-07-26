package NisabaWebTest;

use strict;
use warnings;
use File::Basename ();
use File::Spec;

=head1 NAME

NisabaWebTest - shared scaffolding for the Nisaba web app test suite

=head1 SYNOPSIS

    use FindBin ();
    use lib "$FindBin::Bin/lib";
    use NisabaWebTest;                                # the common setup
    use NisabaWebTest qw(no_rate_limit no_pkce);      # plus per-suite opt-outs

    my $entry = FakeEntry->new(
        _dn => 'uid=alice,ou=users,dc=example,dc=com',
        uid => 'alice',
    );

=head1 DESCRIPTION

Loading this module — before any App::Nisaba web app module — stubs
C<File::ShareDir::dist_dir> to point at the repository F<share/> directory so
the web apps can start without the dist being installed, and sets
C<NISABA_SECRET> (the apps refuse to start without an explicit session
secret). Environment variables are only set when not already defined, so a
caller's environment still wins.

Import flags:

=over 4

=item * C<keep_cookie_secure> - by default C<NISABA_COOKIE_SECURE=0> is set so
the session cookie round-trips over the plain-HTTP test server; this flag
leaves the variable untouched (t/web-hardening.t checks the secure-by-default
behaviour and the explicit opt-out).

=item * C<no_rate_limit> - sets C<NISABA_RATELIMIT=0>. Rate limiting has its
own suite (t/web-ratelimit.t); suites that log in repeatedly disable it so
their requests are not throttled.

=item * C<no_pkce> - sets C<NISABA_REQUIRE_PKCE=0>. The mandatory-PKCE policy
is covered on its own in t/web-sso-pkce.t; the broader OIDC suites exercise a
public client without PKCE.

=back

Also provides the C<FakeEntry> class, a minimal stand-in for
L<Net::LDAP::Entry> used to build fixture users, groups, and OIDC clients:
C<new> takes an attribute hash (an arrayref value makes the attribute
multi-valued; the C<_dn> pseudo-attribute sets the DN) and entries answer
C<dn>, C<attributes>, and C<get_value>.

=cut

BEGIN {
	my $share = File::Spec->rel2abs(
		File::Spec->catdir( File::Basename::dirname(__FILE__), File::Spec->updir, File::Spec->updir, 'share' ) );
	require File::ShareDir;
	no warnings 'redefine';
	*File::ShareDir::dist_dir = sub { $share };

	# The web apps refuse to start without an explicit session secret.
	$ENV{NISABA_SECRET} = 'test-secret-nisaba' unless defined $ENV{NISABA_SECRET};
} ## end BEGIN

sub import {
	my ( $class, @flags ) = @_;
	my %flags = map { $_ => 1 } @flags;

	# Serve over plain HTTP in tests so the session cookie round-trips.
	unless ( $flags{keep_cookie_secure} ) {
		$ENV{NISABA_COOKIE_SECURE} = '0' unless defined $ENV{NISABA_COOKIE_SECURE};
	}

	if ( $flags{no_rate_limit} ) {
		$ENV{NISABA_RATELIMIT} = '0' unless defined $ENV{NISABA_RATELIMIT};
	}

	if ( $flags{no_pkce} ) {
		$ENV{NISABA_REQUIRE_PKCE} = '0' unless defined $ENV{NISABA_REQUIRE_PKCE};
	}

	return 1;
} ## end sub import

package FakeEntry;

sub new {
	my ( $class, %attrs ) = @_;
	my $dn = delete $attrs{_dn} // '';
	return bless { attrs => \%attrs, _dn => $dn }, $class;
}

sub dn         { return $_[0]->{_dn} }
sub attributes { return keys %{ $_[0]->{attrs} } }

sub get_value {
	my ( $self, $attr ) = @_;
	my $value = $self->{attrs}{$attr};
	return () unless defined $value;
	return wantarray ? ( ref $value ? @{$value} : ($value) ) : ( ref $value ? $value->[0] : $value );
}

1;
