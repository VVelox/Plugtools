package App::Nisaba::WebSecret;

use strict;
use warnings;
use Carp ();

=head1 NAME

App::Nisaba::WebSecret - resolve the session-signing secret for the web apps

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 DESCRIPTION

Mojolicious session cookies are signed (HMAC) with the application secret but
are not encrypted, and every authentication decision in the Nisaba web apps is
carried in that cookie. If the secret is known, anyone can forge a cookie and
impersonate any user, including an administrator.

To avoid the footgun of a predictable session secret, this module resolves the
secret from explicit configuration only and B<refuses to start> when none is
provided, rather than falling back to any hard-coded default.

=head1 FUNCTIONS

=head2 resolve

    my $secret = App::Nisaba::WebSecret::resolve(
        configured => $pt->{ini}->{''}->{websecret},
        env        => $ENV{NISABA_SECRET},
        app        => 'App::Nisaba::Web',
    );

Returns the session secret, using the first non-empty source in this order:

=over 4

=item 1. C<configured> - the C<websecret> value from the Nisaba config.

=item 2. C<env> - the C<NISABA_SECRET> environment variable.

=back

If neither is set (or both are empty), it C<croak>s with an actionable message
instead of returning a guessable default. C<app> is only used to make that
message clearer.

=cut

sub resolve {
	my (%args) = @_;

	for my $candidate ( $args{configured}, $args{env} ) {
		return $candidate if defined $candidate && $candidate ne '';
	}

	my $app = $args{app} // 'the Nisaba web application';
	Carp::croak(<<"END_MSG");
Refusing to start $app without a session secret.

The session cookie that carries every authentication decision is signed with
this secret. Without a strong, private secret those cookies could be forged and
any account, including an administrator, impersonated. Set one of:

  * 'websecret' in the Nisaba config file (pointed to by NISABA_CONFIG), or
  * the NISABA_SECRET environment variable

to a long, random string, for example:

  NISABA_SECRET=\$(openssl rand -base64 48)
END_MSG
} ## end sub resolve

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 LICENSE

Same terms as Perl itself.

=cut

1;
