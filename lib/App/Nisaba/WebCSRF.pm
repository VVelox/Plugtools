package App::Nisaba::WebCSRF;

use strict;
use warnings;
use Mojo::URL;
use App::Nisaba::WebUtil qw(secure_compare);

=head1 NAME

App::Nisaba::WebCSRF - shared CSRF protection for the Nisaba web apps

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 DESCRIPTION

Cross-site request forgery protection shared by all three Nisaba web
applications so the policy cannot drift between them (historically the
self-service portal was missing it entirely).

=head2 Layer 1 - origin check (this module, phase A)

L</install_origin_check> installs a C<before_dispatch> hook that rejects any
state-changing request (POST/PUT/PATCH/DELETE) whose stated origin does not
match the request's own origin. The stated origin is taken from the C<Origin>
header when present - browsers send it on cross-origin and most same-origin
writes and page script cannot forge it - falling back to C<Referer>. Origins are
compared as C<scheme://host:port> with default ports folded in, so a bare host
match is not enough (unlike the earlier host-only check).

Certain paths are exempt: OIDC endpoints called server-to-server by relying
parties (C</token>, C</userinfo>) carry client credentials or a bearer token
rather than a browser cookie, so neither the threat nor the headers apply.

=head2 Layer 2 - synchronizer token (this module, phase B)

L</install_token_check> installs an C<around_action> hook that requires every
state-changing request to carry the per-session CSRF token. The token is read
from the C<csrf_token> form field (emitted by Mojolicious' C<< <%= csrf_field %> >>
helper) or, for the JSON C<fetch()> passkey endpoints, from an C<X-CSRF-Token>
request header, and compared - in constant time - against the token stored in
the signed session. An attacker's cross-site page cannot read the victim's
token, so it cannot forge a valid submission even if it could influence the
Origin/Referer headers.

The check runs as an C<around_action> hook (not C<before_dispatch>) so it fires
during dispatch, after the session has been established. The same exempt paths
apply as for the origin check.

=head1 FUNCTIONS

=head2 install_origin_check

    App::Nisaba::WebCSRF::install_origin_check( $app,
        exempt_paths => [ '/token', '/userinfo' ] );

Installs the origin-check hook on the given Mojolicious app. C<exempt_paths> is
an optional arrayref of exact request paths that skip the check.

=cut

sub install_origin_check {
	my ( $app, %opts ) = @_;
	my %exempt = map { $_ => 1 } @{ $opts{exempt_paths} // [] };

	$app->hook(
		before_dispatch => sub {
			my $c = shift;
			return unless _is_write_method( $c->req->method );
			return if $exempt{ $c->req->url->path->to_string };

			my $stated = _stated_origin($c);
			unless ( defined $stated ) {
				$c->render( text => 'Forbidden: missing Origin/Referer header', status => 403 );
				return;
			}

			my $expected = _normalize_origin( $c->req->url->to_abs );
			unless ( defined $expected && $stated eq $expected ) {
				$c->render( text => 'Forbidden: Origin/Referer mismatch', status => 403 );
				return;
			}
		}
	);

	return 1;
} ## end sub install_origin_check

=head2 install_token_check

    App::Nisaba::WebCSRF::install_token_check( $app,
        exempt_paths => [ '/token', '/userinfo' ] );

Installs the synchronizer-token check on the given Mojolicious app. Every
state-changing request must present the session's CSRF token, either in the
C<csrf_token> parameter or an C<X-CSRF-Token> header. C<exempt_paths> is an
optional arrayref of exact request paths that skip the check.

=cut

sub install_token_check {
	my ( $app, %opts ) = @_;
	my %exempt = map { $_ => 1 } @{ $opts{exempt_paths} // [] };

	$app->hook(
		around_action => sub {
			my ( $next, $c, $action, $last ) = @_;

			return $next->() unless _is_write_method( $c->req->method );
			return $next->() if $exempt{ $c->req->url->path->to_string };

			unless ( token_valid($c) ) {
				$c->render( text => 'Forbidden: CSRF token missing or invalid', status => 403 );
				return;    # do not call $next: halts the dispatch chain
			}

			return $next->();
		}
	);

	return 1;
} ## end sub install_token_check

=head2 token_valid

    App::Nisaba::WebCSRF::token_valid($c)  or  <refuse the request>;

True when the request carries the session's CSRF token and it matches. The
token is read from the C<X-CSRF-Token> header first (the JSON C<fetch()>
endpoints have no form field), then the C<csrf_token> form parameter emitted
by C<< <%= csrf_field %> >>, and compared in constant time against the token
in the signed session. This is the same check L</install_token_check> applies
app-wide; it is exposed for handlers on CSRF-exempt paths (the SSO
end-session endpoint) that need to apply it selectively.

=cut

sub token_valid {
	my ($c) = @_;

	my $expected = $c->session('csrf_token');

	my $got = $c->req->headers->header('X-CSRF-Token');
	$got = $c->param('csrf_token') unless defined $got && $got ne '';

	return ( defined $expected && $expected ne '' && defined $got && secure_compare( $got, $expected ) ) ? 1 : 0;
} ## end sub token_valid

# True for HTTP methods that can change server state.
sub _is_write_method {
	my ($method) = @_;
	return
		   $method eq 'POST'
		|| $method eq 'PUT'
		|| $method eq 'PATCH'
		|| $method eq 'DELETE';
}

# The origin the request claims to come from: Origin header first, then Referer.
# Returns undef when neither yields a usable origin.
sub _stated_origin {
	my ($c) = @_;

	my $origin = $c->req->headers->origin;
	if ( defined $origin && $origin ne '' && lc($origin) ne 'null' ) {
		return _normalize_origin( Mojo::URL->new($origin) );
	}

	my $referer = $c->req->headers->referrer;
	if ( defined $referer && $referer ne '' ) {
		return _normalize_origin( Mojo::URL->new($referer) );
	}

	return undef;
} ## end sub _stated_origin

# Normalize a Mojo::URL to "scheme://host:port", folding in default ports so
# http://h and http://h:80 (and https://h and https://h:443) compare equal.
sub _normalize_origin {
	my ($url) = @_;
	return undef unless $url;

	my $scheme = lc( $url->scheme // '' );
	my $host   = lc( $url->host   // '' );
	return undef if $host eq '';

	my $port = $url->port;
	if ( !defined $port || $port eq '' ) {
		$port = $scheme eq 'https' ? 443 : $scheme eq 'http' ? 80 : 0;
	}

	return "$scheme://$host:$port";
} ## end sub _normalize_origin

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 LICENSE

Same terms as Perl itself.

=cut

1;
