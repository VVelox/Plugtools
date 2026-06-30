package App::Nisaba::WebSSO;

use Mojo::Base 'Mojolicious';
use App::Nisaba;
use File::ShareDir 'dist_dir';

=head1 NAME

App::Nisaba::WebSSO - OpenID Connect SSO Provider for App::Nisaba

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    # Started via mojo_nisaba_sso
    mojo_nisaba_sso daemon -l https://*:443

=head1 DESCRIPTION

A Mojolicious web application that implements an OpenID Connect Provider
(OP) backed by LDAP via App::Nisaba. Provides the standard OIDC endpoints
for the Authorization Code flow with PKCE support.

OIDC client registrations are stored as C<oidcRelyingParty> entries in
LDAP under the configured C<oidcbase>.

=head1 METHODS

=head2 startup

Mojolicious startup hook. Configures templates, helpers, secret, and
routes.

=cut

sub startup {
	my $self = shift;

	my $share = dist_dir('App-Nisaba');
	push @{ $self->renderer->paths }, "$share/templates";
	push @{ $self->static->paths },   "$share/public";

	# Instantiate App::Nisaba
	my %pt_args;
	$pt_args{config} = $ENV{NISABA_CONFIG} if $ENV{NISABA_CONFIG};
	my $pt = App::Nisaba->new( \%pt_args );

	# Session secret
	$self->secrets( [ $pt->{ini}->{''}->{websecret} // $ENV{NISABA_SECRET} // 'nisaba_sso_change_me' ] );

	# Helper to access the App::Nisaba instance
	$self->helper( pt => sub { $pt } );

	# Helper to call a pt method and return an error string (empty = success)
	$self->helper(
		pt_call => sub {
			my ( $c, $code ) = @_;
			eval { $code->() };
			return $@ if $@;
			if ( $c->pt->error ) {
				return $c->pt->errorString || ( 'Error code ' . $c->pt->error );
			}
			return '';
		}
	);

	# Helper: passkey login is available when the passkey schema is loaded
	$self->helper(
		passkey_login_available => sub {
			my ($c) = @_;
			return eval { $c->pt->passkeySchemaAvailable } ? 1 : 0;
		}
	);

	# Helper: resolve the OIDC issuer URL
	$self->helper(
		sso_issuer => sub {
			my ($c) = @_;
			my $issuer = $c->pt->{ini}->{''}->{ssoIssuer};
			if ( $issuer && $issuer ne '' ) {
				return $issuer;
			}
			my $url = $c->req->url->to_abs;
			return $url->scheme . '://' . $url->host_port;
		}
	);

	# Referer check: every POST must originate from the same host.
	$self->hook(
		before_dispatch => sub {
			my $c = shift;
			return unless $c->req->method eq 'POST';

			# Exempt OIDC protocol endpoints that relying parties call directly
			# (server-to-server, no browser Referer): the token endpoint and the
			# UserInfo endpoint. These are authenticated by client credentials /
			# Bearer token, not by a session cookie, so the CSRF Referer check
			# neither applies nor should block them.
			return if $c->req->url->path eq '/token';
			return if $c->req->url->path eq '/userinfo';

			my $referer = $c->req->headers->referrer;
			unless ($referer) {
				$c->render( text => 'Forbidden: missing Referer header', status => 403 );
				return;
			}

			my $ref_host = Mojo::URL->new($referer)->host // '';
			my $req_host = $c->req->url->to_abs->host     // '';
			unless ( $ref_host eq $req_host ) {
				$c->render( text => 'Forbidden: Referer host mismatch', status => 403 );
				return;
			}
		}
	);

	my $r = $self->routes;

	# OIDC discovery
	$r->get('/.well-known/openid-configuration')->to('s_s_o#discovery')->name('sso_discovery');

	# JWKS endpoint (public keys for token verification)
	$r->get('/jwks')->to('s_s_o#jwks')->name('sso_jwks');

	# Authorization endpoint
	$r->get('/authorize')->to('s_s_o#authorize')->name('sso_authorize');

	# Login form and submission (shown during authorize when user is not authenticated)
	$r->get('/sso/login')->to('s_s_o#login_form')->name('sso_login');
	$r->post('/sso/login')->to('s_s_o#login')->name('sso_login_post');

	# TOTP challenge (if user has TOTP enabled)
	$r->get('/sso/totp')->to('s_s_o#totp_challenge_form')->name('sso_totp_challenge');
	$r->post('/sso/totp')->to('s_s_o#totp_challenge')->name('sso_totp_challenge_post');

	# Passkey login
	$r->get('/sso/passkeys/login/start')->to('s_s_o#passkey_login_start')->name('sso_passkey_login_start');
	$r->post('/sso/passkeys/login/finish')->to('s_s_o#passkey_login_finish')->name('sso_passkey_login_finish');

	# Consent form and submission
	$r->get('/sso/consent')->to('s_s_o#consent_form')->name('sso_consent');
	$r->post('/sso/consent')->to('s_s_o#consent')->name('sso_consent_post');

	# Token endpoint (POST only, used by RPs)
	$r->post('/token')->to('s_s_o#token')->name('sso_token');

	# UserInfo endpoint (GET and POST per spec)
	$r->get('/userinfo')->to('s_s_o#userinfo')->name('sso_userinfo_get');
	$r->post('/userinfo')->to('s_s_o#userinfo')->name('sso_userinfo_post');

} ## end sub startup

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 LICENSE

Same terms as Perl itself.

=cut

1;
