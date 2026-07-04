package App::Nisaba::WebSSO;

use Mojo::Base 'Mojolicious';
use App::Nisaba;
use App::Nisaba::WebSecret;
use App::Nisaba::WebCSRF;
use App::Nisaba::WebUtil ();
use App::Nisaba::WebSSO::Storage;
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

	# Session secret — from config or NISABA_SECRET. Refuses to start rather
	# than sign sessions with a predictable default (see App::Nisaba::WebSecret).
	$self->secrets(
		[
			App::Nisaba::WebSecret::resolve(
				configured => $pt->{ini}->{''}->{websecret},
				env        => $ENV{NISABA_SECRET},
				app        => 'App::Nisaba::WebSSO (OIDC provider)',
			)
		]
	);

	# Harden the session cookie: SameSite=Lax (explicit) and Secure (HTTPS-only).
	# Lax still allows the top-level cross-site GET navigation an RP uses to reach
	# /authorize. Secure is on by default; disable it for plain-HTTP development
	# or testing with cookieSecure=0 in the config or NISABA_COOKIE_SECURE=0.
	$self->sessions->samesite('Lax');
	my $cookie_secure = $pt->{ini}->{''}->{cookieSecure} // $ENV{NISABA_COOKIE_SECURE} // 1;
	$self->sessions->secure( $cookie_secure ? 1 : 0 );

	# Helper to access the App::Nisaba instance
	$self->helper( pt => sub { $pt } );

	# Shared server-side store for OIDC authorization codes and access tokens.
	# These are redeemed by relying-party back ends (server-to-server, no
	# browser cookie), so they cannot live in the session. Built lazily and
	# memoized on first use; the test suite overrides this helper with an
	# in-memory store, so the default on-disk path is never touched there.
	my $sso_storage;
	$self->helper(
		sso_storage => sub {
			return $sso_storage if $sso_storage;
			my $ini = $pt->{ini}->{''} // {};
			$sso_storage = App::Nisaba::WebSSO::Storage->new(
				{
					backend          => ( $ini->{ssoStorageBackend} // 'SQLite' ),
					path             => $ini->{ssoStoragePath},
					cleanup_interval => $ini->{ssoStorageCleanupInterval},
				}
			);
			return $sso_storage;
		}
	);

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

	# CSRF: reject state-changing requests whose origin isn't our own. The OIDC
	# token and UserInfo endpoints are exempt: relying parties call them
	# server-to-server with client credentials / a Bearer token and no browser
	# cookie, so the CSRF threat and its headers don't apply there.
	App::Nisaba::WebCSRF::install_origin_check( $self, exempt_paths => [ '/token', '/userinfo' ] );
	App::Nisaba::WebCSRF::install_token_check( $self, exempt_paths => [ '/token', '/userinfo' ] );

	# Brute-force rate limiting for the auth endpoints.
	App::Nisaba::WebUtil::install_rate_limiter($self);

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

	# Logout / end-session (OIDC RP-Initiated Logout). GET initiates (and
	# confirms when the request is not authenticated by a valid id_token_hint);
	# POST performs the confirmed logout.
	$r->get('/sso/logout')->to('s_s_o#logout')->name('sso_logout');
	$r->post('/sso/logout')->to('s_s_o#logout_post')->name('sso_logout_post');

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
