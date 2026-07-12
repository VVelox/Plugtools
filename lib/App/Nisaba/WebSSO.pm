package App::Nisaba::WebSSO;

use Mojo::Base 'Mojolicious';
use Mojo::URL;
use App::Nisaba;
use App::Nisaba::WebSecret;
use App::Nisaba::WebCSRF;
use App::Nisaba::WebUtil ();
use App::Nisaba::WebSSO::Storage;
use File::ShareDir 'dist_dir';

=encoding UTF-8

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
(OP) backed by LDAP via App::Nisaba: the Authorization Code flow with
PKCE, refresh tokens (rotated on every use), token revocation (RFC 7009)
and introspection (RFC 7662), C<prompt>/C<max_age> handling including
C<prompt=none> silent authentication, per-user remembered consent,
RP-initiated logout, and per-client ID-token signing with key rotation.

OIDC client registrations are stored as C<oidcRelyingParty> entries in
LDAP under the configured C<oidcbase>. Several registration fields are
enforced, not just stored — registered scopes are an allow-list, the
token endpoint auth method binds the credential transport, and the
C<refresh_token> grant type is the opt-in for refresh tokens. See the
L<mojo_nisaba_sso> documentation for the full operator-facing details.

=head1 CONFIGURATION

Read from the App::Nisaba INI config (default section).

=over 4

=item * ssoIssuer - the public base URL of this provider, e.g.
C<https://sso.example.com>. B<Set this in production.> When unset the issuer
is derived from each request's Host header, which behind a reverse proxy
produces an issuer relying parties will reject (C<iss> mismatch). The value
must not contain a path component: the provider's routes are mounted at the
server root, so an issuer like C<https://example.com/sso> would advertise
endpoints that do not exist. Serve the provider on its own hostname.

=item * ssoCodeLifetime - authorization code validity in seconds (default 600).

=item * ssoTokenLifetime - access token validity in seconds (default 3600).

=item * ssoIdTokenLifetime - ID token validity in seconds; defaults to
C<ssoTokenLifetime>.

=item * ssoRefreshTokenLifetime - refresh token validity in seconds (default
2592000, 30 days). Refresh tokens are only issued to clients whose
registration includes the C<refresh_token> grant type, and are rotated on
every use.

=item * ssoConsentLifetime - how long a remembered ("remember this decision")
consent lasts, in seconds. Default 0: remembered consents do not expire.

=item * ssoRequirePkce - require PKCE (S256) for public clients (default 1;
disabling is strongly discouraged).

=item * ssoStorageBackend / ssoStoragePath / ssoStorageCleanupInterval - the
shared grant store, see L<App::Nisaba::WebSSO::Storage>.

=item * rateLimit / rateLimitPath / rateLimitToken* / rateLimitTokenIp* -
brute-force rate limiting for the token, revocation, and introspection
endpoints (and the login/TOTP/passkey UI); see L<mojo_nisaba_sso> for the
per-key details.

=item * cookieSecure - mark the session cookie Secure (default 1); disable
only for plain-HTTP development.

=back

=head1 METHODS

=head2 issuer_config_warnings

    my @warnings = App::Nisaba::WebSSO::issuer_config_warnings( $issuer, $mode );

Returns warning strings for a problematic C<ssoIssuer> value. An unset issuer
is only flagged when C<$mode> is C<production> (Host-header derivation is fine
for ad-hoc development); an issuer with a path component, a trailing slash, or
a non-http(s) scheme is always flagged. Logged at startup so the resulting
relying-party C<iss> mismatches are debuggable.

=cut

sub issuer_config_warnings {
	my ( $issuer, $mode ) = @_;
	my @warnings;

	if ( !defined $issuer || $issuer eq '' ) {
		push @warnings,
			  'ssoIssuer is not configured: the OIDC issuer will be derived from each request\'s Host header. '
			. 'Behind a reverse proxy this produces an issuer relying parties will reject (iss mismatch). '
			. 'Set ssoIssuer to the public URL of this provider.'
			if ( $mode // '' ) eq 'production';
		return @warnings;
	}

	my $url = Mojo::URL->new($issuer);
	if ( ( $url->scheme // '' ) !~ /\Ahttps?\z/ ) {
		push @warnings, "ssoIssuer '$issuer' is not an absolute http(s) URL.";
		return @warnings;
	}
	if ( $url->path->to_string =~ m{[^/]} ) {
		push @warnings,
			  "ssoIssuer '$issuer' contains a path component, but the provider's routes are mounted at the "
			. 'server root: the endpoints advertised in discovery will not match the actual routes. '
			. 'Serve the provider on its own hostname without a path.';
	} elsif ( $issuer =~ m{/\z} ) {
		push @warnings,
			"ssoIssuer '$issuer' ends with a slash: advertised endpoint URLs would contain double slashes. "
			. 'Remove the trailing slash.';
	}

	return @warnings;
} ## end sub issuer_config_warnings

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

	# Flag issuer misconfiguration loudly: relying parties validate iss
	# strictly and the failure mode (a silently Host-header-derived issuer, or
	# advertised endpoints that don't exist) is confusing to debug from the RP
	# side.
	$self->log->warn($_) for issuer_config_warnings( $pt->{ini}->{''}->{ssoIssuer}, $self->mode );

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
	# cookie, so the CSRF threat and its headers don't apply there. The
	# end-session endpoint is also exempt because OIDC RP-Initiated Logout
	# allows relying parties to POST to it cross-site; the logout handler does
	# its own protection (a verifiable id_token_hint authenticates the request,
	# and anything else must carry the session's CSRF token or is answered
	# with the confirmation page instead of a logout).
	my @csrf_exempt = ( '/token', '/userinfo', '/revoke', '/introspect', '/sso/logout' );
	App::Nisaba::WebCSRF::install_origin_check( $self, exempt_paths => \@csrf_exempt );
	App::Nisaba::WebCSRF::install_token_check( $self, exempt_paths => \@csrf_exempt );

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

	# Token revocation (RFC 7009) and introspection (RFC 7662), both
	# server-to-server with client authentication
	$r->post('/revoke')->to('s_s_o#revoke')->name('sso_revoke');
	$r->post('/introspect')->to('s_s_o#introspect')->name('sso_introspect');

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
