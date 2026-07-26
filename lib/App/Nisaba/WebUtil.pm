package App::Nisaba::WebUtil;

use strict;
use warnings;
use Exporter 'import';
use Mojo::Util                        ();
use MIME::Base64                      ();
use Crypt::PRNG                       ();
use App::Nisaba::WebUtil::RateLimiter ();

our @EXPORT_OK = qw(secure_compare random_b64url b64url_encode b64url_decode);

=head1 NAME

App::Nisaba::WebUtil - small shared security helpers for the Nisaba web apps

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 FUNCTIONS

=head2 secure_compare

    secure_compare( $a, $b )  or  die "mismatch";

Constant-time string comparison. Returns true when C<$a> and C<$b> are equal.
Unlike C<eq>, the time taken does not depend on how many leading characters
match, so it cannot be used as an oracle to recover a secret one character at a
time. Use it whenever one operand is a secret or a MAC/signature (client
secrets, HMACs, tokens).

The length of C<$a> is compared to C<$b> up front, which is standard practice
(e.g. Rails' C<secure_compare>); only the per-character comparison needs to be
constant time. The comparison itself is delegated to
L<Mojo::Util/secure_compare>; this wrapper adds tolerance of C<undef> operands.

=cut

sub secure_compare {
	my ( $x, $y ) = @_;
	return 0 unless defined $x && defined $y;
	return Mojo::Util::secure_compare( $x, $y ) ? 1 : 0;
}

# --------------------------------------------------------------------------- #
# Base64url / random tokens
# --------------------------------------------------------------------------- #

=head2 b64url_encode / b64url_decode

    my $b64url = b64url_encode($bytes);
    my $bytes  = b64url_decode($b64url);

Base64url (RFC 4648 URL-safe alphabet, no padding) encode and decode.

=head2 random_b64url

    my $token = random_b64url(32);

Generate the given number of cryptographically random bytes (default 32) and
return them base64url encoded. Uses L<Crypt::PRNG>, which croaks rather than
returning weak or short output if the underlying entropy source fails.

=cut

sub b64url_encode {
	my ($data) = @_;
	my $b64 = MIME::Base64::encode_base64( $data, '' );
	$b64 =~ tr|+/|-_|;
	$b64 =~ s/=+$//;
	return $b64;
}

sub b64url_decode {
	my ($b64url) = @_;
	$b64url =~ tr|-_|+/|;
	while ( length($b64url) % 4 ) { $b64url .= '=' }
	return MIME::Base64::decode_base64($b64url);
}

sub random_b64url {
	my ($length) = @_;
	$length //= 32;
	return b64url_encode( Crypt::PRNG::random_bytes($length) );
}

# --------------------------------------------------------------------------- #
# Common application startup
# --------------------------------------------------------------------------- #

=head2 install_common_startup

    my $pt = App::Nisaba::WebUtil::install_common_startup(
        $app,
        app_description   => 'App::Nisaba::Web (admin portal)',
        csrf_exempt_paths => ['/token'],    # optional
    );

The startup steps shared by all three Nisaba web apps: share-dir template and
static paths, the shared L<App::Nisaba> instance (config path from
C<$ENV{NISABA_CONFIG}>), session-secret resolution via
L<App::Nisaba::WebSecret>, session-cookie hardening, the C<pt> / C<pt_call> /
C<passkey_login_available> helpers, CSRF protection (with optional exempt
paths), brute-force rate limiting, and Hypnotoad tuning. Returns the
L<App::Nisaba> instance for any app-specific startup that still needs it.

=cut

sub install_common_startup {
	my ( $app, %opts ) = @_;

	# require rather than use: App::Nisaba::WebCSRF imports from this module,
	# so loading it at this module's compile time would be circular.
	require App::Nisaba;
	require App::Nisaba::WebSecret;
	require App::Nisaba::WebCSRF;
	require File::ShareDir;

	my $share = File::ShareDir::dist_dir('App-Nisaba');
	push @{ $app->renderer->paths }, "$share/templates";
	push @{ $app->static->paths },   "$share/public";

	# Shared App::Nisaba instance. Config path via $ENV{NISABA_CONFIG} or default.
	my %pt_args;
	$pt_args{config} = $ENV{NISABA_CONFIG} if $ENV{NISABA_CONFIG};
	my $pt = App::Nisaba->new( \%pt_args );

	# Session secret — from config or NISABA_SECRET. Refuses to start rather
	# than sign sessions with a predictable default (see App::Nisaba::WebSecret).
	$app->secrets(
		[
			App::Nisaba::WebSecret::resolve(
				configured => $pt->{ini}->{''}->{websecret},
				env        => $ENV{NISABA_SECRET},
				app        => $opts{app_description},
			)
		]
	);

	# Harden the session cookie: SameSite=Lax (explicit) and Secure (HTTPS-only).
	# Lax still allows the top-level cross-site GET navigation an RP uses to
	# reach the SSO app's /authorize. Secure is on by default; disable it for
	# plain-HTTP development or testing with cookieSecure=0 in the config or
	# NISABA_COOKIE_SECURE=0 in the env.
	$app->sessions->samesite('Lax');
	my $cookie_secure = $pt->{ini}->{''}->{cookieSecure} // $ENV{NISABA_COOKIE_SECURE} // 1;
	$app->sessions->secure( $cookie_secure ? 1 : 0 );

	# Helper to access the App::Nisaba instance
	$app->helper( pt => sub { $pt } );

	# Helper to call a pt method and return an error string (empty = success)
	$app->helper(
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
	$app->helper(
		passkey_login_available => sub {
			my ($c) = @_;
			return eval { $c->pt->passkeySchemaAvailable } ? 1 : 0;
		}
	);

	# CSRF: reject state-changing requests whose origin isn't our own, and
	# require the per-session synchronizer token on every such request.
	my @csrf_opts = $opts{csrf_exempt_paths} ? ( exempt_paths => $opts{csrf_exempt_paths} ) : ();
	App::Nisaba::WebCSRF::install_origin_check( $app, @csrf_opts );
	App::Nisaba::WebCSRF::install_token_check( $app, @csrf_opts );

	# Brute-force rate limiting for the auth endpoints.
	install_rate_limiter($app);

	# Production Hypnotoad tuning from nisabarc / NISABA_HYPNOTOAD_* (see rc/).
	install_hypnotoad_config($app);

	return $pt;
} ## end sub install_common_startup

# --------------------------------------------------------------------------- #
# Shared login flows
# --------------------------------------------------------------------------- #

=head2 handle_password_login

    App::Nisaba::WebUtil::handle_password_login( $c, %callbacks );

The password login flow shared by all three web apps: rate limiting, password
verification, and the hand-off to either the TOTP challenge or a logged-in
session. The app-specific parts are supplied as callbacks:

=over 4

=item * C<render_block> - render args (template/layout) used when the rate
limiter blocks the request.

=item * C<redirect_login> - C<< sub ($c) >>: redirect back to the login form
after a failed password.

=item * C<verify_extra> - optional C<< sub ($c, $user) >>: extra authorization
after the password verifies (e.g. the admin-group check). Must render or
redirect and return false to reject; return true to continue.

=item * C<set_totp_pending> - C<< sub ($c, $user) >>: record in the session
that a TOTP challenge is pending for the user.

=item * C<goto_totp_challenge> - C<< sub ($c) >>: redirect to the TOTP
challenge form.

=item * C<set_logged_in> - C<< sub ($c, $user) >>: record the completed login
in the session.

=item * C<goto_logged_in> - C<< sub ($c) >>: redirect to wherever a completed
login lands.

=back

=cut

sub handle_password_login {
	my ( $c, %opts ) = @_;
	my $user = $c->param('user') // '';
	my $pass = $c->param('pass') // '';

	return unless $c->rate_guard( 'login', user => $user, render => $opts{render_block} );

	my $err = $c->pt_call( sub { $c->pt->userVerifyPassword( { user => $user, password => $pass } ) } );
	if ($err) {
		$c->rate_fail( 'login', user => $user );
		$c->flash( error => 'Invalid username or password.' );
		return $opts{redirect_login}->($c);
	}
	$c->rate_reset( 'login', user => $user );

	if ( $opts{verify_extra} ) {
		return unless $opts{verify_extra}->( $c, $user );
	}

	# Check whether TOTP is active for this user
	my $info;
	$c->pt_call( sub { $info = $c->pt->userSelfInfo( { user => $user } ) } );
	if ( $info && ( $info->{totpStatus} // '' ) eq 'active' ) {
		$opts{set_totp_pending}->( $c, $user );
		return $opts{goto_totp_challenge}->($c);
	}

	$opts{set_logged_in}->( $c, $user );
	return $opts{goto_logged_in}->($c);
} ## end sub handle_password_login

=head2 handle_totp_challenge

    App::Nisaba::WebUtil::handle_totp_challenge( $c, %callbacks );

The TOTP challenge flow shared by all three web apps. The caller pulls the
pending user out of the session (redirecting to login when there is none) and
passes it as C<pending_user>; C<render_block>, C<set_logged_in>, and
C<goto_logged_in> are as for L</handle_password_login>, and
C<redirect_totp_challenge> redirects back to the challenge form after a bad
code.

=cut

sub handle_totp_challenge {
	my ( $c, %opts ) = @_;
	my $user = $opts{pending_user};

	return unless $c->rate_guard( 'totp', user => $user, render => $opts{render_block} );

	my $code = $c->param('code') // '';

	my $ok;
	my $err = $c->pt_call( sub { $ok = $c->pt->userTotpVerify( { user => $user, code => $code } ) } );
	if ( $err || !$ok ) {
		$c->rate_fail( 'totp', user => $user );
		$c->flash( error => 'Invalid TOTP code. Please try again.' );
		return $opts{redirect_totp_challenge}->($c);
	}
	$c->rate_reset( 'totp', user => $user );

	$opts{set_logged_in}->( $c, $user );
	return $opts{goto_logged_in}->($c);
} ## end sub handle_totp_challenge

=head2 webauthn_context / webauthn_verifier

    my $context  = App::Nisaba::WebUtil::webauthn_context($c);
    my $verifier = App::Nisaba::WebUtil::webauthn_verifier($context);

C<webauthn_context> computes the WebAuthn relying-party parameters for a
request: C<rp_id> and C<uv> (user verification) from the config, falling back
to the request host and C<preferred>, plus the request C<origin> including any
non-default port. C<webauthn_verifier> builds an L<Authen::WebAuthn> verifier
from a context, or returns undef when the module is not installed.

=cut

sub webauthn_context {
	my ($c) = @_;
	my $url = $c->req->url->to_abs;
	my $ini = $c->pt->{ini}->{''};

	my $origin = $url->scheme . '://' . $url->host;
	my $port   = $url->port;
	$origin .= ":$port"
		if $port
		&& !( ( $url->scheme eq 'https' && $port == 443 ) || ( $url->scheme eq 'http' && $port == 80 ) );

	return {
		rp_id  => ( $ini->{passkeyRpId}             || $url->host ),
		uv     => ( $ini->{passkeyUserVerification} || 'preferred' ),
		origin => $origin,
	};
} ## end sub webauthn_context

sub webauthn_verifier {
	my ($context) = @_;
	return eval {
		require Authen::WebAuthn;
		Authen::WebAuthn->new( rp_id => $context->{rp_id}, origin => $context->{origin} );
	};
}

=head2 handle_passkey_login_start / handle_passkey_login_finish

    App::Nisaba::WebUtil::handle_passkey_login_start( $c,
        challenge_session_key => 'passkey_login_challenge' );
    App::Nisaba::WebUtil::handle_passkey_login_finish( $c,
        challenge_session_key => 'passkey_login_challenge', %callbacks );

The WebAuthn passkey login flow shared by all three web apps: challenge
generation (start), then assertion verification, sign-count update, and TOTP
hand-off (finish). The challenge lives in the session under
C<challenge_session_key>. C<handle_passkey_login_finish> takes the same
C<verify_extra>, C<set_totp_pending>, and C<set_logged_in> callbacks as
L</handle_password_login>; both success responses are rendered as JSON here,
so no navigation callbacks are needed.

=cut

sub handle_passkey_login_start {
	my ( $c, %opts ) = @_;

	my $challenge_b64 = random_b64url(32);
	$c->session( $opts{challenge_session_key} => $challenge_b64 );

	my $context = webauthn_context($c);

	# Empty allowCredentials triggers discoverable-credential (resident key) mode
	$c->render(
		json => {
			challenge        => $challenge_b64,
			rpId             => $context->{rp_id},
			userVerification => $context->{uv},
			allowCredentials => [],
			timeout          => 60000,
		}
	);
} ## end sub handle_passkey_login_start

sub handle_passkey_login_finish {
	my ( $c, %opts ) = @_;

	return unless $c->rate_guard( 'passkey', render => { json => 1 } );

	my $challenge_b64 = $c->session( $opts{challenge_session_key} );
	unless ($challenge_b64) {
		return $c->render( json => { error => 'No login in progress' }, status => 400 );
	}
	delete $c->session->{ $opts{challenge_session_key} };

	my $body = $c->req->json;
	unless ( $body && ref $body->{response} eq 'HASH' ) {
		return $c->render( json => { error => 'Invalid request body' }, status => 400 );
	}

	my $credential_id = $body->{id} // '';
	unless ($credential_id) {
		return $c->render( json => { error => 'Missing credential ID' }, status => 400 );
	}

	# Look up which user owns this credential
	my $found;
	my $find_err
		= $c->pt_call( sub { $found = $c->pt->userPasskeyFindByCredentialId( { credentialId => $credential_id } ) } );
	if ( $find_err || !$found ) {
		return $c->render( json => { error => 'Unknown passkey' }, status => 401 );
	}

	my $user = $found->{user};
	my $cred = $found->{credential};

	if ( $opts{verify_extra} ) {
		return unless $opts{verify_extra}->( $c, $user );
	}

	my $context  = webauthn_context($c);
	my $verifier = webauthn_verifier($context);
	unless ($verifier) {
		return $c->render(
			json   => { error => 'WebAuthn not available on this server (Authen::WebAuthn not installed)' },
			status => 501,
		);
	}

	my $result = eval {
		$verifier->validate_assertion(
			challenge_b64          => $challenge_b64,
			credential_pubkey_b64  => $cred->{cosePublicKey},
			stored_sign_count      => $cred->{signCount},
			requested_uv           => $context->{uv},
			client_data_json_b64   => $body->{response}{clientDataJSON},
			authenticator_data_b64 => $body->{response}{authenticatorData},
			signature_b64          => $body->{response}{signature},
			user_handle_b64        => $body->{response}{userHandle},
			token_binding_id_b64   => undef,
		);
	};
	if ($@) {
		( my $msg = $@ ) =~ s/ at \S+ line \d+\.?\s*$//;
		$c->rate_fail('passkey');
		return $c->render( json => { error => "Verification failed: $msg" }, status => 401 );
	}
	$c->rate_reset('passkey');

	# Update sign count and last-used timestamp (best-effort; don't abort login on failure)
	$c->pt_call(
		sub {
			$c->pt->userPasskeyCredentialUpdate(
				{
					user         => $user,
					credentialId => $credential_id,
					signCount    => $result->{sign_count} // $cred->{signCount},
					backupState  => ( $result->{bs} // 0 ) ? 'TRUE' : 'FALSE',
				}
			);
		}
	);

	# Check whether TOTP is also required
	my $info;
	$c->pt_call( sub { $info = $c->pt->userSelfInfo( { user => $user } ) } );
	if ( $info && ( $info->{totpStatus} // '' ) eq 'active' ) {
		$opts{set_totp_pending}->( $c, $user );
		return $c->render( json => { ok => 1, totp_required => 1 } );
	}

	$opts{set_logged_in}->( $c, $user );
	$c->render( json => { ok => 1 } );
} ## end sub handle_passkey_login_finish

# --------------------------------------------------------------------------- #
# Rate limiting
# --------------------------------------------------------------------------- #

=head2 install_rate_limiter

    App::Nisaba::WebUtil::install_rate_limiter($app);

Installs brute-force rate limiting on a Mojolicious app. Adds a lazily-built,
shared L<App::Nisaba::WebUtil::RateLimiter> (config is read from the app's
C<pt> helper on first use) plus controller helpers:

=over 4

=item * C<< $c->rate_guard($scope, %opts) >> - checks the limit and, if blocked,
renders a 429 (or 503 when the limiter DB is unavailable) and returns false;
returns true when the request may proceed. Pass C<< render => {...} >> with the
form template to re-render on a block, or C<< render => { json => 1 } >>, and
C<< hit => 1 >> for request-rate scopes.

=item * C<< $c->rate_fail($scope, %opts) >> - record a failed attempt.

=item * C<< $c->rate_reset($scope, %opts) >> - clear on success (the IP backstop
is intentionally not cleared).

=item * C<< $c->rate_check / $c->rate_hit >> - the underlying evaluators.

=back

C<%opts> carries the key parts, e.g. C<< user => $user >>; the client IP is
taken from C<< $c->tx->remote_address >>. When rate limiting is disabled
(C<rateLimit=0>) all helpers allow. When it is enabled but the store cannot be
opened, guarded endpoints fail B<closed>.

=cut

# scope => ordered list of sub-limits. 'backstop' sub-limits (the per-IP one)
# are not cleared on success so a single valid credential can't reset them.
my %SCOPE_KEYS = (
	login =>
		[ { scope => 'login', parts => [ 'user', 'ip' ] }, { scope => 'login_ip', parts => ['ip'], backstop => 1 } ],
	totp =>
		[ { scope => 'totp', parts => [ 'user', 'ip' ] }, { scope => 'totp_ip', parts => ['ip'], backstop => 1 } ],
	forgot =>
		[ { scope => 'forgot', parts => [ 'user', 'ip' ] }, { scope => 'forgot_ip', parts => ['ip'], backstop => 1 } ],
	passkey => [ { scope => 'passkey', parts => ['ip'] } ],
	reset   => [ { scope => 'reset',   parts => ['ip'] } ],
	token   =>
		[ { scope => 'token', parts => [ 'user', 'ip' ] }, { scope => 'token_ip', parts => ['ip'], backstop => 1 } ],
);

# Built-in defaults; every value is overridable in the config (see below).
my %DEFAULT_POLICIES = (
	login     => { max => 8,   window => 900,  lockout => 900 },
	login_ip  => { max => 50,  window => 900,  lockout => 1800 },
	totp      => { max => 5,   window => 300,  lockout => 900 },
	totp_ip   => { max => 50,  window => 900,  lockout => 1800 },
	passkey   => { max => 30,  window => 900,  lockout => 900 },
	reset     => { max => 20,  window => 3600, lockout => 3600 },
	forgot    => { max => 3,   window => 3600, lockout => 3600 },
	forgot_ip => { max => 10,  window => 3600, lockout => 3600 },
	token     => { max => 10,  window => 900,  lockout => 900 },
	token_ip  => { max => 100, window => 900,  lockout => 1800 },
);

sub install_rate_limiter {
	my ($app) = @_;

	# Lazily built and memoized, so tests (which override the pt helper after
	# startup) and the real app both read config from pt at first use.
	my %S      = ( built => 0, enabled => 0, rl => undef );
	my $ensure = sub {
		my ($c) = @_;
		return \%S if $S{built};
		$S{built} = 1;
		my $ini = ( eval { $c->pt->{ini}->{''} } ) || {};
		my $en  = $ini->{rateLimit} // $ENV{NISABA_RATELIMIT} // 1;
		$S{enabled} = ( $en && $en ne '0' ) ? 1 : 0;
		if ( $S{enabled} ) {
			my $path = $ini->{rateLimitPath} // $ENV{NISABA_RATELIMIT_PATH}
				// $App::Nisaba::WebUtil::RateLimiter::DEFAULT_PATH;
			$S{rl} = eval {
				App::Nisaba::WebUtil::RateLimiter->new(
					{ path => $path, policies => { _policies_from_config($ini) } } );
			};
			$c->app->log->error( 'Rate limiter DB unavailable, failing closed: ' . ( $@ || '' ) ) if !$S{rl};
		}
		return \%S;
	}; ## end $ensure = sub

	$app->helper( rate_limiter => sub { my $c = shift; $ensure->($c)->{rl} } );

	$app->helper( rate_check => sub { my ( $c, $scope, %p ) = @_; _rl_evaluate( $c, $ensure->($c), $scope, \%p, 0 ) } );
	$app->helper( rate_hit   => sub { my ( $c, $scope, %p ) = @_; _rl_evaluate( $c, $ensure->($c), $scope, \%p, 1 ) } );
	$app->helper( rate_fail =>
			sub { my ( $c, $scope, %p ) = @_; _rl_mutate( $c, $ensure->($c), $scope, \%p, 'fail' ); return } );
	$app->helper( rate_reset =>
			sub { my ( $c, $scope, %p ) = @_; _rl_mutate( $c, $ensure->($c), $scope, \%p, 'reset' ); return } );

	$app->helper(
		rate_guard => sub {
			my ( $c, $scope, %opts ) = @_;
			my $render = delete $opts{render} || {};
			my $hit    = delete $opts{hit} ? 1                             : 0;
			my $res    = $hit              ? $c->rate_hit( $scope, %opts ) : $c->rate_check( $scope, %opts );
			return 1 if $res->{allowed};
			_rl_render_block( $c, $res, $render );
			return 0;
		}
	);

	return 1;
} ## end sub install_rate_limiter

# Populate the Mojolicious "hypnotoad" config section from nisabarc keys and/or
# NISABA_HYPNOTOAD_* environment variables, so the production Hypnotoad server
# (see rc/) can be tuned without a separate Mojolicious config file. Called from
# each web app's startup; a no-op (hypnotoad uses its own defaults) when nothing
# is set. Must run during startup, before hypnotoad reads config('hypnotoad').
#
# Config key / env var / hypnotoad setting (all optional):
#   hypnotoadListen           NISABA_LISTEN                        listen (space-separated URLs)
#   hypnotoadWorkers          NISABA_HYPNOTOAD_WORKERS             workers
#   hypnotoadClients          NISABA_HYPNOTOAD_CLIENTS             clients
#   hypnotoadAccepts          NISABA_HYPNOTOAD_ACCEPTS             accepts
#   hypnotoadSpare            NISABA_HYPNOTOAD_SPARE               spare
#   hypnotoadBacklog          NISABA_HYPNOTOAD_BACKLOG             backlog
#   hypnotoadRequests         NISABA_HYPNOTOAD_REQUESTS            requests
#   hypnotoadGracefulTimeout  NISABA_HYPNOTOAD_GRACEFUL_TIMEOUT    graceful_timeout
#   hypnotoadHeartbeatInterval NISABA_HYPNOTOAD_HEARTBEAT_INTERVAL heartbeat_interval
#   hypnotoadHeartbeatTimeout NISABA_HYPNOTOAD_HEARTBEAT_TIMEOUT   heartbeat_timeout
#   hypnotoadInactivityTimeout NISABA_HYPNOTOAD_INACTIVITY_TIMEOUT inactivity_timeout
#   hypnotoadKeepAliveTimeout NISABA_HYPNOTOAD_KEEP_ALIVE_TIMEOUT  keep_alive_timeout
#   hypnotoadUpgradeTimeout   NISABA_HYPNOTOAD_UPGRADE_TIMEOUT     upgrade_timeout
#   hypnotoadPidFile          NISABA_HYPNOTOAD_PID_FILE            pid_file
#   hypnotoadProxy            NISABA_HYPNOTOAD_PROXY               proxy (reverse-proxy header handling)
sub install_hypnotoad_config {
	my ($app) = @_;
	my $ini = ( eval { $app->pt->{ini}->{''} } ) || {};

	my %h = %{ $app->config('hypnotoad') || {} };

	# nisabarc key, env var, hypnotoad setting — coerced to a number.
	my @numeric = (
		[ 'hypnotoadWorkers',           'NISABA_HYPNOTOAD_WORKERS',            'workers' ],
		[ 'hypnotoadClients',           'NISABA_HYPNOTOAD_CLIENTS',            'clients' ],
		[ 'hypnotoadAccepts',           'NISABA_HYPNOTOAD_ACCEPTS',            'accepts' ],
		[ 'hypnotoadSpare',             'NISABA_HYPNOTOAD_SPARE',              'spare' ],
		[ 'hypnotoadBacklog',           'NISABA_HYPNOTOAD_BACKLOG',            'backlog' ],
		[ 'hypnotoadRequests',          'NISABA_HYPNOTOAD_REQUESTS',           'requests' ],
		[ 'hypnotoadGracefulTimeout',   'NISABA_HYPNOTOAD_GRACEFUL_TIMEOUT',   'graceful_timeout' ],
		[ 'hypnotoadHeartbeatInterval', 'NISABA_HYPNOTOAD_HEARTBEAT_INTERVAL', 'heartbeat_interval' ],
		[ 'hypnotoadHeartbeatTimeout',  'NISABA_HYPNOTOAD_HEARTBEAT_TIMEOUT',  'heartbeat_timeout' ],
		[ 'hypnotoadInactivityTimeout', 'NISABA_HYPNOTOAD_INACTIVITY_TIMEOUT', 'inactivity_timeout' ],
		[ 'hypnotoadKeepAliveTimeout',  'NISABA_HYPNOTOAD_KEEP_ALIVE_TIMEOUT', 'keep_alive_timeout' ],
		[ 'hypnotoadUpgradeTimeout',    'NISABA_HYPNOTOAD_UPGRADE_TIMEOUT',    'upgrade_timeout' ],
	);
	for my $m (@numeric) {
		my ( $ckey, $env, $hkey ) = @{$m};
		my $v = $ini->{$ckey} // $ENV{$env};
		next unless defined $v && $v ne '';
		$h{$hkey} = $v + 0;
	}

	# One or more whitespace-separated listen URLs. A single TLS URL such as
	# https://*:8443?cert=...&key=... contains no whitespace, so it survives.
	my $listen = $ini->{hypnotoadListen} // $ENV{NISABA_LISTEN};
	if ( defined $listen && $listen ne '' ) {
		$h{listen} = [ grep { length } split ' ', $listen ];
	}

	# Hypnotoad's default pid_file sits next to the application script, which is
	# not writable under a hardened service; honour an explicit path.
	my $pid = $ini->{hypnotoadPidFile} // $ENV{NISABA_HYPNOTOAD_PID_FILE};
	$h{pid_file} = $pid if defined $pid && $pid ne '';

	# Trust reverse-proxy headers (X-Forwarded-*). MOJO_REVERSE_PROXY is honoured
	# as a fallback for parity with the rest of the stack.
	my $proxy = $ini->{hypnotoadProxy} // $ENV{NISABA_HYPNOTOAD_PROXY} // $ENV{MOJO_REVERSE_PROXY};
	$h{proxy} = 1 if defined $proxy && $proxy ne '' && $proxy ne '0';

	$app->config( hypnotoad => \%h ) if %h;
	return 1;
} ## end sub install_hypnotoad_config

sub _policies_from_config {
	my ($ini) = @_;
	my %pol;
	for my $scope ( keys %DEFAULT_POLICIES ) {
		my $camel = join '', map { ucfirst } split /_/, $scope;
		my %p;
		for my $param (qw(max window lockout)) {
			my $key = 'rateLimit' . $camel . ucfirst($param);
			my $v   = $ini->{$key};
			$p{$param} = ( defined $v && $v ne '' ) ? ( $v + 0 ) : $DEFAULT_POLICIES{$scope}{$param};
		}
		$pol{$scope} = \%p;
	} ## end for my $scope ( keys %DEFAULT_POLICIES )
	return %pol;
} ## end sub _policies_from_config

sub _rl_subscopes { return @{ $SCOPE_KEYS{ $_[0] } || [] } }

sub _rl_build_id {
	my ( $sub, $parts, $ip ) = @_;
	my @vals;
	for my $p ( @{ $sub->{parts} } ) {
		push @vals, $ip                        if $p eq 'ip';
		push @vals, lc( $parts->{user} // '' ) if $p eq 'user';
	}
	return join( "\0", @vals );
}

# Returns { allowed => 1|0, retry_after => secs, unavailable => 1? }.
sub _rl_evaluate {
	my ( $c, $st, $scope, $parts, $record ) = @_;
	return { allowed => 1 }                                      unless $st->{enabled};
	return { allowed => 0, unavailable => 1, retry_after => 30 } unless $st->{rl};

	my $ip    = $c->tx->remote_address // '';
	my $worst = { allowed => 1, retry_after => 0 };
	for my $sub ( _rl_subscopes($scope) ) {
		my $id = _rl_build_id( $sub, $parts, $ip );
		my $r  = eval { $record ? $st->{rl}->hit( $sub->{scope}, $id ) : $st->{rl}->check( $sub->{scope}, $id ) };
		return { allowed => 0, unavailable => 1, retry_after => 30 } if $@;
		if ( !$r->{allowed} && ( $r->{retry_after} // 0 ) > $worst->{retry_after} ) {
			$worst = { allowed => 0, retry_after => $r->{retry_after} };
		}
	}
	return $worst;
} ## end sub _rl_evaluate

sub _rl_mutate {
	my ( $c, $st, $scope, $parts, $op ) = @_;
	return unless $st->{enabled} && $st->{rl};
	my $ip = $c->tx->remote_address // '';
	for my $sub ( _rl_subscopes($scope) ) {
		next if $op eq 'reset' && $sub->{backstop};
		my $id = _rl_build_id( $sub, $parts, $ip );
		eval { $st->{rl}->$op( $sub->{scope}, $id ) };
	}
	return;
} ## end sub _rl_mutate

sub _rl_render_block {
	my ( $c, $res, $render ) = @_;
	my $secs   = $res->{retry_after} || 30;
	my $status = $res->{unavailable} ? 503 : 429;
	$c->res->headers->header( 'Retry-After' => $secs );

	if ( $render->{json} ) {
		return $c->render(
			json => {
				error       => ( $res->{unavailable} ? 'service_unavailable' : 'too_many_requests' ),
				retry_after => ( $secs + 0 ),
			},
			status => $status,
		);
	}

	my $msg
		= $res->{unavailable}
		? 'The service is temporarily unavailable. Please try again shortly.'
		: 'Too many attempts. Please try again in ' . _rl_fmt_secs($secs) . '.';
	$c->stash( rate_error => $msg );
	return $c->render( %$render, status => $status );
} ## end sub _rl_render_block

sub _rl_fmt_secs {
	my ($s) = @_;
	return "$s seconds" if $s < 90;
	my $m = int( ( $s + 59 ) / 60 );
	return "$m minute" . ( $m == 1 ? '' : 's' );
}

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 LICENSE

Same terms as Perl itself.

=cut

1;
