package App::Nisaba::WebSSO::Controller::SSO;

use Mojo::Base 'Mojolicious::Controller';
use Mojo::URL;
use Mojo::Util   qw(b64_encode b64_decode url_unescape);
use Mojo::JSON   qw(decode_json);
use MIME::Base64 ();
use Digest::SHA  qw(sha256);
use Crypt::PK::RSA;
use App::Nisaba::WebUtil qw(secure_compare random_b64url b64url_encode b64url_decode);
use App::Nisaba::WebCSRF ();

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

# --------------------------------------------------------------------------- #
# OIDC Discovery
# --------------------------------------------------------------------------- #

sub discovery {
	my $self   = shift;
	my $issuer = $self->sso_issuer;

	$self->render(
		json => {
			issuer                                        => $issuer,
			authorization_endpoint                        => "$issuer/authorize",
			token_endpoint                                => "$issuer/token",
			userinfo_endpoint                             => "$issuer/userinfo",
			end_session_endpoint                          => "$issuer/sso/logout",
			revocation_endpoint                           => "$issuer/revoke",
			introspection_endpoint                        => "$issuer/introspect",
			response_types_supported                      => ['code'],
			response_modes_supported                      => ['query'],
			grant_types_supported                         => [ 'authorization_code',  'refresh_token' ],
			revocation_endpoint_auth_methods_supported    => [ 'client_secret_basic', 'client_secret_post', 'none' ],
			introspection_endpoint_auth_methods_supported => [ 'client_secret_basic', 'client_secret_post' ],
			subject_types_supported                       => ['public'],
			jwks_uri                                      => "$issuer/jwks",
			id_token_signing_alg_values_supported         => [ 'RS256',  'HS256' ],
			scopes_supported                              => [ 'openid', 'profile', 'email', 'phone', 'address' ],
			token_endpoint_auth_methods_supported         => [ 'client_secret_basic', 'client_secret_post', 'none', ],
			claims_supported                              => [
				'sub',          'name',                  'given_name',         'family_name',
				'middle_name',  'nickname',              'preferred_username', 'profile',
				'picture',      'website',               'email',              'email_verified',
				'gender',       'birthdate',             'zoneinfo',           'locale',
				'phone_number', 'phone_number_verified', 'address',            'updated_at',
			],
			code_challenge_methods_supported => ['S256'],
		}
	);
} ## end sub discovery

# --------------------------------------------------------------------------- #
# JWKS endpoint — serves public keys for all clients that have oidcJwks set
# --------------------------------------------------------------------------- #

sub jwks {
	my $self = shift;

	my @all_keys;
	my $clients;
	eval { $clients = $self->pt->getOIDCClients };
	$clients //= [];

	for my $entry (@$clients) {
		my $jwks_json = $entry->get_value('oidcJwks');
		next unless $jwks_json;
		eval {
			my $jwks = decode_json($jwks_json);
			if ( $jwks->{keys} && ref $jwks->{keys} eq 'ARRAY' ) {
				for my $key ( @{ $jwks->{keys} } ) {
					# Only expose public components
					my %pub = map { $_ => $key->{$_} }
						grep { defined $key->{$_} } qw(kty n e kid use alg key_ops);
					$pub{use} //= 'sig';
					push @all_keys, \%pub;
				}
			}
		};
	} ## end for my $entry (@$clients)

	$self->render( json => { keys => \@all_keys } );
} ## end sub jwks

# --------------------------------------------------------------------------- #
# Authorization endpoint
# --------------------------------------------------------------------------- #

sub authorize {
	my $self = shift;

	# Validate required parameters
	my $client_id     = $self->param('client_id')     // '';
	my $redirect_uri  = $self->param('redirect_uri')  // '';
	my $response_type = $self->param('response_type') // '';
	my $scope         = $self->param('scope')         // '';
	my $state         = $self->param('state')         // '';
	my $nonce         = $self->param('nonce')         // '';

	# PKCE parameters
	my $code_challenge        = $self->param('code_challenge')        // '';
	my $code_challenge_method = $self->param('code_challenge_method') // '';

	# Look up the client
	my $client_entry;
	my $err = $self->pt_call( sub { $client_entry = $self->pt->getOIDCClientEntry( { clientId => $client_id } ) } );
	if ( $err || !$client_entry ) {
		return $self->render(
			template          => 'sso/error',
			layout            => 'sso',
			error_title       => 'Unknown Client',
			error_description => "The client_id '$client_id' is not registered.",
		);
	}

	# Validate redirect_uri against registered URIs
	my @registered_uris = $client_entry->get_value('oidcRedirectURI');
	unless (@registered_uris) {
		return $self->render(
			template          => 'sso/error',
			layout            => 'sso',
			error_title       => 'Client Configuration Error',
			error_description => 'This client has no registered redirect URIs.',
		);
	}
	unless ( grep { $_ eq $redirect_uri } @registered_uris ) {
		return $self->render(
			template          => 'sso/error',
			layout            => 'sso',
			error_title       => 'Invalid Redirect URI',
			error_description => 'The redirect_uri does not match any registered URI for this client.',
		);
	}

	# response_type is required (RFC 6749 Section 4.1.2.1: missing required
	# parameter is invalid_request); only the authorization code flow is supported.
	if ( $response_type eq '' ) {
		return $self->_authz_error( $redirect_uri, $state, 'invalid_request', 'response_type is required.' );
	}
	if ( $response_type ne 'code' ) {
		return $self->_authz_error( $redirect_uri, $state, 'unsupported_response_type',
			'Only response_type=code is supported.' );
	}

	# Scope must include openid
	my @scopes = split /\s+/, $scope;
	unless ( grep { $_ eq 'openid' } @scopes ) {
		return $self->_authz_error( $redirect_uri, $state, 'invalid_scope', 'The openid scope is required.' );
	}

	# The client's registered oidcScope values are an allow-list. openid itself
	# is always permitted (no OIDC client can function without it); every other
	# requested scope must be registered, so a client can never obtain
	# profile/email/phone/address claims its registration never granted. A
	# client with no registered scopes gets openid only.
	my %allowed_scopes = map { $_ => 1 } $client_entry->get_value('oidcScope');
	$allowed_scopes{openid} = 1;
	my @denied_scopes = grep { !$allowed_scopes{$_} } @scopes;
	if (@denied_scopes) {
		return $self->_authz_error( $redirect_uri, $state, 'invalid_scope',
			'Scope not registered for this client: ' . join( ' ', @denied_scopes ) . '.' );
	}

	# response_mode (OAuth 2.0 Multiple Response Types): only the default
	# 'query' encoding for the code flow is implemented. Reject anything else
	# rather than silently answering in an encoding the client did not ask for.
	my $response_mode = $self->param('response_mode') // '';
	if ( $response_mode ne '' && $response_mode ne 'query' ) {
		return $self->_authz_error( $redirect_uri, $state, 'invalid_request',
			"Unsupported response_mode '$response_mode'; only 'query' is supported." );
	}

	# prompt (OIDC Core 3.1.2.1). none must stand alone, and this is a
	# single-account provider so select_account can never be satisfied.
	my $prompt  = $self->param('prompt') // '';
	my %prompts = map { $_ => 1 } split /\s+/, $prompt;
	for my $p ( sort keys %prompts ) {
		unless ( $p eq 'none' || $p eq 'login' || $p eq 'consent' || $p eq 'select_account' ) {
			return $self->_authz_error( $redirect_uri, $state, 'invalid_request', "Unknown prompt value '$p'." );
		}
	}
	if ( $prompts{none} && keys(%prompts) > 1 ) {
		return $self->_authz_error( $redirect_uri, $state, 'invalid_request',
			'prompt=none cannot be combined with other prompt values.' );
	}
	if ( $prompts{select_account} ) {
		return $self->_authz_error( $redirect_uri, $state, 'account_selection_required',
			'Account selection is not supported.' );
	}

	# max_age: request parameter, falling back to the client's registered
	# oidcDefaultMaxAge. The End-User must have authenticated within this many
	# seconds; a staler session is sent back through login. (auth_time is
	# always included in the ID token, so oidcRequireAuthTime is satisfied
	# unconditionally.)
	my $max_age = $self->param('max_age');
	$max_age = $client_entry->get_value('oidcDefaultMaxAge') if !defined $max_age || $max_age eq '';
	undef $max_age unless defined $max_age && $max_age =~ /\A\d+\z/;

	# A code_challenge_method without a code_challenge is malformed — reject it
	# rather than silently issuing a code with no PKCE binding.
	if ( $code_challenge eq '' && $code_challenge_method ne '' ) {
		return $self->_authz_error( $redirect_uri, $state, 'invalid_request',
			'code_challenge_method requires a code_challenge.' );
	}

	# RFC 7636 Section 4.3: reject unsupported code_challenge_method
	if (   $code_challenge ne ''
		&& $code_challenge_method ne ''
		&& $code_challenge_method ne 'S256'
		&& $code_challenge_method ne 'plain' )
	{
		return $self->_authz_error( $redirect_uri, $state, 'invalid_request', 'Unsupported code_challenge_method.' );
	}

	# OAuth 2.1 / RFC 7636: a public client cannot authenticate at the token
	# endpoint, so PKCE is its only defence against authorization-code
	# interception — require it, and require S256 specifically ('plain' sends
	# challenge == verifier, handing an interceptor everything it needs). This is
	# on by default; an operator may relax it for legacy public clients with
	# ssoRequirePkce=0 in the config (strongly discouraged).
	my $require_pkce = $self->pt->{ini}->{''}->{ssoRequirePkce} // $ENV{NISABA_REQUIRE_PKCE} // 1;
	if ($require_pkce) {
		my $auth_method = $client_entry->get_value('oidcTokenEndpointAuthMethod') // '';
		my $has_secret  = ( $client_entry->get_value('oidcClientSecret') // '' ) ne '';
		my $is_public   = ( $auth_method eq 'none' ) || !$has_secret;

		if ($is_public) {
			if ( $code_challenge eq '' ) {
				return $self->_authz_error( $redirect_uri, $state, 'invalid_request',
					'This client is public and must use PKCE: a code_challenge is required.' );
			}
			# An absent method defaults to 'plain' (RFC 7636 4.3); public clients must use S256.
			if ( ( $code_challenge_method || 'plain' ) ne 'S256' ) {
				return $self->_authz_error( $redirect_uri, $state, 'invalid_request',
					'Public clients must use PKCE with code_challenge_method=S256.' );
			}
		} ## end if ($is_public)
	} ## end if ($require_pkce)

	my %authz = (
		client_id             => $client_id,
		redirect_uri          => $redirect_uri,
		scope                 => $scope,
		state                 => $state,
		nonce                 => $nonce,
		code_challenge        => $code_challenge,
		code_challenge_method => $code_challenge_method,
		created               => time(),
	);
	$authz{max_age} = $max_age + 0 if defined $max_age;
	# prompt=login — and max_age=0, which OIDC defines as equivalent — demand
	# an authentication fresher than this request, even if a session exists.
	$authz{min_auth_time} = time() if $prompts{login} || ( defined $max_age && $max_age == 0 );
	# prompt=consent demands the consent screen even when a matching grant is
	# already remembered.
	$authz{force_consent} = 1 if $prompts{consent};

	# prompt=none: no UI may be shown. Succeed silently only when the session
	# is already authenticated (and fresh enough) and the user has already
	# consented — in this session or durably — to this client/scope
	# combination; otherwise return the specific error the RP needs to fall
	# back to an interactive request.
	if ( $prompts{none} ) {
		unless ( $self->_authz_auth_ok( \%authz ) ) {
			return $self->_authz_error( $redirect_uri, $state, 'login_required',
				'No suitable authenticated session; interaction is required.' );
		}
		unless ( $self->_consent_covers( \%authz ) ) {
			return $self->_authz_error( $redirect_uri, $state, 'consent_required',
				'Consent has not been granted; interaction is required.' );
		}
		return $self->_issue_code( \%authz );
	} ## end if ( $prompts{none} )

	# Store the authorization request server-side in the session, keyed by a
	# request ID carried through the login/consent redirects. Keying by rid
	# lets several authorization requests (e.g. two browser tabs) proceed
	# concurrently without clobbering each other. A per-session monotonic
	# sequence orders the requests exactly; the created timestamp alone has
	# one-second resolution, which ties under rapid requests.
	my $seq = ( $self->session('sso_authz_seq') // 0 ) + 1;
	$self->session( sso_authz_seq => $seq );
	$authz{seq} = $seq;

	my $rid     = random_b64url(16);
	my $pending = $self->session('sso_authz');
	$pending = {} unless ref $pending eq 'HASH';
	$pending->{$rid} = \%authz;

	# Cap the number of in-flight requests so the session cookie stays small;
	# beyond the cap the oldest are dropped.
	my @rids = sort { ( $pending->{$b}{seq} // 0 ) <=> ( $pending->{$a}{seq} // 0 ) }
		grep { ref $pending->{$_} eq 'HASH' } keys %$pending;
	delete @{$pending}{ @rids[ 5 .. $#rids ] } if @rids > 5;
	$self->session( sso_authz => $pending );

	# If the user is already authenticated (and the authentication is fresh
	# enough for this request), move the request forward — which skips the
	# consent screen entirely when a matching grant is already remembered.
	# Otherwise go to login.
	if ( $self->_authz_auth_ok( \%authz ) ) {
		return $self->_advance_authz( $rid, \%authz );
	}
	$self->redirect_to( $self->url_for('sso_login')->query( rid => $rid ) );
} ## end sub authorize

# --------------------------------------------------------------------------- #
# Login
# --------------------------------------------------------------------------- #

sub login_form {
	my $self = shift;
	my ( $rid, $authz ) = $self->_pending_authz;
	unless ($authz) {
		return $self->render(
			template          => 'sso/error',
			layout            => 'sso',
			error_title       => 'No Authorization Request',
			error_description => 'Please start from the application you want to sign in to.',
		);
	}
	$self->stash( sso_rid => $rid );
	$self->render( template => 'sso/login', layout => 'sso' );
} ## end sub login_form

# Where the shared login flows (App::Nisaba::WebUtil) keep this app's session
# state and where each step navigates next.
sub _login_flow_callbacks {
	my ( $self, $rid ) = @_;
	return (
		set_totp_pending => sub { my ( $c, $user ) = @_; $c->session( sso_totp_pending_user => $user ) },
		set_logged_in    => sub {
			my ( $c, $user ) = @_;
			delete $c->session->{sso_totp_pending_user};
			$c->session( sso_user      => $user );
			$c->session( sso_auth_time => time() );
		},
		goto_totp_challenge => sub {
			my ($c) = @_;
			$c->redirect_to( $c->url_for('sso_totp_challenge')->query( rid => $rid // '' ) );
		},
		goto_logged_in => sub {
			my ($c) = @_;
			my ( undef, $authz ) = $c->_pending_authz;
			return $c->_advance_authz( $rid, $authz ) if defined $rid && $authz;
			$c->redirect_to( $c->url_for('sso_consent')->query( rid => $rid // '' ) );
		},
	);
} ## end sub _login_flow_callbacks

sub login {
	my $self = shift;
	my ($rid) = $self->_pending_authz;
	$self->stash( sso_rid => $rid // '' );

	App::Nisaba::WebUtil::handle_password_login(
		$self,
		$self->_login_flow_callbacks($rid),
		render_block   => { template => 'sso/login', layout => 'sso' },
		redirect_login => sub {
			my ($c) = @_;
			$c->redirect_to( $c->url_for('sso_login')->query( rid => $rid // '' ) );
		},
	);
} ## end sub login

# --------------------------------------------------------------------------- #
# Passkey login for SSO
# --------------------------------------------------------------------------- #

sub passkey_login_start {
	my $self = shift;
	App::Nisaba::WebUtil::handle_passkey_login_start( $self, challenge_session_key => 'sso_passkey_login_challenge' );
}

sub passkey_login_finish {
	my $self = shift;
	App::Nisaba::WebUtil::handle_passkey_login_finish(
		$self,
		$self->_login_flow_callbacks(undef),
		challenge_session_key => 'sso_passkey_login_challenge'
	);
}

# --------------------------------------------------------------------------- #
# TOTP challenge
# --------------------------------------------------------------------------- #

sub totp_challenge_form {
	my $self = shift;
	my ($rid) = $self->_pending_authz;
	unless ( $self->session('sso_totp_pending_user') ) {
		return $self->redirect_to( $self->url_for('sso_login')->query( rid => $rid // '' ) );
	}
	$self->stash( sso_rid => $rid // '' );
	$self->render( template => 'sso/totp_challenge', layout => 'sso' );
}

sub totp_challenge {
	my $self  = shift;
	my $user  = $self->session('sso_totp_pending_user');
	my ($rid) = $self->_pending_authz;
	$self->stash( sso_rid => $rid // '' );
	unless ($user) {
		return $self->redirect_to( $self->url_for('sso_login')->query( rid => $rid // '' ) );
	}

	App::Nisaba::WebUtil::handle_totp_challenge(
		$self,
		$self->_login_flow_callbacks($rid),
		pending_user            => $user,
		render_block            => { template => 'sso/totp_challenge', layout => 'sso' },
		redirect_totp_challenge => sub {
			my ($c) = @_;
			$c->redirect_to( $c->url_for('sso_totp_challenge')->query( rid => $rid // '' ) );
		},
	);
} ## end sub totp_challenge

# --------------------------------------------------------------------------- #
# Consent
# --------------------------------------------------------------------------- #

sub consent_form {
	my $self = shift;

	my ( $rid, $authz ) = $self->_pending_authz;
	unless ($authz) {
		return $self->render(
			template          => 'sso/error',
			layout            => 'sso',
			error_title       => 'No Authorization Request',
			error_description => 'Please start from the application you want to sign in to.',
		);
	}

	# Re-authentication constraints (max_age / prompt=login) gate the consent
	# screen too, so they cannot be bypassed by navigating here directly.
	my $user = $self->session('sso_user');
	unless ( $user && $self->_authz_auth_ok($authz) ) {
		return $self->redirect_to( $self->url_for('sso_login')->query( rid => $rid ) );
	}
	$self->stash( sso_rid => $rid );

	# Look up client for display info
	my $client_entry;
	$self->pt_call( sub { $client_entry = $self->pt->getOIDCClientEntry( { clientId => $authz->{client_id} } ) } );

	my $client_name = '';
	my $client_uri  = '';
	my $logo_uri    = '';
	my $policy_uri  = '';
	my $tos_uri     = '';
	if ($client_entry) {
		$client_name = $client_entry->get_value('oidcClientName') // $authz->{client_id};
		$client_uri  = $client_entry->get_value('oidcClientURI')  // '';
		$logo_uri    = $client_entry->get_value('oidcLogoURI')    // '';
		$policy_uri  = $client_entry->get_value('oidcPolicyURI')  // '';
		$tos_uri     = $client_entry->get_value('oidcTosURI')     // '';
	}

	my @scopes = split /\s+/, ( $authz->{scope} // '' );

	$self->render(
		template    => 'sso/consent',
		layout      => 'sso',
		user        => $user,
		client_name => $client_name,
		client_uri  => $client_uri,
		logo_uri    => $logo_uri,
		policy_uri  => $policy_uri,
		tos_uri     => $tos_uri,
		scopes      => \@scopes,
	);
} ## end sub consent_form

sub consent {
	my $self = shift;

	my ( $rid, $authz ) = $self->_pending_authz;
	my $user = $self->session('sso_user');
	unless ( $authz && $user ) {
		return $self->redirect_to('sso_login');
	}
	unless ( $self->_authz_auth_ok($authz) ) {
		return $self->redirect_to( $self->url_for('sso_login')->query( rid => $rid ) );
	}

	# This request is settled either way; drop it from the pending map.
	delete $self->session->{sso_authz}{$rid};

	my $decision = $self->param('decision') // '';
	if ( $decision ne 'allow' ) {
		# User denied consent
		return $self->_authz_error(
			$authz->{redirect_uri},
			$authz->{state}, 'access_denied', 'The user denied the authorization request.',
		);
	}

	# Remember the granted client/scope combination for this session so a
	# later prompt=none (silent) request can succeed without UI.
	my $consents = $self->session('sso_consents');
	$consents = {} unless ref $consents eq 'HASH';
	my %granted = map { $_ => 1 } split( /\s+/, $consents->{ $authz->{client_id} } // '' ),
		split( /\s+/, $authz->{scope} // '' );
	$consents->{ $authz->{client_id} } = join ' ', sort keys %granted;
	$self->session( sso_consents => $consents );

	# When asked to, also persist the grant in the shared store so it survives
	# this browser session: later visits skip the consent screen and silent
	# (prompt=none) requests succeed after any fresh login.
	if ( $self->param('remember') ) {
		my $key      = $user . "\0" . $authz->{client_id};
		my $existing = $self->sso_storage->get( 'consent', $key );
		my %all      = map { $_ => 1 } split( /\s+/, ( ( $existing && $existing->{scopes} ) // '' ) ),
			split( /\s+/, $authz->{scope} // '' );
		my $ttl = $self->pt->{ini}->{''}->{ssoConsentLifetime} // 0;
		$self->sso_storage->put(
			'consent', $key,
			{ scopes => join( ' ', sort keys %all ), granted_at => time() },
			( $ttl && $ttl > 0 ) ? $ttl : undef,
		);
	} ## end if ( $self->param('remember') )

	$self->_issue_code($authz);
} ## end sub consent

# --------------------------------------------------------------------------- #
# Logout / end-session (OIDC RP-Initiated Logout 1.0)
# --------------------------------------------------------------------------- #

sub logout {
	my $self = shift;

	my $hint  = $self->param('id_token_hint')            // '';
	my $post  = $self->param('post_logout_redirect_uri') // '';
	my $state = $self->param('state')                    // '';
	my $cid   = $self->param('client_id')                // '';

	# A request authenticated by a verifiable id_token_hint can be logged out
	# without prompting. Otherwise we must confirm with the user to prevent a
	# malicious third party from forcing a logout via a crafted link.
	my $info = $self->_verify_id_token_hint($hint);
	if ( $info && $info->{verified} ) {
		return $self->_perform_logout( $post, $state, $info, $cid );
	}

	$self->render(
		template                 => 'sso/logout_confirm',
		layout                   => 'sso',
		post_logout_redirect_uri => $post,
		state                    => $state,
		client_id                => $cid,
	);
} ## end sub logout

sub logout_post {
	my $self = shift;

	my $hint  = $self->param('id_token_hint')            // '';
	my $post  = $self->param('post_logout_redirect_uri') // '';
	my $state = $self->param('state')                    // '';
	my $cid   = $self->param('client_id')                // '';

	my $info = $self->_verify_id_token_hint($hint);

	# /sso/logout is exempt from the app-wide CSRF middleware so relying
	# parties may POST to the end-session endpoint cross-site (OIDC
	# RP-Initiated Logout 1.0). That is only safe when the request
	# authenticates itself with a verifiable id_token_hint; anything else must
	# be our own confirmation form, which carries the session's CSRF token.
	# A cross-site POST without either gets the confirmation page, not a
	# logout.
	unless ( $info && $info->{verified} ) {
		unless ( App::Nisaba::WebCSRF::token_valid($self) ) {
			return $self->render(
				template                 => 'sso/logout_confirm',
				layout                   => 'sso',
				post_logout_redirect_uri => $post,
				state                    => $state,
				client_id                => $cid,
			);
		}
	} ## end unless ( $info && $info->{verified} )

	return $self->_perform_logout( $post, $state, $info, $cid );
} ## end sub logout_post

# --------------------------------------------------------------------------- #
# Token endpoint
# --------------------------------------------------------------------------- #

sub token {
	my $self = shift;

	# RFC 6749 Section 3.2 / 4.1.3: token request parameters arrive in the
	# request body (application/x-www-form-urlencoded). Query-string
	# parameters are deliberately ignored so authorization codes and client
	# secrets never end up in access or proxy logs.
	my $params = $self->req->body_params;

	my $grant_type = $params->param('grant_type') // '';
	unless ( $grant_type eq 'authorization_code' || $grant_type eq 'refresh_token' ) {
		return $self->render(
			json   => { error => 'unsupported_grant_type' },
			status => 400,
		);
	}

	# Client authentication happens before any grant is touched, so a failed
	# authentication cannot burn a legitimate authorization code or refresh
	# token.
	my ( $client_id, $client_entry ) = $self->_authenticate_client($params);
	return unless defined $client_id;

	if ( $grant_type eq 'refresh_token' ) {
		return $self->_token_refresh( $params, $client_id, $client_entry );
	}
	return $self->_token_authorization_code( $params, $client_id, $client_entry );
} ## end sub token

# Shared client authentication for the server-to-server endpoints (/token,
# /revoke, /introspect). Reads client_id/secret from the Authorization header
# (client_secret_basic) or the request body (client_secret_post), applies the
# token-scope rate limit, resolves the client entry (fail closed), and
# enforces the registered token endpoint auth method:
#   - none: public client, no authentication (PKCE is enforced at the
#     authorization endpoint instead).
#   - client_secret_basic / client_secret_post: the secret must arrive by
#     the registered transport and match.
#   - unset: legacy default — a client with a stored secret must present it
#     by either transport; one without a secret is treated as public.
#   - anything else (private_key_jwt, client_secret_jwt, ...) is not
#     implemented by this provider: fail closed rather than skipping
#     authentication.
# Returns ( $client_id, $client_entry ) on success; renders the appropriate
# error response and returns an empty list on failure.
sub _authenticate_client {
	my ( $self, $params ) = @_;

	my $client_id   = $params->param('client_id')        // '';
	my $body_secret = $params->param('client_secret')    // '';
	my $auth_header = $self->req->headers->authorization // '';
	my $used_basic  = 0;
	my $basic_secret;
	if ( $auth_header =~ /^Basic\s+(.+)$/i ) {
		$used_basic = 1;
		my $decoded = MIME::Base64::decode_base64($1);
		my ( $hdr_id, $hdr_secret ) = split /:/, $decoded, 2;
		# RFC 6749 Section 2.3.1: credentials are application/x-www-form-urlencoded
		if ( defined $hdr_id ) {
			$hdr_id =~ s/\+/ /g;
			$hdr_id = url_unescape($hdr_id);
		}
		if ( defined $hdr_secret ) {
			$hdr_secret =~ s/\+/ /g;
			$hdr_secret = url_unescape($hdr_secret);
		}
		$client_id    = $hdr_id // $client_id;
		$basic_secret = $hdr_secret;
	} ## end if ( $auth_header =~ /^Basic\s+(.+)$/i )

	# Brute-force guard, keyed by (client_id, IP) with an IP backstop.
	return () unless $self->rate_guard( 'token', user => $client_id, render => { json => 1 } );

	# Resolve the client entry. This must fail closed: the secret check below
	# depends on it, so a lookup that errors out (e.g. a transient LDAP
	# failure) is a server_error, and an unknown client is invalid_client —
	# never fall through with authentication unchecked.
	my $client_entry;
	my $lookup_err
		= $self->pt_call( sub { $client_entry = $self->pt->getOIDCClientEntry( { clientId => $client_id } ) } );
	if ($lookup_err) {
		$self->render(
			json   => { error => 'server_error', error_description => 'Unable to resolve client.' },
			status => 500,
		);
		return ();
	}
	unless ($client_entry) {
		$self->rate_fail( 'token', user => $client_id );
		$self->res->headers->www_authenticate('Basic realm="token"') if $used_basic;
		$self->render(
			json   => { error => 'invalid_client', error_description => 'Client authentication failed.' },
			status => 401,
		);
		return ();
	}

	my $auth_method   = $client_entry->get_value('oidcTokenEndpointAuthMethod') // '';
	my $stored_secret = $client_entry->get_value('oidcClientSecret')            // '';

	my $auth_failed;
	if ( $auth_method eq 'none' ) {
		$auth_failed = 0;
	} elsif ( $auth_method eq 'client_secret_basic' ) {
		$auth_failed
			= $stored_secret eq ''
			|| !$used_basic
			|| !secure_compare( $basic_secret // '', $stored_secret );
	} elsif ( $auth_method eq 'client_secret_post' ) {
		$auth_failed
			= $stored_secret eq ''
			|| $used_basic
			|| !secure_compare( $body_secret, $stored_secret );
	} elsif ( $auth_method eq '' ) {
		my $presented = $used_basic ? ( $basic_secret // '' ) : $body_secret;
		$auth_failed = ( $stored_secret ne '' ) && !secure_compare( $presented, $stored_secret );
	} else {
		$auth_failed = 1;
	}

	if ($auth_failed) {
		$self->rate_fail( 'token', user => $client_id );
		# RFC 6749 Section 5.2: if the client authenticated via the
		# Authorization header, a 401 MUST carry a WWW-Authenticate header.
		$self->res->headers->www_authenticate('Basic realm="token"') if $used_basic;
		$self->render(
			json   => { error => 'invalid_client', error_description => 'Client authentication failed.' },
			status => 401,
		);
		return ();
	} ## end if ($auth_failed)
	$self->rate_reset( 'token', user => $client_id );

	return ( $client_id, $client_entry );
} ## end sub _authenticate_client

sub _token_authorization_code {
	my ( $self, $params, $client_id, $client_entry ) = @_;

	my $code         = $params->param('code')         // '';
	my $redirect_uri = $params->param('redirect_uri') // '';

	# Look up the authorization code in the shared store and atomically delete
	# it: consume() enforces one-time use across concurrent worker processes.
	my $code_data = $self->sso_storage->consume( 'code', $code );
	unless ($code_data) {
		$self->rate_fail( 'token', user => $client_id );
		return $self->render(
			json   => { error => 'invalid_grant', error_description => 'Authorization code not found or expired.' },
			status => 400,
		);
	}

	# Validate code hasn't expired
	my $code_lifetime = $self->pt->{ini}->{''}->{ssoCodeLifetime} // 600;
	if ( ( time() - $code_data->{issued_at} ) > $code_lifetime ) {
		return $self->render(
			json   => { error => 'invalid_grant', error_description => 'Authorization code expired.' },
			status => 400,
		);
	}

	# The code must have been issued to the authenticated client
	if ( $client_id ne $code_data->{client_id} ) {
		return $self->render(
			json   => { error => 'invalid_grant', error_description => 'client_id mismatch.' },
			status => 400,
		);
	}

	# Validate redirect_uri matches (RFC 6749 Section 4.1.3: REQUIRED if
	# redirect_uri was included in the authorization request)
	if ( $code_data->{redirect_uri} && $code_data->{redirect_uri} ne '' ) {
		if ( $redirect_uri eq '' ) {
			return $self->render(
				json   => { error => 'invalid_grant', error_description => 'redirect_uri is required.' },
				status => 400,
			);
		}
		if ( $redirect_uri ne $code_data->{redirect_uri} ) {
			return $self->render(
				json   => { error => 'invalid_grant', error_description => 'redirect_uri mismatch.' },
				status => 400,
			);
		}
	} ## end if ( $code_data->{redirect_uri} && $code_data...)

	# Validate PKCE code_verifier if code_challenge was provided
	if ( $code_data->{code_challenge} && $code_data->{code_challenge} ne '' ) {
		my $code_verifier = $params->param('code_verifier') // '';
		unless ($code_verifier) {
			return $self->render(
				json   => { error => 'invalid_grant', error_description => 'code_verifier required.' },
				status => 400,
			);
		}

		my $method = $code_data->{code_challenge_method} || 'plain';
		my $expected;
		if ( $method eq 'S256' ) {
			$expected = b64url_encode( sha256($code_verifier) );
		} else {
			$expected = $code_verifier;
		}

		if ( $expected ne $code_data->{code_challenge} ) {
			return $self->render(
				json   => { error => 'invalid_grant', error_description => 'PKCE verification failed.' },
				status => 400,
			);
		}
	} ## end if ( $code_data->{code_challenge} && $code_data...)

	# Build the ID token before minting the access token so a signing failure
	# leaves nothing behind: the code is consumed either way, but no orphan
	# access token may remain valid in the store after a server_error response.
	# Returns undef if the client is configured for a signing algorithm that
	# the server cannot satisfy (missing/unusable key material); never
	# silently downgrade to an unsigned token in that case.
	my $id_token
		= $self->_build_id_token( $code_data->{user}, $client_id, $code_data->{nonce}, $code_data->{scope},
			$code_data->{auth_time},
			$client_entry, );
	unless ( defined $id_token ) {
		return $self->render(
			json   => { error => 'server_error', error_description => 'Unable to sign ID token.' },
			status => 500,
		);
	}

	my $access_token = $self->_issue_access_token( $code_data->{user}, $code_data->{scope}, $client_id );

	# Issue a refresh token only when the client's registration allows the
	# refresh_token grant.
	my %grant_types = map { $_ => 1 } $client_entry->get_value('oidcGrantType');
	my $refresh_token;
	if ( $grant_types{refresh_token} ) {
		$refresh_token = $self->_issue_refresh_token(
			{
				user      => $code_data->{user},
				scope     => $code_data->{scope},
				client_id => $client_id,
				auth_time => $code_data->{auth_time},
			}
		);
	} ## end if ( $grant_types{refresh_token} )

	my $token_lifetime = $self->pt->{ini}->{''}->{ssoTokenLifetime} // 3600;

	# RFC 6749 Section 5.1: responses containing tokens MUST include these headers
	$self->res->headers->cache_control('no-store');
	$self->res->headers->header( 'Pragma' => 'no-cache' );

	$self->render(
		json => {
			access_token => $access_token,
			token_type   => 'Bearer',
			expires_in   => ( $token_lifetime + 0 ),    # RFC 6749 5.1: MUST be a JSON number
			id_token     => $id_token,
			scope        => $code_data->{scope},
			( defined $refresh_token ? ( refresh_token => $refresh_token ) : () ),
		}
	);
} ## end sub _token_authorization_code

sub _token_refresh {
	my ( $self, $params, $client_id, $client_entry ) = @_;

	# The client registration must allow the refresh_token grant.
	my %grant_types = map { $_ => 1 } $client_entry->get_value('oidcGrantType');
	unless ( $grant_types{refresh_token} ) {
		return $self->render(
			json =>
				{ error => 'unauthorized_client', error_description => 'Client may not use the refresh_token grant.' },
			status => 400,
		);
	}

	my $presented = $params->param('refresh_token') // '';
	if ( $presented eq '' ) {
		return $self->render(
			json   => { error => 'invalid_request', error_description => 'refresh_token is required.' },
			status => 400,
		);
	}

	# Rotation: consume() atomically retires the presented token, so a replay
	# of a rotated-out (possibly stolen) refresh token fails.
	my $rt_data = $self->sso_storage->consume( 'refresh', $presented );
	unless ($rt_data) {
		$self->rate_fail( 'token', user => $client_id );
		return $self->render(
			json   => { error => 'invalid_grant', error_description => 'Refresh token not found or expired.' },
			status => 400,
		);
	}

	my $rt_lifetime = $self->pt->{ini}->{''}->{ssoRefreshTokenLifetime} // 2592000;
	if ( ( time() - $rt_data->{issued_at} ) > $rt_lifetime ) {
		return $self->render(
			json   => { error => 'invalid_grant', error_description => 'Refresh token expired.' },
			status => 400,
		);
	}

	# The refresh token must have been issued to the authenticated client
	if ( $client_id ne ( $rt_data->{client_id} // '' ) ) {
		$self->rate_fail( 'token', user => $client_id );
		return $self->render(
			json   => { error => 'invalid_grant', error_description => 'client_id mismatch.' },
			status => 400,
		);
	}

	# Optional scope narrowing (RFC 6749 Section 6): the requested scope must
	# be a subset of the originally granted one. The refresh token itself
	# keeps the original grant, so narrowing one exchange is not permanent.
	my $scope = $params->param('scope') // '';
	if ( $scope ne '' ) {
		my %orig = map { $_ => 1 } split /\s+/, ( $rt_data->{scope} // '' );
		if ( grep { !$orig{$_} } split /\s+/, $scope ) {
			return $self->render(
				json   => { error => 'invalid_scope', error_description => 'Scope exceeds the original grant.' },
				status => 400,
			);
		}
	} else {
		$scope = $rt_data->{scope} // '';
	}

	# New ID token (OIDC Core 12.2): same sub, auth_time carried over from the
	# original authentication, fresh iat, and no nonce.
	my $id_token
		= $self->_build_id_token( $rt_data->{user}, $client_id, '', $scope, $rt_data->{auth_time}, $client_entry, );
	unless ( defined $id_token ) {
		return $self->render(
			json   => { error => 'server_error', error_description => 'Unable to sign ID token.' },
			status => 500,
		);
	}

	my $access_token = $self->_issue_access_token( $rt_data->{user}, $scope, $client_id );

	# Rotate: the old token is already retired; hand out a successor carrying
	# the original (un-narrowed) grant.
	my $new_refresh_token = $self->_issue_refresh_token(
		{
			user      => $rt_data->{user},
			scope     => $rt_data->{scope},
			client_id => $client_id,
			auth_time => $rt_data->{auth_time},
		}
	);

	my $token_lifetime = $self->pt->{ini}->{''}->{ssoTokenLifetime} // 3600;

	$self->res->headers->cache_control('no-store');
	$self->res->headers->header( 'Pragma' => 'no-cache' );

	$self->render(
		json => {
			access_token  => $access_token,
			token_type    => 'Bearer',
			expires_in    => ( $token_lifetime + 0 ),
			id_token      => $id_token,
			scope         => $scope,
			refresh_token => $new_refresh_token,
		}
	);
} ## end sub _token_refresh

# Mint and store an access token. TTL is a GC backstop; UserInfo and
# introspection enforce the protocol expiry from issued_at.
sub _issue_access_token {
	my ( $self, $user, $scope, $client_id ) = @_;
	my $access_token   = random_b64url(32);
	my $token_lifetime = $self->pt->{ini}->{''}->{ssoTokenLifetime} // 3600;
	$self->sso_storage->put(
		'token',
		$access_token,
		{
			user      => $user,
			scope     => $scope,
			client_id => $client_id,
			issued_at => time(),
		},
		$token_lifetime,
	);
	return $access_token;
} ## end sub _issue_access_token

# Mint and store a refresh token carrying the original grant.
sub _issue_refresh_token {
	my ( $self, $grant ) = @_;
	my $refresh_token = random_b64url(32);
	my $rt_lifetime   = $self->pt->{ini}->{''}->{ssoRefreshTokenLifetime} // 2592000;
	$self->sso_storage->put( 'refresh', $refresh_token, { %$grant, issued_at => time() }, $rt_lifetime );
	return $refresh_token;
}

# --------------------------------------------------------------------------- #
# Token revocation (RFC 7009)
# --------------------------------------------------------------------------- #

sub revoke {
	my $self = shift;

	my $params = $self->req->body_params;
	my ( $client_id, $client_entry ) = $self->_authenticate_client($params);
	return unless defined $client_id;

	# RFC 7009 Section 2.2: respond 200 whether or not the token exists — an
	# unknown or foreign token reveals nothing. Only tokens issued to the
	# authenticated client are actually removed. token_type_hint is treated as
	# just that, a hint: both kinds are checked regardless.
	my $token = $params->param('token') // '';
	if ( $token ne '' ) {
		for my $kind (qw(token refresh)) {
			my $data = $self->sso_storage->get( $kind, $token );
			next unless $data;
			$self->sso_storage->delete( $kind, $token ) if ( $data->{client_id} // '' ) eq $client_id;
		}
	}

	$self->res->headers->cache_control('no-store');
	return $self->render( json => {}, status => 200 );
} ## end sub revoke

# --------------------------------------------------------------------------- #
# Token introspection (RFC 7662)
# --------------------------------------------------------------------------- #

sub introspect {
	my $self = shift;

	my $params = $self->req->body_params;
	my ( $client_id, $client_entry ) = $self->_authenticate_client($params);
	return unless defined $client_id;

	# RFC 7662 Section 2.1: introspection must not be open to callers that
	# cannot authenticate — an unauthenticated endpoint is a token-validity
	# oracle. Public clients (auth method none / no secret) are refused.
	my $auth_method = $client_entry->get_value('oidcTokenEndpointAuthMethod') // '';
	my $has_secret  = ( $client_entry->get_value('oidcClientSecret') // '' ) ne '';
	if ( $auth_method eq 'none' || !$has_secret ) {
		return $self->render(
			json =>
				{ error => 'invalid_client', error_description => 'Introspection requires a confidential client.' },
			status => 401,
		);
	}

	$self->res->headers->cache_control('no-store');

	my $token = $params->param('token') // '';
	my ( $data, $kind );
	if ( $token ne '' ) {
		for my $k (qw(token refresh)) {
			my $d = $self->sso_storage->get( $k, $token );
			if ($d) { ( $data, $kind ) = ( $d, $k ); last }
		}
	}

	# Unknown, expired, or foreign tokens are simply "not active" (RFC 7662
	# Section 2.2) — never leak another client's token metadata.
	my $lifetime
		= ( $kind // '' ) eq 'refresh'
		? ( $self->pt->{ini}->{''}->{ssoRefreshTokenLifetime} // 2592000 )
		: ( $self->pt->{ini}->{''}->{ssoTokenLifetime} // 3600 );
	unless ( $data
		&& ( $data->{client_id} // '' ) eq $client_id
		&& ( time() - ( $data->{issued_at} // 0 ) ) <= $lifetime )
	{
		return $self->render( json => { active => Mojo::JSON->false } );
	}

	return $self->render(
		json => {
			active     => Mojo::JSON->true,
			scope      => ( $data->{scope} // '' ),
			client_id  => $data->{client_id},
			username   => $data->{user},
			sub        => $data->{user},
			token_type => ( $kind eq 'refresh' ? 'refresh_token' : 'Bearer' ),
			iat        => ( $data->{issued_at} + 0 ),
			exp        => ( $data->{issued_at} + $lifetime + 0 ),
			iss        => $self->sso_issuer,
		}
	);
} ## end sub introspect

# --------------------------------------------------------------------------- #
# UserInfo endpoint
# --------------------------------------------------------------------------- #

sub userinfo {
	my $self = shift;

	# Extract bearer token
	my $token;
	my $auth = $self->req->headers->authorization // '';
	if ( $auth =~ /^Bearer\s+(.+)$/i ) {
		$token = $1;
	} else {
		$token = $self->param('access_token') // '';
	}

	unless ($token) {
		$self->res->headers->www_authenticate('Bearer');
		return $self->render( json => { error => 'invalid_token' }, status => 401 );
	}

	my $token_data = $self->sso_storage->get( 'token', $token );
	unless ($token_data) {
		$self->res->headers->www_authenticate('Bearer error="invalid_token"');
		return $self->render( json => { error => 'invalid_token' }, status => 401 );
	}

	# Check token expiry
	my $token_lifetime = $self->pt->{ini}->{''}->{ssoTokenLifetime} // 3600;
	if ( ( time() - $token_data->{issued_at} ) > $token_lifetime ) {
		$self->sso_storage->delete( 'token', $token );
		$self->res->headers->www_authenticate('Bearer error="invalid_token"');
		return $self->render( json => { error => 'invalid_token' }, status => 401 );
	}

	my $user   = $token_data->{user};
	my @scopes = split /\s+/, ( $token_data->{scope} // '' );
	my %scopes = map { $_ => 1 } @scopes;

	# Build claims
	my $claims = $self->_build_userinfo_claims( $user, \%scopes );

	$self->render( json => $claims );
} ## end sub userinfo

# --------------------------------------------------------------------------- #
# Private helpers
# --------------------------------------------------------------------------- #

# Resolve the pending authorization request for this hop. Prefers the rid
# request parameter (set on every redirect between authorize, login, TOTP and
# consent); with no rid, falls back to the most recently started pending
# request (direct navigation, and the pre-rid behaviour). Returns
# ( $rid, $authz ) or an empty list.
sub _pending_authz {
	my ($self) = @_;
	my $pending = $self->session('sso_authz');
	return () unless ref $pending eq 'HASH';
	my $rid = $self->param('rid') // '';
	if ( $rid ne '' ) {
		my $authz = $pending->{$rid};
		return ( ref $authz eq 'HASH' ) ? ( $rid, $authz ) : ();
	}
	my ($newest) = sort { ( $pending->{$b}{seq} // 0 ) <=> ( $pending->{$a}{seq} // 0 ) }
		grep { ref $pending->{$_} eq 'HASH' } keys %$pending;
	return defined $newest ? ( $newest, $pending->{$newest} ) : ();
} ## end sub _pending_authz

# Is the session's authentication acceptable for this pending request? The
# user must be logged in and the recorded auth_time must satisfy the request's
# max_age (request param or oidcDefaultMaxAge) and min_auth_time (prompt=login)
# constraints.
sub _authz_auth_ok {
	my ( $self, $authz ) = @_;
	return 0 unless $self->session('sso_user');
	my $auth_time = $self->session('sso_auth_time');
	return 0 if !defined $auth_time;
	return 0 if defined $authz->{max_age}       && ( time() - $auth_time ) > $authz->{max_age};
	return 0 if defined $authz->{min_auth_time} && $auth_time < $authz->{min_auth_time};
	return 1;
}

# The scopes this user has granted the client, as a hash: the union of the
# consents recorded in this browser session and the durable per-user consents
# in the shared store ("remember this decision").
sub _consented_scopes {
	my ( $self, $user, $client_id ) = @_;
	my %granted;
	my $consents = $self->session('sso_consents');
	if ( ref $consents eq 'HASH' ) {
		$granted{$_} = 1 for split /\s+/, ( $consents->{$client_id} // '' );
	}
	if ( defined $user && $user ne '' && defined $client_id && $client_id ne '' ) {
		my $durable = $self->sso_storage->get( 'consent', $user . "\0" . $client_id );
		$granted{$_} = 1 for split /\s+/, ( ( $durable && $durable->{scopes} ) // '' );
	}
	return %granted;
} ## end sub _consented_scopes

# Does an existing consent (session or durable) cover every scope of this
# pending request?
sub _consent_covers {
	my ( $self, $authz ) = @_;
	my %granted = $self->_consented_scopes( $self->session('sso_user'), $authz->{client_id} );
	return !grep { !$granted{$_} } split /\s+/, ( $authz->{scope} // '' );
}

# Move an authenticated pending request forward: issue the code immediately
# when the user has already granted this client the requested scopes and the
# request does not force a fresh consent (prompt=consent); otherwise show the
# consent screen.
sub _advance_authz {
	my ( $self, $rid, $authz ) = @_;
	if ( !$authz->{force_consent} && $self->_consent_covers($authz) ) {
		delete $self->session->{sso_authz}{$rid};
		return $self->_issue_code($authz);
	}
	return $self->redirect_to( $self->url_for('sso_consent')->query( rid => $rid ) );
}

# Mint an authorization code for an approved request and redirect back to the
# client. Shared by the consent handler and the prompt=none (silent) path.
sub _issue_code {
	my ( $self, $authz ) = @_;

	my $code = random_b64url(32);

	# Store code details in the shared server-side store so the token endpoint
	# (called server-to-server by the relying party, with no browser cookie)
	# can redeem it. The TTL here is a GC backstop; the token endpoint enforces
	# the protocol expiry from issued_at against the current configured lifetime.
	my $code_lifetime = $self->pt->{ini}->{''}->{ssoCodeLifetime} // 600;
	$self->sso_storage->put(
		'code', $code,
		{
			client_id             => $authz->{client_id},
			redirect_uri          => $authz->{redirect_uri},
			scope                 => $authz->{scope},
			nonce                 => $authz->{nonce},
			user                  => $self->session('sso_user'),
			issued_at             => time(),
			auth_time             => ( $self->session('sso_auth_time') // time() ),
			code_challenge        => $authz->{code_challenge},
			code_challenge_method => $authz->{code_challenge_method},
		},
		$code_lifetime,
	);

	my $url = Mojo::URL->new( $authz->{redirect_uri} );
	$url->query->merge( code  => $code );
	$url->query->merge( state => $authz->{state} ) if ( $authz->{state} // '' ) ne '';
	return $self->redirect_to($url);
} ## end sub _issue_code

sub _authz_error {
	my ( $self, $redirect_uri, $state, $error, $description ) = @_;

	if ( !$redirect_uri || $redirect_uri eq '' ) {
		return $self->render(
			template          => 'sso/error',
			layout            => 'sso',
			error_title       => $error,
			error_description => $description,
		);
	}

	my $url = Mojo::URL->new($redirect_uri);
	$url->query->merge( error             => $error );
	$url->query->merge( error_description => $description ) if $description;
	$url->query->merge( state             => $state )       if $state && $state ne '';
	$self->redirect_to($url);
} ## end sub _authz_error

# Parse and (where possible) cryptographically verify an id_token_hint. Returns
# a hashref { client_id, client_entry, verified, payload } or undef if the hint
# is absent/unparseable or was not issued by us. The token's expiry is
# intentionally ignored: logout commonly happens after the ID token has expired.
sub _verify_id_token_hint {
	my ( $self, $hint ) = @_;
	return undef unless defined $hint && $hint ne '';

	my @parts = split /\./, $hint;
	return undef unless @parts >= 2;

	my $header  = eval { decode_json( b64url_decode( $parts[0] ) ) };
	my $payload = eval { decode_json( b64url_decode( $parts[1] ) ) };
	return undef unless $payload && ref $payload eq 'HASH';

	# Must be one of our own ID tokens.
	return undef unless ( $payload->{iss} // '' ) eq $self->sso_issuer;

	my $aud = $payload->{aud};
	$aud = $aud->[0] if ref $aud eq 'ARRAY';
	return undef unless defined $aud && $aud ne '';

	my $client_entry;
	eval { $client_entry = $self->pt->getOIDCClientEntry( { clientId => $aud } ) };
	return undef unless $client_entry;

	# Verify the signature with the client's configured algorithm. An unsigned
	# (alg=none) hint can identify the client but is never treated as verified.
	my $alg           = $header->{alg} // 'none';
	my $signing_input = $parts[0] . '.' . $parts[1];
	my $sig           = @parts >= 3 ? b64url_decode( $parts[2] ) : '';
	my $verified      = 0;

	if ( $alg eq 'RS256' ) {
		my $jwks_json = $client_entry->get_value('oidcJwks');
		my $jwks      = $jwks_json ? eval { decode_json($jwks_json) } : undef;
		if ( $jwks && ref $jwks->{keys} eq 'ARRAY' ) {
			# Select the verification key by the token's kid so hints signed
			# with a rotated-out-but-retained key still verify; with no kid (or
			# no match) fall back to trying every key in the set.
			my @keys       = grep { ref $_ eq 'HASH' } @{ $jwks->{keys} };
			my $kid        = $header      ? $header->{kid}                             : undef;
			my @candidates = defined $kid ? grep { ( $_->{kid} // '' ) eq $kid } @keys : ();
			@candidates = @keys unless @candidates;
			for my $key (@candidates) {
				my $rsa = Crypt::PK::RSA->new;
				next unless eval { $rsa->import_key($key); 1 };
				if ( eval { $rsa->verify_message( $sig, $signing_input, 'SHA256', 'v1.5' ) } ) {
					$verified = 1;
					last;
				}
			}
		} ## end if ( $jwks && ref $jwks->{keys} eq 'ARRAY')
	} elsif ( $alg eq 'HS256' ) {
		my $secret = $client_entry->get_value('oidcClientSecret') // '';
		if ( $secret ne '' ) {
			require Digest::SHA;
			$verified = 1 if secure_compare( $sig, Digest::SHA::hmac_sha256( $signing_input, $secret ) );
		}
	}

	return {
		client_id    => $aud,
		client_entry => $client_entry,
		verified     => $verified,
		payload      => $payload,
	};
} ## end sub _verify_id_token_hint

# Clear the SSO session and, when a post_logout_redirect_uri is supplied and is
# registered for the resolved client, redirect there (with state). Otherwise
# render the logged-out page. The redirect target is always validated against
# the client's registered oidcPostLogoutRedirectURI values to prevent an open
# redirect.
sub _perform_logout {
	my ( $self, $post, $state, $info, $client_id_param ) = @_;

	# Drop the entire SSO session cookie (login state, auth_time, etc.).
	$self->session( expires => 1 );

	# Resolve the client for redirect-URI validation: a verified id_token_hint
	# is authoritative; otherwise fall back to the client_id parameter.
	my $client_entry;
	if ( $info && $info->{verified} ) {
		$client_entry = $info->{client_entry};
	} elsif ( defined $client_id_param && $client_id_param ne '' ) {
		eval { $client_entry = $self->pt->getOIDCClientEntry( { clientId => $client_id_param } ) };
	}

	if ( defined $post && $post ne '' && $client_entry ) {
		my @registered = $client_entry->get_value('oidcPostLogoutRedirectURI');
		if ( grep { $_ eq $post } @registered ) {
			my $url = Mojo::URL->new($post);
			$url->query->merge( state => $state ) if defined $state && $state ne '';
			return $self->redirect_to($url);
		}
	}

	return $self->render( template => 'sso/logout', layout => 'sso' );
} ## end sub _perform_logout

sub _build_id_token {
	my ( $self, $user, $client_id, $nonce, $scope, $auth_time, $client_entry ) = @_;

	my $issuer = $self->sso_issuer;
	my $now    = time();

	# The ID token's validity is configurable separately from the access
	# token's (ssoIdTokenLifetime); it falls back to ssoTokenLifetime.
	my $lifetime = $self->pt->{ini}->{''}->{ssoIdTokenLifetime} // $self->pt->{ini}->{''}->{ssoTokenLifetime} // 3600;

	# JWT payload
	my %payload = (
		iss => $issuer,
		sub => $user,
		aud => $client_id,
		iat => $now,
		exp => $now + $lifetime,
	);
	$payload{nonce} = $nonce if $nonce && $nonce ne '';

	# auth_time (OIDC Core 2): when the End-User authentication actually
	# occurred, not when this token was issued. Falls back to now only if the
	# authentication time was not recorded.
	$payload{auth_time} = ( defined $auth_time ? $auth_time : $now ) + 0;

	# Add claims based on scope
	my %scopes = map { $_ => 1 } split /\s+/, ( $scope // '' );
	if ( $scopes{profile} || $scopes{email} ) {
		my $entry;
		$self->pt_call( sub { $entry = $self->pt->getUserEntry( { user => $user } ) } );
		if ($entry) {
			my %claims = $self->_claims_for_scopes( $entry, $user, \%scopes );
			@payload{ keys %claims } = values %claims;
		}
	}

	my $json_payload = Mojo::JSON::encode_json( \%payload );
	my $body         = b64url_encode($json_payload);

	# Determine the signing algorithm from the client entry (resolved and
	# validated by the caller). OIDC Core 2: when the client did not register
	# id_token_signed_response_alg, the default is RS256.
	my $alg = $client_entry->get_value('oidcIdTokenSignedResponseAlg');
	$alg = 'RS256' if !defined $alg || $alg eq '';
	my $jwks_json = $client_entry->get_value('oidcJwks');

	if ( $alg eq 'RS256' ) {
		# Sign with the newest private key in the client's JWKS. Key rotation
		# keeps older keys in the set as public-only entries (for verification
		# overlap), so pick the first key that still has private material.
		my $jwks = $jwks_json ? eval { decode_json($jwks_json) } : undef;
		if ( $jwks && ref $jwks->{keys} eq 'ARRAY' ) {
			my ($jwk) = grep { ref $_ eq 'HASH' && defined $_->{d} } @{ $jwks->{keys} };
			if ($jwk) {
				my $kid = $jwk->{kid} // '';
				my $header
					= b64url_encode( Mojo::JSON::encode_json( { alg => 'RS256', typ => 'JWT', kid => $kid } ) );
				my $signing_input = "$header.$body";

				my $rsa = Crypt::PK::RSA->new;
				eval { $rsa->import_key($jwk) };
				if ( !$@ ) {
					my $sig     = $rsa->sign_message( $signing_input, 'SHA256', 'v1.5' );
					my $sig_b64 = b64url_encode($sig);
					return "$signing_input.$sig_b64";
				}
			} ## end if ($jwk)
		} ## end if ( $jwks && ref $jwks->{keys} eq 'ARRAY')

		# Client requires RS256 but no usable key: do NOT downgrade to none.
		return undef;
	} elsif ( $alg eq 'HS256' ) {
		# Sign with the client secret using HMAC-SHA256
		my $secret = $client_entry->get_value('oidcClientSecret') // '';
		if ( $secret ne '' ) {
			my $header        = b64url_encode('{"alg":"HS256","typ":"JWT"}');
			my $signing_input = "$header.$body";
			require Digest::SHA;
			my $sig     = Digest::SHA::hmac_sha256( $signing_input, $secret );
			my $sig_b64 = b64url_encode($sig);
			return "$signing_input.$sig_b64";
		}

		# Client requires HS256 but has no secret: do NOT downgrade to none.
		return undef;
	} ## end elsif ( $alg eq 'HS256' )

	# 'none' (unsigned) or any unknown/unsupported algorithm: refuse to issue
	# a token rather than emit an unsigned or downgraded one. The token
	# endpoint turns this undef into a server_error.
	return undef;
} ## end sub _build_id_token

sub _build_userinfo_claims {
	my ( $self, $user, $scopes ) = @_;

	my %claims = ( sub => $user );

	my $entry;
	$self->pt_call( sub { $entry = $self->pt->getUserEntry( { user => $user } ) } );
	return \%claims unless $entry;

	%claims = ( %claims, $self->_claims_for_scopes( $entry, $user, $scopes, extended => 1 ) );

	return \%claims;
} ## end sub _build_userinfo_claims

# Map a user's LDAP attributes to OIDC claims for the requested scopes. The
# basic profile/email claims are shared by the ID token and the UserInfo
# response so the two can never disagree; extended => 1 adds the
# UserInfo-only claims (preferred_username, the oidcSubject attributes,
# locale, the verified flags, phone, and address).
sub _claims_for_scopes {
	my ( $self, $entry, $user, $scopes, %opts ) = @_;
	my $extended = $opts{extended};

	my %claims;
	my %oc = map { lc($_) => 1 } $entry->get_value('objectClass');

	if ( $scopes->{profile} ) {
		my $name = $entry->get_value('displayName') // $entry->get_value('cn');
		$claims{name}        = $name                          if defined $name;
		$claims{given_name}  = $entry->get_value('givenName') if $entry->get_value('givenName');
		$claims{family_name} = $entry->get_value('sn')        if $entry->get_value('sn');

		if ($extended) {
			$claims{preferred_username} = $user;

			# OIDC-specific claims from oidcSubject
			if ( $oc{oidcsubject} ) {
				$claims{nickname}    = $entry->get_value('oidcNickname')   if $entry->get_value('oidcNickname');
				$claims{middle_name} = $entry->get_value('oidcMiddleName') if $entry->get_value('oidcMiddleName');
				$claims{picture}     = $entry->get_value('oidcPicture')    if $entry->get_value('oidcPicture');
				$claims{profile}     = $entry->get_value('oidcProfile')    if $entry->get_value('oidcProfile');
				$claims{website}     = $entry->get_value('oidcWebsite')    if $entry->get_value('oidcWebsite');
				$claims{gender}      = $entry->get_value('oidcGender')     if $entry->get_value('oidcGender');
				$claims{birthdate}   = $entry->get_value('oidcBirthdate')  if $entry->get_value('oidcBirthdate');
				$claims{zoneinfo}    = $entry->get_value('oidcZoneinfo')   if $entry->get_value('oidcZoneinfo');
			} ## end if ( $oc{oidcsubject} )

			$claims{locale} = $entry->get_value('preferredLanguage') if $entry->get_value('preferredLanguage');
		} ## end if ($extended)
	} ## end if ( $scopes->{profile} )

	if ( $scopes->{email} ) {
		$claims{email} = $entry->get_value('mail') if $entry->get_value('mail');

		if ( $extended && $oc{oidcsubject} ) {
			my $ev = $entry->get_value('oidcEmailVerified');
			$claims{email_verified} = ( defined $ev && $ev eq 'TRUE' ) ? Mojo::JSON->true : Mojo::JSON->false
				if defined $ev;
		}
	}

	if ( $extended && $scopes->{phone} ) {
		$claims{phone_number} = $entry->get_value('telephoneNumber') if $entry->get_value('telephoneNumber');

		if ( $oc{oidcsubject} ) {
			my $pv = $entry->get_value('oidcPhoneNumberVerified');
			$claims{phone_number_verified} = ( defined $pv && $pv eq 'TRUE' ) ? Mojo::JSON->true : Mojo::JSON->false
				if defined $pv;
		}
	}

	if ( $extended && $scopes->{address} ) {
		my %addr;
		$addr{street_address} = $entry->get_value('street')     if $entry->get_value('street');
		$addr{locality}       = $entry->get_value('l')          if $entry->get_value('l');
		$addr{region}         = $entry->get_value('st')         if $entry->get_value('st');
		$addr{postal_code}    = $entry->get_value('postalCode') if $entry->get_value('postalCode');
		$addr{country}        = $entry->get_value('c')          if $entry->get_value('c');
		$claims{address}      = \%addr                          if %addr;
	}

	return %claims;
} ## end sub _claims_for_scopes

1;
