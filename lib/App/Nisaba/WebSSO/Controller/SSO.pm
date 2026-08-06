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

# Per-worker-process cache of the provider's parsed JWK Set and imported RSA
# key objects, so token issuance does not pay a JSON parse plus an RSA key
# import on top of every signature. It is validated against the raw
# oidcProviderJwks string from a freshly fetched LDAP entry on every use, so a
# key rotation takes effect on the very next request; LDAP stays the source of
# truth.
my $provider_material_cache;

# Parse a JWK Set JSON string into usable key material:
#
#   raw         - the JSON this material was built from
#   signing_key - imported Crypt::PK::RSA for the first key with private
#                 material, or undef when there is no usable one (matching
#                 _build_id_token's refusal to sign, with no fallback to a
#                 later private key)
#   signing_kid - that key's kid ('' when unset)
#   verify_keys - ordered list of { kid, key } for every importable key
#   public_keys - the public components served by the /jwks endpoint
#
# Args:
#   $jwks_json - a JWK Set as a JSON string, e.g. '{"keys":[{"kty":"RSA",...}]}'.
#                Malformed JSON, a missing keys array, and individual entries
#                that will not import are all tolerated: they contribute
#                nothing rather than aborting the parse, so one bad key cannot
#                take the whole set down.
#
# Returns the hashref described above; every list is empty and signing_key is
# undef when nothing usable was found.
sub _parse_jwks {
	my ( $self, $jwks_json ) = @_;

	my %material = (
		raw         => $jwks_json,
		signing_key => undef,
		signing_kid => '',
		verify_keys => [],
		public_keys => [],
	);

	my $jwks = eval { decode_json($jwks_json) };
	my @keys = ( $jwks && ref $jwks->{keys} eq 'ARRAY' ) ? grep { ref $_ eq 'HASH' } @{ $jwks->{keys} } : ();

	for my $jwk (@keys) {
		my $rsa = Crypt::PK::RSA->new;
		next unless eval { $rsa->import_key($jwk); 1 };
		push @{ $material{verify_keys} }, { kid => ( $jwk->{kid} // '' ), key => $rsa };

		# Only expose public components, and only for keys that actually
		# import: publishing a fragmentary (non-RSA / malformed) entry in the
		# JWKS would just break relying parties' key-set parsing.
		my %public = map { $_ => $jwk->{$_} } grep { defined $jwk->{$_} } qw(kty n e kid use alg key_ops);
		$public{use} //= 'sig';
		push @{ $material{public_keys} }, \%public;
	} ## end for my $jwk (@keys)

	# Sign with the first key that still has private material. Key rotation
	# keeps older keys in the set as public-only entries (for verification
	# overlap), so this is the newest key.
	my ($signing_jwk) = grep { defined $_->{d} } @keys;
	if ($signing_jwk) {
		my $rsa = Crypt::PK::RSA->new;
		if ( eval { $rsa->import_key($signing_jwk); 1 } ) {
			$material{signing_key} = $rsa;
			$material{signing_kid} = $signing_jwk->{kid} // '';
		}
	}

	return \%material;
} ## end sub _parse_jwks

# The provider's own signing key material, as described by _parse_jwks.
#
# There is one key set for the whole provider, not one per client. Every
# relying party validates against the single jwks_uri named in the discovery
# document, so it will accept a token signed by any key published there:
# per-client keys would give no isolation at all, while multiplying the number
# of private keys able to forge a token for every other client.
#
# Args:
#   $entry - an already-resolved oidcProvider entry, for callers that had to
#            fetch it anyway (the /jwks endpoint, which needs to tell a lookup
#            failure apart from an unprovisioned provider). Omit it and the
#            entry is fetched here.
#
# Returns the material hashref, or undef when the provider has no signing key
# yet or the lookup failed — callers must treat that as "cannot sign" rather
# than falling back to anything.
#
#   my $material = $self->_provider_jwks_material;
#   my $key      = $material && $material->{signing_key};
sub _provider_jwks_material {
	my ( $self, $entry ) = @_;

	unless ( defined $entry ) {
		my $err = $self->pt_call( sub { $entry = $self->pt->getOIDCProviderEntry } );
		return undef if $err || !$entry;
	}

	my $jwks_json = $entry->get_value('oidcProviderJwks');
	return undef unless defined $jwks_json && $jwks_json ne '';

	return $provider_material_cache
		if $provider_material_cache && $provider_material_cache->{raw} eq $jwks_json;

	$provider_material_cache = $self->_parse_jwks($jwks_json);
	return $provider_material_cache;
} ## end sub _provider_jwks_material

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

			# Request objects (OIDC Core 6) and the claims request parameter
			# (OIDC Core 5.5) are not implemented, and the authorization
			# endpoint rejects them rather than ignoring them. These must be
			# stated explicitly: request_uri_parameter_supported defaults to
			# *true* when omitted (OIDC Discovery 3), so leaving it out tells
			# relying parties the opposite of the truth.
			request_parameter_supported     => Mojo::JSON->false,
			request_uri_parameter_supported => Mojo::JSON->false,
			claims_parameter_supported      => Mojo::JSON->false,
		}
	);
} ## end sub discovery

# --------------------------------------------------------------------------- #
# JWKS endpoint — serves the provider's public signing keys
# --------------------------------------------------------------------------- #

sub jwks {
	my $self = shift;

	# A lookup failure must be a 500, not an empty key set: relying parties
	# refetch the JWKS periodically, and a 200 with no keys during a transient
	# LDAP failure would have them cache 'no keys' and reject valid ID tokens
	# until their next refresh.
	my $entry;
	my $err = $self->pt_call( sub { $entry = $self->pt->getOIDCProviderEntry } );
	if ($err) {
		return $self->render(
			json   => { error => 'server_error', error_description => 'Unable to resolve signing keys.' },
			status => 500,
		);
	}

	# An unprovisioned provider publishes an empty set — that is the truth, and
	# distinct from the failure above.
	my $material = $entry ? $self->_provider_jwks_material($entry) : undef;

	$self->render( json => { keys => ( $material ? $material->{public_keys} : [] ) } );
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

	# Request objects (OIDC Core 6) are not implemented, and must be refused
	# rather than ignored. A relying party that signs its parameters into a
	# request object expects those to be the authoritative ones; silently
	# dropping the object and honouring the query string instead would act on
	# whatever an interceptor put there. Discovery advertises both parameters
	# as unsupported.
	if ( ( $self->param('request') // '' ) ne '' ) {
		return $self->_authz_error( $redirect_uri, $state, 'request_not_supported',
			'Request objects are not supported.' );
	}
	if ( ( $self->param('request_uri') // '' ) ne '' ) {
		return $self->_authz_error( $redirect_uri, $state, 'request_uri_not_supported',
			'The request_uri parameter is not supported.' );
	}

	# The claims request parameter (OIDC Core 5.5) is likewise unimplemented;
	# an RP asking for an essential claim must not be told it succeeded.
	if ( ( $self->param('claims') // '' ) ne '' ) {
		return $self->_authz_error( $redirect_uri, $state, 'invalid_request',
			'The claims request parameter is not supported.' );
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

	# Bound the client-supplied opaque values. The pending request is stored
	# in the signed session cookie, which browsers cap at ~4 KB — an oversized
	# state or nonce would overflow the cookie and silently drop the whole
	# session, killing the user's login rather than just this request.
	if ( length($state) > 1024 ) {
		return $self->_authz_error( $redirect_uri, $state, 'invalid_request',
			'state is too long (maximum 1024 characters).' );
	}
	if ( length($nonce) > 512 ) {
		return $self->_authz_error( $redirect_uri, $state, 'invalid_request',
			'nonce is too long (maximum 512 characters).' );
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

	# Carry the scope forward de-duplicated: a scope value's meaning is a set,
	# and a repetitive-but-allowed scope string ('openid openid ...') must not
	# bloat the session cookie or the stored grants.
	{
		my %seen_scopes;
		$scope = join ' ', grep { !$seen_scopes{$_}++ } @scopes;
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

	# RFC 7636 Sections 4.1/4.2: a code_challenge is 43-128 characters from
	# the unreserved set. Enforcing the ABNF also bounds what the pending
	# request stores in the session cookie.
	if ( $code_challenge ne '' && $code_challenge !~ /\A[A-Za-z0-9\-._~]{43,128}\z/ ) {
		return $self->_authz_error( $redirect_uri, $state, 'invalid_request', 'Malformed code_challenge.' );
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
	# Taken from created rather than a second call to time() so the two cannot
	# straddle a second boundary: _authz_auth_ok treats "authenticated at or
	# after the request arrived" as satisfying both.
	$authz{min_auth_time} = $authz{created} if $prompts{login} || ( defined $max_age && $max_age == 0 );
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

	# Cap the in-flight requests so the session cookie stays under the ~4 KB
	# browser limit: keep the newest requests, at most 5 of them, and only as
	# many as fit a cumulative byte budget. The newest request (this one) is
	# always kept, even when it alone exceeds the budget — the per-parameter
	# length caps above bound how large it can be.
	my @rids = sort { ( $pending->{$b}{seq} // 0 ) <=> ( $pending->{$a}{seq} // 0 ) }
		grep { ref $pending->{$_} eq 'HASH' } keys %$pending;
	my $cumulative_bytes = 0;
	my %keep;
	for my $pending_rid (@rids) {
		my $entry_bytes = 0;
		$entry_bytes      += length( $_ // '' ) for values %{ $pending->{$pending_rid} };
		$cumulative_bytes += $entry_bytes;
		last if %keep && ( keys(%keep) >= 5 || $cumulative_bytes > 2048 );
		$keep{$pending_rid} = 1;
	}
	delete @{$pending}{ grep { !$keep{$_} } keys %$pending };
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

			# A different account signing in on this browser session must not
			# inherit anything the previous one authorized. Session consents
			# are keyed by user as well as client (see _consent_key), so this
			# is not what makes the switch safe — it keeps the session cookie
			# from accumulating an entry per user who has ever signed in here,
			# which matters against the ~4 KB browser cap. The in-flight
			# authorization requests are deliberately kept: they belong to the
			# browser, not to a user, and the one being answered right now is
			# usually the reason this login happened.
			my $previous_user = $c->session('sso_user');
			delete $c->session->{sso_consents}
				if defined $previous_user && $previous_user ne '' && $previous_user ne $user;

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
	my $key      = $self->_consent_key( $user, $authz->{client_id} );
	my $consents = $self->session('sso_consents');
	$consents = {} unless ref $consents eq 'HASH';
	my %granted = map { $_ => 1 } split( ' ', $consents->{$key} // '' ), split( ' ', $authz->{scope} // '' );
	$consents->{$key} = join ' ', sort keys %granted;
	$self->session( sso_consents => $consents );

	# When asked to, also persist the grant in the shared store so it survives
	# this browser session: later visits skip the consent screen and silent
	# (prompt=none) requests succeed after any fresh login.
	if ( $self->param('remember') ) {
		my $existing = $self->sso_storage->get( 'consent', $key );
		my %all      = map { $_ => 1 } split( ' ', ( ( $existing && $existing->{scopes} ) // '' ) ),
			split( ' ', $authz->{scope} // '' );
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

	# A request authenticated by a verifiable id_token_hint that belongs to
	# the current session can be logged out without prompting. Otherwise we
	# must confirm with the user to prevent a malicious third party from
	# forcing a logout via a crafted link.
	my $info = $self->_verify_id_token_hint($hint);
	if ( $self->_logout_hint_authorizes( $info, $cid ) ) {
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
	# authenticates itself with a verifiable id_token_hint belonging to the
	# current session; anything else must be our own confirmation form, which
	# carries the session's CSRF token. A cross-site POST without either gets
	# the confirmation page, not a logout.
	unless ( $self->_logout_hint_authorizes( $info, $cid ) ) {
		unless ( App::Nisaba::WebCSRF::token_valid($self) ) {
			return $self->render(
				template                 => 'sso/logout_confirm',
				layout                   => 'sso',
				post_logout_redirect_uri => $post,
				state                    => $state,
				client_id                => $cid,
			);
		}
	} ## end unless ( $self->_logout_hint_authorizes( $info...))

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
		# RFC 6749 Section 2.3: a client MUST NOT use more than one
		# authentication mechanism per request, and a client_id duplicated in
		# the body must agree with the Authorization header's.
		if ( $body_secret ne '' || ( $client_id ne '' && defined $hdr_id && $hdr_id ne $client_id ) ) {
			$self->render(
				json   => { error => 'invalid_request', error_description => 'Conflicting client authentication.' },
				status => 400,
			);
			return ();
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

		# A code presented twice has leaked (RFC 6749 Section 4.1.2): revoke
		# the tokens the first redemption produced rather than leaving them
		# live in whoever's hands got there first.
		$self->_detect_replay( 'code', $code );

		return $self->render(
			json   => { error => 'invalid_grant', error_description => 'Authorization code not found or expired.' },
			status => 400,
		);
	} ## end unless ($code_data)

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

	# A grant_id ties every token minted from this authorization grant
	# together, so revoking the refresh token can also invalidate the access
	# tokens issued alongside it (RFC 7009 Section 2.1). Minted for every
	# grant, not just those that get a refresh token: replay of the
	# authorization code has to be able to cascade to the access token too.
	my %grant_types = map { $_ => 1 } $client_entry->get_value('oidcGrantType');
	my $grant_id    = random_b64url(16);

	# Record the redemption before handing anything out, so a replay that
	# arrives while this response is still in flight finds the tombstone.
	$self->_mark_redeemed( 'code', $code, $grant_id );

	my $access_token = $self->_issue_access_token( $code_data->{user}, $code_data->{scope}, $client_id, $grant_id );

	# Issue a refresh token only when the client's registration allows the
	# refresh_token grant.
	my $refresh_token;
	if ( $grant_types{refresh_token} ) {
		$refresh_token = $self->_issue_refresh_token(
			{
				user            => $code_data->{user},
				scope           => $code_data->{scope},
				client_id       => $client_id,
				auth_time       => $code_data->{auth_time},
				grant_id        => $grant_id,
				grant_issued_at => time(),
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

		# Rotation exists so that a stolen refresh token shows up as a replay:
		# the thief and the legitimate client both present the same value, and
		# whichever arrives second finds it already retired. That is the signal
		# the token leaked, so tear the grant down (RFC 9700 Section 4.14.2)
		# instead of only refusing this request and leaving the winner of the
		# race holding a working chain.
		$self->_detect_replay( 'refresh', $presented );

		return $self->render(
			json   => { error => 'invalid_grant', error_description => 'Refresh token not found or expired.' },
			status => 400,
		);
	} ## end unless ($rt_data)

	# Retire the presented token by name as well: consume() already removed it,
	# but the tombstone is what makes a later replay recognisable.
	$self->_mark_redeemed( 'refresh', $presented, $rt_data->{grant_id} );

	# The grant may have been torn down while this token was still live —
	# by a revocation (RFC 7009 Section 2.1) or by replay detected on a
	# sibling credential from the same chain.
	if ( $self->_grant_revoked( $rt_data->{grant_id} ) ) {
		return $self->render(
			json   => { error => 'invalid_grant', error_description => 'The grant has been revoked.' },
			status => 400,
		);
	}

	# The refresh-token lifetime is absolute, measured from the original
	# authorization grant: rotation hands out successor tokens, but must not
	# extend the chain's life indefinitely. (grant_issued_at falls back to the
	# token's own issued_at for records that predate the chain timestamp.)
	my $rt_lifetime   = $self->pt->{ini}->{''}->{ssoRefreshTokenLifetime} // 2592000;
	my $chain_started = $rt_data->{grant_issued_at}                       // $rt_data->{issued_at};
	if ( ( time() - $chain_started ) > $rt_lifetime ) {
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

	my $access_token = $self->_issue_access_token( $rt_data->{user}, $scope, $client_id, $rt_data->{grant_id} );

	# Rotate: the old token is already retired; hand out a successor carrying
	# the original (un-narrowed) grant, its grant_id, and the chain's original
	# issue time so the absolute lifetime keeps counting.
	my $new_refresh_token = $self->_issue_refresh_token(
		{
			user            => $rt_data->{user},
			scope           => $rt_data->{scope},
			client_id       => $client_id,
			auth_time       => $rt_data->{auth_time},
			grant_id        => $rt_data->{grant_id},
			grant_issued_at => $chain_started,
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
# introspection enforce the protocol expiry from issued_at. The optional
# grant_id links the token to its refresh-token chain for revocation
# cascading.
sub _issue_access_token {
	my ( $self, $user, $scope, $client_id, $grant_id ) = @_;
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
			( defined $grant_id ? ( grant_id => $grant_id ) : () ),
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
# Grant teardown and single-use replay detection
# --------------------------------------------------------------------------- #

# Kill an entire authorization grant: every access token minted from it, and
# any refresh token still holding it. Tokens are stored hashed and carry no
# back-reference, so revocation is a tombstone on the grant_id that UserInfo,
# introspection and the refresh grant all consult before honouring a token.
#
# Args:
#   $grant_id - the grant chain to tear down. A no-op when undef or empty, so
#               callers do not have to guard.
#
# Returns nothing. The tombstone's TTL is the refresh-token lifetime: it need
# only outlive the longest-lived thing that could still present the grant, and
# no token from the grant can outlive that.
#
#   $self->_revoke_grant( $rt_data->{grant_id} );
sub _revoke_grant {
	my ( $self, $grant_id ) = @_;
	return unless defined $grant_id && $grant_id ne '';
	my $rt_lifetime = $self->pt->{ini}->{''}->{ssoRefreshTokenLifetime} // 2592000;
	$self->sso_storage->put( 'revoked_grant', $grant_id, { revoked_at => time() }, $rt_lifetime );
	return;
}

# Has this grant been torn down by _revoke_grant?
#
# Args:
#   $grant_id - the grant chain to test; undef is never revoked.
#
# Returns 1 when a tombstone exists, 0 otherwise.
sub _grant_revoked {
	my ( $self, $grant_id ) = @_;
	return 0 unless defined $grant_id && $grant_id ne '';
	return $self->sso_storage->get( 'revoked_grant', $grant_id ) ? 1 : 0;
}

# Remember that a single-use credential has been redeemed. consume() removes
# the credential itself, which is what enforces single use; this records only
# that it *was* used and which grant it produced, so a later replay can be told
# apart from an ordinary expiry.
#
# Args:
#   $kind     - the store namespace the credential was consumed from, either
#               'code' (authorization code) or 'refresh' (refresh token)
#   $key      - the raw code or token string that was presented. It is hashed
#               before storage by App::Nisaba::WebSSO::Storage, as everywhere
#               else, so redeemed credentials are not recoverable from the
#               store either.
#   $grant_id - the grant the redemption produced or belonged to.
#
# Returns nothing.
#
#   $self->_mark_redeemed( 'refresh', $presented, $rt_data->{grant_id} );
sub _mark_redeemed {
	my ( $self, $kind, $key, $grant_id ) = @_;
	my $rt_lifetime = $self->pt->{ini}->{''}->{ssoRefreshTokenLifetime} // 2592000;
	$self->sso_storage->put(
		'redeemed',
		$kind . ':' . $key,
		{ redeemed_at => time(), ( defined $grant_id ? ( grant_id => $grant_id ) : () ) }, $rt_lifetime,
	);
	return;
} ## end sub _mark_redeemed

# Called when a single-use credential was not found. If it was not found
# because it had already been redeemed, then two parties are presenting the
# same credential and it has leaked — refusing just this request would leave
# whichever of them redeemed first in possession of a working grant. RFC 9700
# Section 4.14.2 (rotated refresh tokens) and RFC 6749 Section 4.1.2
# (authorization codes) both call for tearing down the whole grant instead.
#
# Args:
#   $kind - the store namespace, 'code' or 'refresh', as passed to
#           _mark_redeemed
#   $key  - the raw code or token string that was presented
#
# Returns 1 when this was a replay (and the grant has been revoked), 0 when the
# credential was simply unknown or expired. The caller answers invalid_grant
# either way: telling the two cases apart would confirm to an attacker that a
# stolen token had been valid.
#
#   $self->_detect_replay( 'refresh', $presented );
sub _detect_replay {
	my ( $self, $kind, $key ) = @_;
	my $redeemed = $self->sso_storage->get( 'redeemed', $kind . ':' . $key );
	return 0 unless $redeemed;
	$self->_revoke_grant( $redeemed->{grant_id} );
	return 1;
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
			next unless ( $data->{client_id} // '' ) eq $client_id;
			$self->sso_storage->delete( $kind, $token );

			# RFC 7009 Section 2.1: revoking a refresh token SHOULD also
			# invalidate the access tokens based on the same grant.
			$self->_revoke_grant( $data->{grant_id} ) if $kind eq 'refresh';
		} ## end for my $kind (qw(token refresh))
	} ## end if ( $token ne '' )

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

	# Unknown or foreign tokens are simply "not active" (RFC 7662 Section 2.2)
	# — never leak another client's token metadata.
	unless ( $data && ( $data->{client_id} // '' ) eq $client_id ) {
		return $self->render( json => { active => Mojo::JSON->false } );
	}

	my $lifetime
		= $kind eq 'refresh'
		? ( $self->pt->{ini}->{''}->{ssoRefreshTokenLifetime} // 2592000 )
		: ( $self->pt->{ini}->{''}->{ssoTokenLifetime} // 3600 );

	# A refresh token's life is absolute, measured from the original
	# authorization grant: rotation hands out successors but does not extend
	# the chain, which is exactly how _token_refresh decides. Measuring from
	# the successor's own issued_at instead would report a chain that /token
	# already rejects as active, and hand the caller an exp in the future for a
	# token that is dead. iat stays this token's own issue time.
	my $issued_at = $data->{issued_at} // 0;
	my $expires_at
		= ( $kind eq 'refresh' ? ( $data->{grant_issued_at} // $issued_at ) : $issued_at ) + $lifetime;

	if ( time() > $expires_at ) {
		return $self->render( json => { active => Mojo::JSON->false } );
	}

	# A token whose grant was torn down — revoked (RFC 7009 Section 2.1) or
	# replayed — is no longer active either.
	if ( $self->_grant_revoked( $data->{grant_id} ) ) {
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
			iat        => ( $issued_at + 0 ),
			exp        => ( $expires_at + 0 ),
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

	# An access token whose grant was torn down — revoked (RFC 7009 Section
	# 2.1) or replayed — is no longer valid.
	if ( $self->_grant_revoked( $token_data->{grant_id} ) ) {
		$self->sso_storage->delete( 'token', $token );
		$self->res->headers->www_authenticate('Bearer error="invalid_token"');
		return $self->render( json => { error => 'invalid_token' }, status => 401 );
	}

	# The relying party the token was issued to must still be registered.
	# Deleting a client has to take its outstanding access tokens with it, and
	# nothing else here would notice: the grant store keeps no back-reference
	# from a token to a client entry, so without this check a deleted client
	# keeps reading user claims until the token's own lifetime runs out. A
	# lookup that errors out is a 500, not a 401 — a directory that is briefly
	# unreachable must not destroy live tokens.
	my $client_entry;
	my $client_err
		= $self->pt_call(
			sub { $client_entry = $self->pt->getOIDCClientEntry( { clientId => ( $token_data->{client_id} // '' ) } ) }
		);
	if ($client_err) {
		return $self->render(
			json   => { error => 'server_error', error_description => 'Unable to resolve client.' },
			status => 500,
		);
	}
	unless ($client_entry) {
		$self->sso_storage->delete( 'token', $token );
		$self->res->headers->www_authenticate('Bearer error="invalid_token"');
		return $self->render( json => { error => 'invalid_token' }, status => 401 );
	}

	my $user   = $token_data->{user};
	my %scopes = map { $_ => 1 } split ' ', ( $token_data->{scope} // '' );

	# Build claims
	my ( $claims, $claims_error ) = $self->_build_userinfo_claims( $user, \%scopes );

	# A subject that no longer resolves in the directory ends the token: an
	# answer of 200 with a bare sub would have relying parties treat a deleted
	# account as a live one. A lookup that merely failed leaves the token
	# alone and reports a server error.
	if ( ( $claims_error // '' ) eq 'not_found' ) {
		$self->sso_storage->delete( 'token', $token );
		$self->res->headers->www_authenticate('Bearer error="invalid_token"');
		return $self->render( json => { error => 'invalid_token' }, status => 401 );
	}
	if ( !$claims ) {
		return $self->render(
			json   => { error => 'server_error', error_description => 'Unable to resolve user claims.' },
			status => 500,
		);
	}

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

	# An authentication at or after the moment this request arrived was
	# performed *for* this request, which settles both constraints by
	# construction. Without this escape hatch, max_age is measured against a
	# wall clock that keeps running while the user reads the consent screen, so
	# any value shorter than a human takes to click "Allow" bounces them back
	# to login — where a successful login lands on consent again, forever.
	# max_age=0, which OIDC Core defines as equivalent to prompt=login, could
	# never complete at all. The RP can still enforce a stricter reading: the
	# ID token always carries auth_time.
	my $requested_at = $authz->{created};
	return 1 if defined $requested_at && $auth_time >= $requested_at;

	return 0 if defined $authz->{min_auth_time} && $auth_time < $authz->{min_auth_time};
	return 0 if defined $authz->{max_age}       && ( time() - $auth_time ) > $authz->{max_age};
	return 1;
} ## end sub _authz_auth_ok

# The key a consent record is filed under, for both the session map and the
# durable store. Consent is granted by a specific End-User to a specific
# client, so it must be keyed by both: an SSO session outlives the account that
# started it (signing in at /sso/login replaces the session's user without
# tearing the session down), and a map keyed by client alone would let a
# consent Alice granted silently authorize Bob's account to the same client.
#
# Args:
#   $user      - the End-User the consent belongs to; the LDAP username, as
#                stored in the session's sso_user
#   $client_id - the oidcClientId the consent was granted to
#
# Returns the two joined by a NUL, which cannot occur in either. Both are
# treated as the empty string when undef, so a caller that has not resolved a
# user cannot collide with one that has.
#
#   my $key = $self->_consent_key( 'alice', 'testapp' );   # "alice\0testapp"
sub _consent_key {
	my ( $self, $user, $client_id ) = @_;
	return ( defined $user ? $user : '' ) . "\0" . ( defined $client_id ? $client_id : '' );
}

# The scopes this user has granted the client, as a hash: the union of the
# consents recorded in this browser session and the durable per-user consents
# in the shared store ("remember this decision"). Both are keyed by
# _consent_key, so neither can be read across a user switch.
sub _consented_scopes {
	my ( $self, $user, $client_id ) = @_;
	my %granted;
	return %granted unless defined $user && $user ne '' && defined $client_id && $client_id ne '';

	my $key = $self->_consent_key( $user, $client_id );

	my $consents = $self->session('sso_consents');
	if ( ref $consents eq 'HASH' ) {
		$granted{$_} = 1 for split ' ', ( $consents->{$key} // '' );
	}

	my $durable = $self->sso_storage->get( 'consent', $key );
	$granted{$_} = 1 for split ' ', ( ( $durable && $durable->{scopes} ) // '' );

	return %granted;
} ## end sub _consented_scopes

# Does an existing consent (session or durable) cover every scope of this
# pending request?
sub _consent_covers {
	my ( $self, $authz ) = @_;
	my %granted = $self->_consented_scopes( $self->session('sso_user'), $authz->{client_id} );
	return !grep { !$granted{$_} } split ' ', ( $authz->{scope} // '' );
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
		my $material = $self->_provider_jwks_material;
		if ($material) {
			# Select the verification key by the token's kid so hints signed
			# with a rotated-out-but-retained key still verify; with no kid (or
			# no match) fall back to trying every key in the set.
			my @keys       = @{ $material->{verify_keys} };
			my $kid        = $header      ? $header->{kid}                   : undef;
			my @candidates = defined $kid ? grep { $_->{kid} eq $kid } @keys : ();
			@candidates = @keys unless @candidates;
			for my $candidate (@candidates) {
				if ( eval { $candidate->{key}->verify_message( $sig, $signing_input, 'SHA256', 'v1.5' ) } ) {
					$verified = 1;
					last;
				}
			}
		} ## end if ($material)
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

# Does a parsed id_token_hint authorize a logout without user confirmation?
# Cryptographic verification alone is not enough (OIDC RP-Initiated Logout
# 1.0): a client_id parameter, when present, MUST match the token's audience,
# and the token must identify the End-User of the current session — any other
# user's ID token (e.g. an attacker's own, embedded in a crafted link) gets
# the confirmation page instead of silently forcing the victim's logout.
sub _logout_hint_authorizes {
	my ( $self, $info, $client_id_param ) = @_;
	return 0 unless $info && $info->{verified};
	return 0
		if defined $client_id_param
		&& $client_id_param ne ''
		&& $client_id_param ne $info->{client_id};
	my $session_user = $self->session('sso_user');
	return 0
		if defined $session_user
		&& $session_user ne ''
		&& ( $info->{payload}{sub} // '' ) ne $session_user;
	return 1;
} ## end sub _logout_hint_authorizes

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

	if ( $alg eq 'RS256' ) {
		# Sign with the newest private key in the provider's JWK Set (the
		# cached, already-imported key object; see _provider_jwks_material).
		my $material = $self->_provider_jwks_material;
		if ( $material && $material->{signing_key} ) {
			my $header = b64url_encode(
				Mojo::JSON::encode_json( { alg => 'RS256', typ => 'JWT', kid => $material->{signing_kid} } ) );
			my $signing_input = "$header.$body";
			my $sig           = $material->{signing_key}->sign_message( $signing_input, 'SHA256', 'v1.5' );
			my $sig_b64       = b64url_encode($sig);
			return "$signing_input.$sig_b64";
		}

		# RS256 was asked for but the provider has no usable signing key: do
		# NOT downgrade to none. The token endpoint turns this into a
		# server_error, which is the honest answer to an unprovisioned OP.
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

# Resolve a user's UserInfo claims from the directory.
#
# Args:
#   $user   - the subject to look up; the LDAP username carried in the access
#             token's grant record
#   $scopes - hashref of the scopes the token was issued for, as
#             { openid => 1, profile => 1, ... }; selects which claims are
#             included, see _claims_for_scopes
#
# Returns the two-element list ( $claims, $error ):
#
#   - $claims :: hashref of OIDC claims including sub, or undef when nothing
#     could be resolved
#   - $error :: '' when the claims are good, 'not_found' when the directory
#     has no such user, or 'unavailable' when the lookup itself failed
#
# The distinction matters to the caller: a deleted account has to invalidate
# the access token, while a directory that is momentarily unreachable must
# leave it alone. App::Nisaba reports a clean miss as error 17 and a search
# that genuinely failed as 32 (or a die, which pt_call turns into a string).
#
#   my ( $claims, $error ) = $self->_build_userinfo_claims( 'alice', { openid => 1, email => 1 } );
#   # ( { sub => 'alice', email => 'alice@example.org' }, '' )
sub _build_userinfo_claims {
	my ( $self, $user, $scopes ) = @_;

	my $entry;
	$self->pt_call( sub { $entry = $self->pt->getUserEntry( { user => $user } ) } );
	unless ($entry) {
		return ( undef, ( ( $self->pt->error // 0 ) == 17 ) ? 'not_found' : 'unavailable' );
	}

	my %claims = ( sub => $user, $self->_claims_for_scopes( $entry, $user, $scopes, extended => 1 ) );

	return ( \%claims, '' );
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
