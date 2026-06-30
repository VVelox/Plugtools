package App::Nisaba::WebSSO::Controller::SSO;

use Mojo::Base 'Mojolicious::Controller';
use Mojo::URL;
use Mojo::Util   qw(b64_encode b64_decode);
use MIME::Base64 ();
use Digest::SHA  qw(sha256);

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

sub _pt_call {
	my ( $self, $code ) = @_;
	eval { $code->() };
	return $@ if $@;
	if ( $self->pt->error ) {
		return $self->pt->errorString || ( 'Error code ' . $self->pt->error );
	}
	return '';
}

# Generate a random base64url string
sub _random_b64url {
	my ($len) = @_;
	$len //= 32;
	my $bytes = '';
	open my $fh, '<:raw', '/dev/urandom' or return undef;
	read $fh, $bytes, $len;
	close $fh;
	my $b64 = MIME::Base64::encode_base64( $bytes, '' );
	$b64 =~ tr|+/|-_|;
	$b64 =~ s/=+$//;
	return $b64;
} ## end sub _random_b64url

# Base64url encode without padding
sub _b64url_encode {
	my ($data) = @_;
	my $b64 = MIME::Base64::encode_base64( $data, '' );
	$b64 =~ tr|+/|-_|;
	$b64 =~ s/=+$//;
	return $b64;
}

# Base64url decode
sub _b64url_decode {
	my ($b64u) = @_;
	$b64u =~ tr|-_|+/|;
	while ( length($b64u) % 4 ) { $b64u .= '=' }
	return MIME::Base64::decode_base64($b64u);
}

# --------------------------------------------------------------------------- #
# OIDC Discovery
# --------------------------------------------------------------------------- #

sub discovery {
	my $self   = shift;
	my $issuer = $self->sso_issuer;

	$self->render(
		json => {
			issuer                                => $issuer,
			authorization_endpoint                => "$issuer/authorize",
			token_endpoint                        => "$issuer/token",
			userinfo_endpoint                     => "$issuer/userinfo",
			response_types_supported              => ['code'],
			grant_types_supported                 => ['authorization_code'],
			subject_types_supported               => [ 'public', 'pairwise' ],
			id_token_signing_alg_values_supported => ['none'],
			scopes_supported                      => [ 'openid', 'profile', 'email', 'phone', 'address' ],
			token_endpoint_auth_methods_supported => [ 'client_secret_basic', 'client_secret_post', 'none', ],
			claims_supported                      => [
				'sub',          'name',                  'given_name',         'family_name',
				'middle_name',  'nickname',              'preferred_username', 'profile',
				'picture',      'website',               'email',              'email_verified',
				'gender',       'birthdate',             'zoneinfo',           'locale',
				'phone_number', 'phone_number_verified', 'address',            'updated_at',
			],
			code_challenge_methods_supported => [ 'S256', 'plain' ],
		}
	);
} ## end sub discovery

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
	my $err = $self->_pt_call( sub { $client_entry = $self->pt->getOIDCClientEntry( { clientId => $client_id } ) } );
	if ( $err || !$client_entry ) {
		return $self->render(
			template          => 'sso/error',
			layout            => 'sso',
			error_title       => 'Unknown Client',
			error_description => "The client_id '$client_id' is not registered.",
		);
	}

	# Validate redirect_uri
	my @registered_uris = $client_entry->get_value('oidcRedirectURI');
	if ( @registered_uris && !grep { $_ eq $redirect_uri } @registered_uris ) {
		return $self->render(
			template          => 'sso/error',
			layout            => 'sso',
			error_title       => 'Invalid Redirect URI',
			error_description => 'The redirect_uri does not match any registered URI for this client.',
		);
	}

	# Only support authorization code flow
	if ( $response_type ne 'code' ) {
		return $self->_authz_error( $redirect_uri, $state, 'unsupported_response_type',
			'Only response_type=code is supported.' );
	}

	# Scope must include openid
	my @scopes = split /\s+/, $scope;
	unless ( grep { $_ eq 'openid' } @scopes ) {
		return $self->_authz_error( $redirect_uri, $state, 'invalid_scope', 'The openid scope is required.' );
	}

	# Store the authorization request in session
	$self->session(
		sso_authz => {
			client_id             => $client_id,
			redirect_uri          => $redirect_uri,
			scope                 => $scope,
			state                 => $state,
			nonce                 => $nonce,
			code_challenge        => $code_challenge,
			code_challenge_method => $code_challenge_method,
		}
	);

	# If user is already authenticated, go straight to consent
	if ( $self->session('sso_user') ) {
		return $self->redirect_to('sso_consent');
	}

	# Otherwise, redirect to login
	$self->redirect_to('sso_login');
} ## end sub authorize

# --------------------------------------------------------------------------- #
# Login
# --------------------------------------------------------------------------- #

sub login_form {
	my $self = shift;
	unless ( $self->session('sso_authz') ) {
		return $self->render(
			template          => 'sso/error',
			layout            => 'sso',
			error_title       => 'No Authorization Request',
			error_description => 'Please start from the application you want to sign in to.',
		);
	}
	$self->render( template => 'sso/login', layout => 'sso' );
} ## end sub login_form

sub login {
	my $self = shift;
	my $user = $self->param('user') // '';
	my $pass = $self->param('pass') // '';

	my $err = $self->_pt_call( sub { $self->pt->userVerifyPassword( { user => $user, password => $pass } ) } );
	if ($err) {
		$self->flash( error => 'Invalid username or password.' );
		return $self->redirect_to('sso_login');
	}

	# Check whether TOTP is active for this user
	my $info;
	$self->_pt_call( sub { $info = $self->pt->userSelfInfo( { user => $user } ) } );
	if ( $info && ( $info->{totpStatus} // '' ) eq 'active' ) {
		$self->session( sso_totp_pending_user => $user );
		return $self->redirect_to('sso_totp_challenge');
	}

	$self->session( sso_user => $user );
	$self->redirect_to('sso_consent');
} ## end sub login

# --------------------------------------------------------------------------- #
# Passkey login for SSO
# --------------------------------------------------------------------------- #

sub passkey_login_start {
	my $self = shift;

	my $challenge_b64 = _random_b64url(32);
	$self->session( sso_passkey_login_challenge => $challenge_b64 );

	my $rp_id = $self->pt->{ini}->{''}->{passkeyRpId}             || $self->req->url->to_abs->host;
	my $uv    = $self->pt->{ini}->{''}->{passkeyUserVerification} || 'preferred';

	$self->render(
		json => {
			challenge        => $challenge_b64,
			rpId             => $rp_id,
			userVerification => $uv,
			allowCredentials => [],
			timeout          => 60000,
		}
	);
} ## end sub passkey_login_start

sub passkey_login_finish {
	my $self = shift;

	my $challenge_b64 = $self->session('sso_passkey_login_challenge');
	unless ($challenge_b64) {
		return $self->render( json => { error => 'No login in progress' }, status => 400 );
	}
	delete $self->session->{sso_passkey_login_challenge};

	my $body = $self->req->json;
	unless ( $body && ref $body->{response} eq 'HASH' ) {
		return $self->render( json => { error => 'Invalid request body' }, status => 400 );
	}

	my $credential_id = $body->{id} // '';
	unless ($credential_id) {
		return $self->render( json => { error => 'Missing credential ID' }, status => 400 );
	}

	my $found;
	my $find_err = $self->_pt_call(
		sub { $found = $self->pt->userPasskeyFindByCredentialId( { credentialId => $credential_id } ) } );
	if ( $find_err || !$found ) {
		return $self->render( json => { error => 'Unknown passkey' }, status => 401 );
	}

	my $user = $found->{user};
	my $cred = $found->{credential};

	my $url    = $self->req->url->to_abs;
	my $rp_id  = $self->pt->{ini}->{''}->{passkeyRpId}             || $url->host;
	my $uv     = $self->pt->{ini}->{''}->{passkeyUserVerification} || 'preferred';
	my $origin = $url->scheme . '://' . $url->host;
	my $port   = $url->port;
	$origin .= ":$port"
		if $port
		&& !( ( $url->scheme eq 'https' && $port == 443 ) || ( $url->scheme eq 'http' && $port == 80 ) );

	my $wa = eval { require Authen::WebAuthn; Authen::WebAuthn->new( rp_id => $rp_id, origin => $origin ) };
	unless ($wa) {
		return $self->render(
			json   => { error => 'WebAuthn not available on this server' },
			status => 501,
		);
	}

	my $result = eval {
		$wa->validate_assertion(
			challenge_b64          => $challenge_b64,
			credential_pubkey_b64  => $cred->{cosePublicKey},
			stored_sign_count      => $cred->{signCount},
			requested_uv           => $uv,
			client_data_json_b64   => $body->{response}{clientDataJSON},
			authenticator_data_b64 => $body->{response}{authenticatorData},
			signature_b64          => $body->{response}{signature},
			user_handle_b64        => $body->{response}{userHandle},
			token_binding_id_b64   => undef,
		);
	};
	if ($@) {
		( my $msg = $@ ) =~ s/ at \S+ line \d+\.?\s*$//;
		return $self->render( json => { error => "Verification failed: $msg" }, status => 401 );
	}

	# Update sign count (best-effort)
	$self->_pt_call(
		sub {
			$self->pt->userPasskeyCredentialUpdate(
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
	$self->_pt_call( sub { $info = $self->pt->userSelfInfo( { user => $user } ) } );
	if ( $info && ( $info->{totpStatus} // '' ) eq 'active' ) {
		$self->session( sso_totp_pending_user => $user );
		return $self->render( json => { ok => 1, totp_required => 1 } );
	}

	$self->session( sso_user => $user );
	$self->render( json => { ok => 1 } );
} ## end sub passkey_login_finish

# --------------------------------------------------------------------------- #
# TOTP challenge
# --------------------------------------------------------------------------- #

sub totp_challenge_form {
	my $self = shift;
	unless ( $self->session('sso_totp_pending_user') ) {
		return $self->redirect_to('sso_login');
	}
	$self->render( template => 'sso/totp_challenge', layout => 'sso' );
}

sub totp_challenge {
	my $self = shift;
	my $user = $self->session('sso_totp_pending_user');
	unless ($user) {
		return $self->redirect_to('sso_login');
	}

	my $code = $self->param('code') // '';

	my $ok;
	my $err = $self->_pt_call( sub { $ok = $self->pt->userTotpVerify( { user => $user, code => $code } ) } );
	if ( $err || !$ok ) {
		$self->flash( error => 'Invalid TOTP code. Please try again.' );
		return $self->redirect_to('sso_totp_challenge');
	}

	delete $self->session->{sso_totp_pending_user};
	$self->session( sso_user => $user );
	$self->redirect_to('sso_consent');
} ## end sub totp_challenge

# --------------------------------------------------------------------------- #
# Consent
# --------------------------------------------------------------------------- #

sub consent_form {
	my $self = shift;

	my $authz = $self->session('sso_authz');
	unless ($authz) {
		return $self->render(
			template          => 'sso/error',
			layout            => 'sso',
			error_title       => 'No Authorization Request',
			error_description => 'Please start from the application you want to sign in to.',
		);
	}

	my $user = $self->session('sso_user');
	unless ($user) {
		return $self->redirect_to('sso_login');
	}

	# Look up client for display info
	my $client_entry;
	$self->_pt_call( sub { $client_entry = $self->pt->getOIDCClientEntry( { clientId => $authz->{client_id} } ) } );

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

	my $authz = $self->session('sso_authz');
	my $user  = $self->session('sso_user');
	unless ( $authz && $user ) {
		return $self->redirect_to('sso_login');
	}

	my $decision = $self->param('decision') // '';
	if ( $decision ne 'allow' ) {
		# User denied consent
		return $self->_authz_error(
			$authz->{redirect_uri},
			$authz->{state}, 'access_denied', 'The user denied the authorization request.',
		);
	}

	# Generate authorization code
	my $code = _random_b64url(32);

	# Store code details in session (in production, use a shared store)
	$self->session(
		'sso_code_'
			. $code => {
				client_id             => $authz->{client_id},
				redirect_uri          => $authz->{redirect_uri},
				scope                 => $authz->{scope},
				nonce                 => $authz->{nonce},
				user                  => $user,
				issued_at             => time(),
				code_challenge        => $authz->{code_challenge},
				code_challenge_method => $authz->{code_challenge_method},
			}
	);

	# Clean up authorization session
	delete $self->session->{sso_authz};

	# Redirect to client with code
	my $url = Mojo::URL->new( $authz->{redirect_uri} );
	$url->query->merge( code  => $code );
	$url->query->merge( state => $authz->{state} ) if $authz->{state} ne '';
	$self->redirect_to($url);
} ## end sub consent

# --------------------------------------------------------------------------- #
# Token endpoint
# --------------------------------------------------------------------------- #

sub token {
	my $self = shift;

	my $grant_type = $self->param('grant_type') // '';
	if ( $grant_type ne 'authorization_code' ) {
		return $self->render(
			json   => { error => 'unsupported_grant_type' },
			status => 400,
		);
	}

	my $code         = $self->param('code')         // '';
	my $redirect_uri = $self->param('redirect_uri') // '';
	my $client_id    = $self->param('client_id')    // '';

	# Client authentication: check Authorization header for client_secret_basic
	my $client_secret = $self->param('client_secret')      // '';
	my $auth_header   = $self->req->headers->authorization // '';
	if ( $auth_header =~ /^Basic\s+(.+)$/i ) {
		my $decoded = MIME::Base64::decode_base64($1);
		my ( $hdr_id, $hdr_secret ) = split /:/, $decoded, 2;
		$client_id     = $hdr_id     // $client_id;
		$client_secret = $hdr_secret // $client_secret;
	}

	# Look up authorization code
	my $code_data = $self->session( 'sso_code_' . $code );
	unless ($code_data) {
		return $self->render(
			json   => { error => 'invalid_grant', error_description => 'Authorization code not found or expired.' },
			status => 400,
		);
	}

	# Delete the code (one-time use)
	delete $self->session->{ 'sso_code_' . $code };

	# Validate code hasn't expired
	my $code_lifetime = $self->pt->{ini}->{''}->{ssoCodeLifetime} // 600;
	if ( ( time() - $code_data->{issued_at} ) > $code_lifetime ) {
		return $self->render(
			json   => { error => 'invalid_grant', error_description => 'Authorization code expired.' },
			status => 400,
		);
	}

	# Validate client_id matches
	if ( $client_id ne $code_data->{client_id} ) {
		return $self->render(
			json   => { error => 'invalid_grant', error_description => 'client_id mismatch.' },
			status => 400,
		);
	}

	# Validate redirect_uri matches
	if ( $redirect_uri ne '' && $redirect_uri ne $code_data->{redirect_uri} ) {
		return $self->render(
			json   => { error => 'invalid_grant', error_description => 'redirect_uri mismatch.' },
			status => 400,
		);
	}

	# Validate PKCE code_verifier if code_challenge was provided
	if ( $code_data->{code_challenge} && $code_data->{code_challenge} ne '' ) {
		my $code_verifier = $self->param('code_verifier') // '';
		unless ($code_verifier) {
			return $self->render(
				json   => { error => 'invalid_grant', error_description => 'code_verifier required.' },
				status => 400,
			);
		}

		my $method = $code_data->{code_challenge_method} || 'plain';
		my $expected;
		if ( $method eq 'S256' ) {
			$expected = _b64url_encode( sha256($code_verifier) );
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

	# Validate client_secret for confidential clients
	my $client_entry;
	$self->_pt_call( sub { $client_entry = $self->pt->getOIDCClientEntry( { clientId => $client_id } ) } );
	if ($client_entry) {
		my $stored_secret = $client_entry->get_value('oidcClientSecret') // '';
		if ( $stored_secret ne '' && $client_secret ne $stored_secret ) {
			return $self->render(
				json   => { error => 'invalid_client', error_description => 'Client authentication failed.' },
				status => 401,
			);
		}
	}

	# Generate access token
	my $access_token   = _random_b64url(32);
	my $token_lifetime = $self->pt->{ini}->{''}->{ssoTokenLifetime} // 3600;

	# Store token in session for userinfo lookup
	$self->session(
		'sso_token_'
			. $access_token => {
				user      => $code_data->{user},
				scope     => $code_data->{scope},
				client_id => $client_id,
				issued_at => time(),
			}
	);

	# Build ID token (unsigned, alg=none — JWT)
	my $id_token = $self->_build_id_token( $code_data->{user}, $client_id, $code_data->{nonce}, $code_data->{scope}, );

	$self->render(
		json => {
			access_token => $access_token,
			token_type   => 'Bearer',
			expires_in   => $token_lifetime,
			id_token     => $id_token,
			scope        => $code_data->{scope},
		}
	);
} ## end sub token

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

	my $token_data = $self->session( 'sso_token_' . $token );
	unless ($token_data) {
		$self->res->headers->www_authenticate('Bearer error="invalid_token"');
		return $self->render( json => { error => 'invalid_token' }, status => 401 );
	}

	# Check token expiry
	my $token_lifetime = $self->pt->{ini}->{''}->{ssoTokenLifetime} // 3600;
	if ( ( time() - $token_data->{issued_at} ) > $token_lifetime ) {
		delete $self->session->{ 'sso_token_' . $token };
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

sub _build_id_token {
	my ( $self, $user, $client_id, $nonce, $scope ) = @_;

	my $issuer   = $self->sso_issuer;
	my $now      = time();
	my $lifetime = $self->pt->{ini}->{''}->{ssoTokenLifetime} // 3600;

	# JWT header (alg=none)
	my $header = _b64url_encode('{"alg":"none","typ":"JWT"}');

	# JWT payload
	my %payload = (
		iss => $issuer,
		sub => $user,
		aud => $client_id,
		iat => $now,
		exp => $now + $lifetime,
	);
	$payload{nonce}     = $nonce if $nonce && $nonce ne '';
	$payload{auth_time} = $now;

	# Add claims based on scope
	my %scopes = map { $_ => 1 } split /\s+/, ( $scope // '' );
	if ( $scopes{profile} || $scopes{email} ) {
		my $entry;
		$self->_pt_call( sub { $entry = $self->pt->getUserEntry( { user => $user } ) } );
		if ($entry) {
			if ( $scopes{profile} ) {
				$payload{name}        = $entry->get_value('displayName') // $entry->get_value('cn') // '';
				$payload{given_name}  = $entry->get_value('givenName')   // '';
				$payload{family_name} = $entry->get_value('sn')          // '';
			}
			if ( $scopes{email} ) {
				$payload{email} = $entry->get_value('mail') // '';
			}
		} ## end if ($entry)
	} ## end if ( $scopes{profile} || $scopes{email} )

	my $json_payload = Mojo::JSON::encode_json( \%payload );
	my $body         = _b64url_encode($json_payload);

	# alg=none: header.payload.
	return "$header.$body.";
} ## end sub _build_id_token

sub _build_userinfo_claims {
	my ( $self, $user, $scopes ) = @_;

	my %claims = ( sub => $user );

	my $entry;
	$self->_pt_call( sub { $entry = $self->pt->getUserEntry( { user => $user } ) } );
	return \%claims unless $entry;

	if ( $scopes->{profile} ) {
		my $name = $entry->get_value('displayName') // $entry->get_value('cn');
		$claims{name}               = $name                          if defined $name;
		$claims{given_name}         = $entry->get_value('givenName') if $entry->get_value('givenName');
		$claims{family_name}        = $entry->get_value('sn')        if $entry->get_value('sn');
		$claims{preferred_username} = $user;

		# OIDC-specific claims from oidcSubject
		my %oc = map { lc($_) => 1 } $entry->get_value('objectClass');
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
	} ## end if ( $scopes->{profile} )

	if ( $scopes->{email} ) {
		$claims{email} = $entry->get_value('mail') if $entry->get_value('mail');

		my %oc = map { lc($_) => 1 } $entry->get_value('objectClass');
		if ( $oc{oidcsubject} ) {
			my $ev = $entry->get_value('oidcEmailVerified');
			$claims{email_verified} = ( defined $ev && $ev eq 'TRUE' ) ? Mojo::JSON->true : Mojo::JSON->false
				if defined $ev;
		}
	} ## end if ( $scopes->{email} )

	if ( $scopes->{phone} ) {
		$claims{phone_number} = $entry->get_value('telephoneNumber') if $entry->get_value('telephoneNumber');

		my %oc = map { lc($_) => 1 } $entry->get_value('objectClass');
		if ( $oc{oidcsubject} ) {
			my $pv = $entry->get_value('oidcPhoneNumberVerified');
			$claims{phone_number_verified} = ( defined $pv && $pv eq 'TRUE' ) ? Mojo::JSON->true : Mojo::JSON->false
				if defined $pv;
		}
	} ## end if ( $scopes->{phone} )

	if ( $scopes->{address} ) {
		my %addr;
		$addr{street_address} = $entry->get_value('street')     if $entry->get_value('street');
		$addr{locality}       = $entry->get_value('l')          if $entry->get_value('l');
		$addr{region}         = $entry->get_value('st')         if $entry->get_value('st');
		$addr{postal_code}    = $entry->get_value('postalCode') if $entry->get_value('postalCode');
		$addr{country}        = $entry->get_value('c')          if $entry->get_value('c');
		$claims{address}      = \%addr                          if %addr;
	}

	return \%claims;
} ## end sub _build_userinfo_claims

1;
