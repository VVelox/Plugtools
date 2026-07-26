package App::Nisaba::WebSelfService::Controller::SelfService;

use Mojo::Base 'Mojolicious::Controller', -signatures;
use experimental 'signatures';    # redundant at runtime; here so perlcritic recognises signatures
use Mojo::Util           qw(hmac_sha1_sum b64_encode b64_decode url_escape);
use App::Nisaba::WebUtil qw(secure_compare random_b64url b64url_encode);

=head1 NAME

App::Nisaba::WebSelfService::Controller::SelfService - Self-service portal controller

=head1 DESCRIPTION

Handles login, logout, password change, SSH key management, and
password-reset-via-email for the self-service portal.

=cut

# --------------------------------------------------------------------------- #
# Auth middleware
# --------------------------------------------------------------------------- #

sub require_login ($self) {
	return 1 if $self->session('user');
	$self->redirect_to('login');
	return undef;
}

# --------------------------------------------------------------------------- #
# Login / logout
# --------------------------------------------------------------------------- #

sub login_form ($self) {
	$self->render( template => 'selfservice/login' );
}

# Where the shared login flows (App::Nisaba::WebUtil) keep this app's session
# state and where each step navigates next.
sub _login_flow_callbacks ($self) {
	return (
		set_totp_pending => sub ( $c, $user ) { $c->session( totp_pending_user => $user ) },
		set_logged_in    => sub ( $c, $user ) {
			delete $c->session->{totp_pending_user};
			$c->session( user => $user );
		},
		goto_totp_challenge => sub ($c) { $c->redirect_to('totp_challenge') },
		goto_logged_in      => sub ($c) { $c->redirect_to('dashboard') },
	);
} ## end sub _login_flow_callbacks

sub login ($self) {
	App::Nisaba::WebUtil::handle_password_login(
		$self,
		$self->_login_flow_callbacks,
		render_block   => { template => 'selfservice/login' },
		redirect_login => sub ($c) { $c->redirect_to('login') },
	);
}

sub logout ($self) {
	$self->session( expires => 1 );
	$self->redirect_to('login');
}

sub passkey_login_start ($self) {
	App::Nisaba::WebUtil::handle_passkey_login_start( $self, challenge_session_key => 'passkey_login_challenge' );
}

sub passkey_login_finish ($self) {
	App::Nisaba::WebUtil::handle_passkey_login_finish(
		$self,
		$self->_login_flow_callbacks,
		challenge_session_key => 'passkey_login_challenge'
	);
}

sub totp_challenge_form ($self) {
	unless ( $self->session('totp_pending_user') ) {
		return $self->redirect_to('login');
	}
	$self->render( template => 'selfservice/totp_challenge' );
}

sub totp_challenge ($self) {
	my $user = $self->session('totp_pending_user');
	unless ($user) {
		return $self->redirect_to('login');
	}

	App::Nisaba::WebUtil::handle_totp_challenge(
		$self,
		$self->_login_flow_callbacks,
		pending_user            => $user,
		render_block            => { template => 'selfservice/totp_challenge' },
		redirect_totp_challenge => sub ($c) { $c->redirect_to('totp_challenge') },
	);
} ## end sub totp_challenge

# --------------------------------------------------------------------------- #
# Dashboard
# --------------------------------------------------------------------------- #

sub dashboard ($self) {
	my $user = $self->session('user');

	my $info;
	my $err = $self->pt_call( sub { $info = $self->pt->userSelfInfo( { user => $user } ) } );
	if ($err) {
		$self->flash( error => "Could not load your account information: $err" );
		return $self->redirect_to('login');
	}

	my $lpk_schema     = $self->pt->ldapPublicKeyAvailable ? 1 : 0;
	my $totp_schema    = $self->pt->totpSchemaAvailable    ? 1 : 0;
	my $passkey_schema = $self->pt->passkeySchemaAvailable ? 1 : 0;

	my ( $totp_qr_b64, $totp_uri ) = ( undef, undef );
	if ( $totp_schema && $info->{objectClasses}{totpuser} && ( $info->{totpStatus} // '' ) eq 'pending' ) {
		my $totp_full;
		my $terr = $self->pt_call( sub { $totp_full = $self->pt->userTotpInfoGet( { user => $user } ) } );
		if ( !$terr && $totp_full && defined $totp_full->{totpSecret} ) {
			my %totp_args = (
				secret    => $totp_full->{totpSecret},
				user      => $user,
				algorithm => $totp_full->{totpAlgorithm},
				period    => $totp_full->{totpPeriod},
				digits    => $totp_full->{totpDigits},
			);
			eval { $totp_qr_b64 = $self->pt->totpQRCodeBase64( \%totp_args ) };
			eval { $totp_uri    = $self->pt->totpURI( \%totp_args ) };
		} ## end if ( !$terr && $totp_full && defined $totp_full...)
	} ## end if ( $totp_schema && $info->{objectClasses...})

	my $passkey_info = undef;
	if ($passkey_schema) {
		$self->pt_call( sub { $passkey_info = $self->pt->userPasskeyInfoGet( { user => $user } ) } );
		$passkey_info //= { hasPasskeyUser => 0, credentials => [] };
	}

	$self->render(
		template       => 'selfservice/dashboard',
		user           => $user,
		info           => $info,
		lpk_schema     => $lpk_schema,
		totp_schema    => $totp_schema,
		totp_qr_b64    => $totp_qr_b64,
		totp_uri       => $totp_uri,
		passkey_schema => $passkey_schema,
		passkey_info   => $passkey_info,
	);
} ## end sub dashboard

# --------------------------------------------------------------------------- #
# Password change
# --------------------------------------------------------------------------- #

sub change_password ($self) {
	my $user     = $self->session('user');
	my $current  = $self->param('current')  // '';
	my $new_pass = $self->param('new_pass') // '';
	my $confirm  = $self->param('confirm')  // '';

	if ( $new_pass eq '' ) {
		$self->flash( error => 'New password must not be empty.' );
		return $self->redirect_to('dashboard');
	}
	if ( $new_pass ne $confirm ) {
		$self->flash( error => 'New password and confirmation do not match.' );
		return $self->redirect_to('dashboard');
	}

	# Verify current password first
	my $verify_err = $self->pt_call( sub { $self->pt->userVerifyPassword( { user => $user, password => $current } ) } );
	if ($verify_err) {
		$self->flash( error => 'Current password is incorrect.' );
		return $self->redirect_to('dashboard');
	}

	my $err = $self->pt_call( sub { $self->pt->userSetPassSelf( { user => $user, pass => $new_pass } ) } );
	if ($err) {
		$self->flash( error => "Password change failed: $err" );
		return $self->redirect_to('dashboard');
	}

	$self->flash( success => 'Password changed successfully.' );
	$self->redirect_to('dashboard');
} ## end sub change_password

# --------------------------------------------------------------------------- #
# SSH key management
# --------------------------------------------------------------------------- #

sub sshkey_enable ($self) {
	my $user = $self->session('user');

	my $err = $self->pt_call( sub { $self->pt->userConvertToLdapPublicKeySelf( { user => $user } ) } );
	if ($err) {
		$self->flash( error => "Could not enable SSH key storage: $err" );
	} else {
		$self->flash( success => 'SSH key storage enabled.' );
	}
	$self->redirect_to('dashboard');
} ## end sub sshkey_enable

sub sshkey_add ($self) {
	my $user = $self->session('user');
	my $key  = $self->param('key') // '';
	$key =~ s/[\r\n]+//g;

	if ( $key eq '' ) {
		$self->flash( error => 'SSH public key must not be empty.' );
		return $self->redirect_to('dashboard');
	}

	my $err = $self->pt_call( sub { $self->pt->userSSHPublicKeyAddSelf( { user => $user, key => $key } ) } );
	if ($err) {
		$self->flash( error => "Could not add SSH key: $err" );
	} else {
		$self->flash( success => 'SSH key added.' );
	}
	$self->redirect_to('dashboard');
} ## end sub sshkey_add

sub sshkey_remove ($self) {
	my $user = $self->session('user');
	my $key  = $self->param('key') // '';

	my $err = $self->pt_call( sub { $self->pt->userSSHPublicKeyRemoveSelf( { user => $user, key => $key } ) } );
	if ($err) {
		$self->flash( error => "Could not remove SSH key: $err" );
	} else {
		$self->flash( success => 'SSH key removed.' );
	}
	$self->redirect_to('dashboard');
} ## end sub sshkey_remove

# --------------------------------------------------------------------------- #
# TOTP
# --------------------------------------------------------------------------- #

sub totp_enable ($self) {
	my $user = $self->session('user');

	my $err = $self->pt_call( sub { $self->pt->userConvertToTotp( { user => $user } ) } );
	if ($err) {
		$self->flash( error => "Could not enable TOTP: $err" );
		return $self->redirect_to('dashboard');
	}

	$err = $self->pt_call( sub { $self->pt->userTotpGenerateSecret( { user => $user } ) } );
	if ($err) {
		$self->flash( error => "TOTP enabled but could not generate a secret: $err" );
		return $self->redirect_to('dashboard');
	}

	$self->flash( success => 'TOTP enabled. Scan the QR code below to enrol your authenticator app.' );
	$self->redirect_to('dashboard');
} ## end sub totp_enable

sub totp_generate ($self) {
	my $user = $self->session('user');

	my $err = $self->pt_call( sub { $self->pt->userTotpGenerateSecret( { user => $user } ) } );
	if ($err) {
		$self->flash( error => "Could not generate TOTP secret: $err" );
		return $self->redirect_to('dashboard');
	}

	$self->flash( success => 'New TOTP secret generated. Scan the QR code below to enrol your authenticator app.' );
	$self->redirect_to('dashboard');
} ## end sub totp_generate

sub totp_verify ($self) {
	my $user = $self->session('user');
	my $code = $self->param('code') // '';

	my $ok;
	my $err = $self->pt_call( sub { $ok = $self->pt->userTotpVerify( { user => $user, code => $code } ) } );
	if ( $err || !$ok ) {
		$self->flash( error => 'TOTP verification failed. Please check the code and try again.' );
		return $self->redirect_to('dashboard');
	}

	$self->pt_call( sub { $self->pt->userTotpStatusSet( { user => $user, status => 'active' } ) } );
	$self->pt_call( sub { $self->pt->userTotpEnrolledDateSet( { user => $user } ) } );

	$self->flash( success => 'TOTP verified and activated. Your account is now protected with MFA.' );
	$self->redirect_to('dashboard');
} ## end sub totp_verify

sub totp_scratch_replace ($self) {
	my $user = $self->session('user');

	my $codes;
	my $err = $self->pt_call( sub { $codes = $self->pt->userTotpScratchCodesReplace( { user => $user } ) } );
	if ($err) {
		$self->flash( error => "Could not generate scratch codes: $err" );
		return $self->redirect_to('dashboard');
	}

	$self->flash( new_scratch_codes => $codes );
	$self->redirect_to('dashboard');
} ## end sub totp_scratch_replace

# --------------------------------------------------------------------------- #
# Passkeys (WebAuthn / FIDO2)
# --------------------------------------------------------------------------- #

sub passkey_enable ($self) {
	my $user = $self->session('user');

	my $err = $self->pt_call( sub { $self->pt->userConvertToPasskeyUser( { user => $user } ) } );
	if ($err) {
		$self->flash( error => "Could not enable passkey storage: $err" );
	} else {
		$self->flash( success => 'Passkey storage enabled.' );
	}
	$self->redirect_to('dashboard');
} ## end sub passkey_enable

sub passkey_register_start ($self) {
	my $user = $self->session('user');

	# 32-byte random challenge
	my $challenge_b64 = random_b64url(32);
	$self->session( passkey_challenge => $challenge_b64 );

	my $info;
	$self->pt_call( sub { $info = $self->pt->userSelfInfo( { user => $user } ) } );
	my $display = ( $info && $info->{displayName} ) ? $info->{displayName} : $user;

	my $webauthn = App::Nisaba::WebUtil::webauthn_context($self);
	my $rp_id    = $webauthn->{rp_id};
	my $uv       = $webauthn->{uv};

	# Encode username as base64url for the user handle
	my $user_id = b64url_encode($user);

	# Collect existing credential IDs so the browser can exclude them
	my $passkey_info;
	$self->pt_call( sub { $passkey_info = $self->pt->userPasskeyInfoGet( { user => $user } ) } );
	my @exclude
		= map { { id => $_->{credentialId}, type => 'public-key' } } @{ ( $passkey_info // {} )->{credentials} // [] };

	$self->render(
		json => {
			challenge        => $challenge_b64,
			rp               => { name => $rp_id,   id   => $rp_id },
			user             => { id   => $user_id, name => $user, displayName => $display },
			pubKeyCredParams => [
				{ type => 'public-key', alg => -7 },
				{ type => 'public-key', alg => -8 },
				{ type => 'public-key', alg => -257 },
			],
			authenticatorSelection => { userVerification => $uv },
			excludeCredentials     => \@exclude,
			timeout                => 60000,
			attestation            => 'none',
		}
	);
} ## end sub passkey_register_start

sub passkey_register_finish ($self) {
	my $user          = $self->session('user');
	my $challenge_b64 = $self->session('passkey_challenge');

	unless ($challenge_b64) {
		return $self->render( json => { error => 'No registration in progress' }, status => 400 );
	}
	delete $self->session->{passkey_challenge};

	my $body = $self->req->json;
	unless ( $body && ref $body->{response} eq 'HASH' ) {
		return $self->render( json => { error => 'Invalid request body' }, status => 400 );
	}

	my $webauthn = App::Nisaba::WebUtil::webauthn_context($self);
	my $verifier = App::Nisaba::WebUtil::webauthn_verifier($webauthn);
	unless ($verifier) {
		return $self->render(
			json =>
				{ error => 'WebAuthn verification is not available on this server (Authen::WebAuthn not installed)' },
			status => 501,
		);
	}

	my $reg = eval {
		$verifier->validate_registration(
			challenge_b64          => $challenge_b64,
			requested_uv           => $webauthn->{uv},
			client_data_json_b64   => $body->{response}{clientDataJSON},
			attestation_object_b64 => $body->{response}{attestationObject},
			token_binding_id_b64   => undef,
		);
	};
	if ($@) {
		( my $msg = $@ ) =~ s/ at \S+ line \d+\.?\s*$//;
		return $self->render( json => { error => "Verification failed: $msg" }, status => 400 );
	}

	my $transports = ref( $body->{response}{transports} ) eq 'ARRAY' ? $body->{response}{transports} : [];

	my $err = $self->pt_call(
		sub {
			$self->pt->userPasskeyCredentialAdd(
				{
					user           => $user,
					credentialId   => $reg->{credential_id},
					cosePublicKey  => $reg->{credential_pubkey},
					algorithm      => $reg->{credential_alg} // '',
					signCount      => $reg->{sign_count}     // 0,
					aaguid         => $reg->{aaguid}         // '',
					transports     => $transports,
					backupEligible => ( $reg->{be} // 0 ) ? 'TRUE' : 'FALSE',
					backupState    => ( $reg->{bs} // 0 ) ? 'TRUE' : 'FALSE',
					nickname       => $body->{nickname} // '',
				}
			);
		}
	);
	if ($err) {
		return $self->render( json => { error => "Could not save credential: $err" }, status => 500 );
	}

	$self->render( json => { ok => 1 } );
} ## end sub passkey_register_finish

sub passkey_remove ($self) {
	my $user         = $self->session('user');
	my $credentialId = $self->param('credentialId') // '';

	my $err = $self->pt_call(
		sub { $self->pt->userPasskeyCredentialRemove( { user => $user, credentialId => $credentialId } ) } );
	if ($err) {
		$self->flash( error => "Could not remove passkey: $err" );
	} else {
		$self->flash( success => 'Passkey removed.' );
	}
	$self->redirect_to('dashboard');
} ## end sub passkey_remove

sub passkey_uv_set ($self) {
	my $user = $self->session('user');
	my $uv   = $self->param('uv') // '';

	my $err = $self->pt_call( sub { $self->pt->userPasskeyUserVerificationSet( { user => $user, uv => $uv } ) } );
	if ($err) {
		$self->flash( error => "Could not update user verification policy: $err" );
	} else {
		$self->flash( success => 'User verification policy updated.' );
	}
	$self->redirect_to('dashboard');
} ## end sub passkey_uv_set

# --------------------------------------------------------------------------- #
# Forgot / reset password
# --------------------------------------------------------------------------- #

sub forgot_form ($self) {
	unless ( $self->reset_available ) {
		$self->flash( error => 'Password reset by email is not configured on this server.' );
		return $self->redirect_to('login');
	}
	# Drop any logged-in identity and any half-completed login (a pending TOTP
	# challenge or passkey challenge would otherwise remain completable), but
	# keep the session itself so the CSRF token rendered into the form survives
	# to the POST.
	delete @{ $self->session }{qw(user totp_pending_user passkey_login_challenge passkey_challenge)};
	$self->render( template => 'selfservice/forgot' );
} ## end sub forgot_form

sub forgot ($self) {
	unless ( $self->reset_available ) {
		$self->flash( error => 'Password reset by email is not configured on this server.' );
		return $self->redirect_to('login');
	}

	my $user = $self->param('user') // '';

	return
		unless $self->rate_guard( 'forgot', user => $user, hit => 1, render => { template => 'selfservice/forgot' } );

	# Always show the same message to prevent user enumeration
	my $ok_msg = 'If that username exists and has an email address on file, a reset link has been sent.';

	# Look up the user's email
	my $info;
	my $err = $self->pt_call( sub { $info = $self->pt->userSelfInfo( { user => $user } ) } );
	if ($err) {
		$self->flash( success => $ok_msg );
		return $self->redirect_to('forgot');
	}

	my $mail = $info->{mail};
	if ( !defined($mail) || $mail eq '' ) {
		$self->flash( success => $ok_msg );
		return $self->redirect_to('forgot');
	}

	# Generate a signed reset token: base64(user \0 expiry \0 sig). The signature
	# is bound to a fingerprint of the user's current password, so as soon as the
	# password changes — including when this token is used to reset it — every
	# outstanding token for the user stops validating. That makes each token
	# effectively single use.
	my $expiry  = time() + 3600;                                       # 1 hour
	my $secret  = $self->app->secrets->[0];
	my $pwfp    = _password_fingerprint( $self, $user );
	my $payload = $user . "\0" . $expiry;
	my $sig     = hmac_sha1_sum( $payload . "\0" . $pwfp, $secret );
	my $token   = b64_encode( $payload . "\0" . $sig, '' );
	$token =~ tr|+/|,-|;                                               # URL-safe

	my $reset_url = $self->url_for('reset')->to_abs->to_string;
	$reset_url =~ s|/reset/?$||;
	$reset_url .= '/reset/' . url_escape($token);

	my $body = <<"END_BODY";
Someone (hopefully you) requested a password reset for your account "$user".

Click the link below to set a new password. The link expires in one hour.

$reset_url

If you did not request this, you can safely ignore this email.
END_BODY

	$self->pt->sendEmail(
		{
			to      => $mail,
			subject => 'Password reset request',
			body    => $body,
		}
	);

	$self->flash( success => $ok_msg );
	$self->redirect_to('forgot');
} ## end sub forgot

sub reset_form ($self) {
	my $token = $self->param('token') // '';
	my $user  = _verify_reset_token( $self, $token );
	if ( !defined($user) ) {
		$self->flash( error => 'This reset link is invalid or has expired.' );
		return $self->redirect_to('forgot');
	}
	# Drop any logged-in identity and any half-completed login (a pending TOTP
	# challenge or passkey challenge would otherwise remain completable), but
	# keep the session itself so the CSRF token rendered into the form survives
	# to the POST.
	delete @{ $self->session }{qw(user totp_pending_user passkey_login_challenge passkey_challenge)};
	$self->render( template => 'selfservice/reset', token => $token );
} ## end sub reset_form

sub reset ($self) {
	my $token = $self->param('token') // '';

	return unless $self->rate_guard( 'reset', render => { template => 'selfservice/reset', token => $token } );

	$self->session( expires => 1 );
	my $new_pass = $self->param('new_pass') // '';
	my $confirm  = $self->param('confirm')  // '';

	my $user = _verify_reset_token( $self, $token );
	if ( !defined($user) ) {
		$self->rate_fail('reset');
		$self->flash( error => 'This reset link is invalid or has expired.' );
		return $self->redirect_to('forgot');
	}
	$self->rate_reset('reset');

	if ( $new_pass eq '' ) {
		$self->flash( error => 'Password must not be empty.' );
		return $self->redirect_to( $self->url_for( 'reset', token => $token ) );
	}
	if ( $new_pass ne $confirm ) {
		$self->flash( error => 'Passwords do not match.' );
		return $self->redirect_to( $self->url_for( 'reset', token => $token ) );
	}

	my $err = $self->pt_call( sub { $self->pt->userSetPassSelf( { user => $user, pass => $new_pass } ) } );
	if ($err) {
		$self->flash( error => "Password reset failed: $err" );
		return $self->redirect_to( $self->url_for( 'reset', token => $token ) );
	}

	$self->flash( success => 'Password reset successfully. Please log in.' );
	$self->redirect_to('login');
} ## end sub reset

# --------------------------------------------------------------------------- #
# Private helpers
# --------------------------------------------------------------------------- #

sub _verify_reset_token {
	my ( $c, $token ) = @_;
	return undef unless defined($token) && $token ne '';

	$token =~ tr|,-|+/|;    # Undo URL-safe encoding
	my $raw = eval { b64_decode($token) };
	return undef if $@;

	my ( $user, $expiry, $sig ) = split /\0/, $raw, 3;
	return undef unless defined($user) && defined($expiry) && defined($sig);
	return undef unless $expiry =~ /\A[0-9]+\z/;                               # a valid token's expiry is an integer timestamp
	return undef if time() > $expiry;

	my $secret   = $c->app->secrets->[0];
	my $pwfp     = _password_fingerprint( $c, $user );
	my $expected = hmac_sha1_sum( $user . "\0" . $expiry . "\0" . $pwfp, $secret );
	return undef unless secure_compare( $sig, $expected );

	return $user;
} ## end sub _verify_reset_token

# A fingerprint of the user's current password, keyed by the app secret. Folded
# into the reset-token signature so a password change invalidates every
# outstanding reset token for the user. A user with no password yet yields a
# stable value, so a token issued beforehand can still set the first password.
sub _password_fingerprint {
	my ( $c, $user ) = @_;
	my $entry;
	eval { $entry = $c->pt->getUserEntry( { user => $user } ) };
	my @pw = $entry ? ( grep { defined } $entry->get_value('userPassword') ) : ();
	return hmac_sha1_sum( join( "\x1f", @pw ), $c->app->secrets->[0] );
}

1;
